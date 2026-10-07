package guard

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/robotNIXX/guardvpn/internal/logging"
)

// Options configures a Guard.
type Options struct {
	// Interval between periodic re-checks while ALLOWED or BLOCKED.
	Interval time.Duration
	// UnknownRetry is the re-check delay after an UNKNOWN result.
	UnknownRetry time.Duration
	// Debounce delays the HTTP check after a network change so that a
	// burst of events (Wi-Fi + route + utun) produces a single request.
	// The state is switched to CHECKING immediately, not after the debounce.
	Debounce time.Duration
	// Required is the list of allowed countries (for log messages).
	Required []string
	Log      *logging.Logger
}

// Guard owns the network state.
//
// Invariants:
//   - a network change (Invalidate) moves the state to CHECKING immediately;
//   - a check result is applied only if no network change happened while it
//     was in flight (generation check), otherwise it is discarded;
//   - a periodic re-check does not leave ALLOWED while it runs, but its
//     result may move the state to BLOCKED/UNKNOWN;
//   - only one check runs at a time (single goroutine).
type Guard struct {
	opts    Options
	checker Checker
	log     *logging.Logger

	mu             sync.Mutex
	st             NetworkState
	gen            uint64 // bumped on every Invalidate
	lastInvalidate time.Time
	startSeq       uint64 // number of checks started
	doneSeq        uint64 // seq of the last finished check
	doneCh         chan struct{}
	subs           []chan struct{}

	poke chan struct{}
}

// New creates a guard in INITIALIZING state.
func New(checker Checker, opts Options) *Guard {
	if opts.Log == nil {
		opts.Log = logging.Discard()
	}
	return &Guard{
		opts:    opts,
		checker: checker,
		log:     opts.Log,
		st:      NetworkState{State: StateInitializing},
		doneCh:  make(chan struct{}),
		poke:    make(chan struct{}, 1),
	}
}

// Allowed reports whether the controlled application may run right now.
func (g *Guard) Allowed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.st.State.Permits()
}

// Snapshot returns a copy of the current state.
func (g *Guard) Snapshot() NetworkState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.st
}

// Subscribe returns a channel that receives a value whenever the state
// changes. Notifications are coalesced.
func (g *Guard) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	g.mu.Lock()
	g.subs = append(g.subs, ch)
	g.mu.Unlock()
	return ch
}

func (g *Guard) notifyLocked() {
	for _, ch := range g.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (g *Guard) wakeLoop() {
	select {
	case g.poke <- struct{}{}:
	default:
	}
}

// Invalidate reports a potentially significant network change. The state
// leaves ALLOWED immediately and a new check is scheduled.
func (g *Guard) Invalidate(reason string) {
	g.mu.Lock()
	g.gen++
	g.lastInvalidate = time.Now()
	prev := g.st.State
	if prev != StateChecking {
		g.st.State = StateChecking
		g.st.Reason = reason
		g.log.Warn("network changed", "reason", reason, "previous_state", prev,
			"previous_ip", g.st.IPv4, "state", StateChecking)
		g.notifyLocked()
	} else {
		g.log.Debug("network changed while checking", "reason", reason)
	}
	g.mu.Unlock()
	g.wakeLoop()
}

// RequestCheck schedules a re-check without changing the current state.
func (g *Guard) RequestCheck() { g.wakeLoop() }

// CheckNow requests a fresh check and waits for a definitive result
// (anything but CHECKING) from a check started after this call.
func (g *Guard) CheckNow(ctx context.Context) (NetworkState, error) {
	g.mu.Lock()
	want := g.startSeq + 1
	g.mu.Unlock()
	g.wakeLoop()
	for {
		g.mu.Lock()
		if g.doneSeq >= want && g.st.State != StateChecking {
			st := g.st
			g.mu.Unlock()
			return st, nil
		}
		ch := g.doneCh
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return g.Snapshot(), ctx.Err()
		case <-ch:
		}
	}
}

// Run drives the check loop until ctx is cancelled.
func (g *Guard) Run(ctx context.Context) {
	g.mu.Lock()
	g.st.State = StateChecking
	g.st.Reason = "startup"
	g.lastInvalidate = time.Time{}
	g.notifyLocked()
	g.mu.Unlock()
	g.log.Info("state changed", "from", StateInitializing, "to", StateChecking, "reason", "startup")

	next := time.NewTimer(0)
	defer next.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.poke:
		case <-next.C:
		}
		if !g.waitDebounce(ctx) {
			return
		}
		// Requests that arrived before this check starts are served by it.
		select {
		case <-g.poke:
		default:
		}

		g.mu.Lock()
		gen := g.gen
		g.startSeq++
		seq := g.startSeq
		g.mu.Unlock()

		res := g.checker.Check(ctx)
		if ctx.Err() != nil {
			return
		}
		delay := g.apply(gen, seq, res)
		next.Reset(delay)
	}
}

// waitDebounce sleeps until Debounce has passed since the last Invalidate.
func (g *Guard) waitDebounce(ctx context.Context) bool {
	for {
		g.mu.Lock()
		remaining := time.Duration(0)
		if !g.lastInvalidate.IsZero() {
			remaining = g.opts.Debounce - time.Since(g.lastInvalidate)
		}
		g.mu.Unlock()
		if remaining <= 0 {
			return true
		}
		t := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
}

func (g *Guard) apply(gen, seq uint64, res Result) time.Duration {
	g.mu.Lock()
	defer func() {
		g.doneSeq = seq
		close(g.doneCh)
		g.doneCh = make(chan struct{})
		g.mu.Unlock()
	}()

	if gen != g.gen {
		// The network changed while this check was in flight: the answer
		// may describe the old route. Discard it and check again.
		g.log.Debug("discarding stale check result", "result", res.State, "ip", res.IPv4)
		return 0
	}

	prev := g.st
	now := time.Now()
	next := NetworkState{
		State:     res.State,
		IPv4:      res.IPv4,
		IPv6:      res.IPv6,
		Country:   res.Country,
		Provider:  res.Provider,
		Reason:    res.Reason,
		CheckedAt: now,
	}
	if res.State != StateAllowed && res.State != StateBlocked {
		next.State = StateUnknown // never let an unexpected value through
	}

	if prev.IPv4 != "" && next.IPv4 != "" && prev.IPv4 != next.IPv4 {
		g.log.Info("external IP changed", "previous_ip", prev.IPv4, "ip", next.IPv4)
	}
	if prev.IPv6 != "" && next.IPv6 != "" && prev.IPv6 != next.IPv6 {
		g.log.Info("external IPv6 changed", "previous_ip", prev.IPv6, "ip", next.IPv6)
	}
	if prev.Country != "" && next.Country != "" && prev.Country != next.Country {
		g.log.Info("country changed", "previous_country", prev.Country, "country", next.Country)
	}

	switch next.State {
	case StateAllowed:
		if prev.State != StateAllowed {
			g.log.Info("network validated", "ip", next.IPv4, "ipv6", next.IPv6,
				"country", next.Country, "provider", next.Provider, "state", next.State)
		} else {
			g.log.Debug("network re-validated", "ip", next.IPv4, "country", next.Country)
		}
	case StateBlocked:
		if prev.State != StateBlocked || prev.Country != next.Country {
			g.log.Warn("country rejected", "ip", next.IPv4, "ipv6", next.IPv6,
				"country", next.Country, "expected", strings.Join(g.opts.Required, ","),
				"reason", next.Reason, "state", next.State)
		}
	case StateUnknown:
		if prev.State != StateUnknown || prev.Reason != next.Reason {
			g.log.Warn("network state unknown", "reason", next.Reason, "state", next.State)
		}
	}
	if prev.State != next.State {
		g.log.Info("state changed", "from", prev.State, "to", next.State)
	}

	g.st = next
	if prev.State != next.State {
		g.notifyLocked()
	}

	if next.State == StateUnknown {
		return g.opts.UnknownRetry
	}
	return g.opts.Interval
}

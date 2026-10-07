package guard

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeChecker returns queued results; each Check blocks until released
// when gate is non-nil.
type fakeChecker struct {
	mu      sync.Mutex
	results []Result
	calls   int
	gate    chan struct{}
	started chan struct{}
}

func (f *fakeChecker) Check(ctx context.Context) Result {
	f.mu.Lock()
	f.calls++
	gate, started := f.gate, f.started
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return Result{State: StateUnknown}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.results) == 0 {
		return Result{State: StateUnknown, Reason: "no result queued"}
	}
	r := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return r
}

func (f *fakeChecker) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func allowed(ip string) Result {
	return Result{State: StateAllowed, IPv4: ip, Country: "TH", Countries: []string{"TH"}}
}

var blockedDE = Result{State: StateBlocked, IPv4: "198.51.100.27", Country: "DE", Countries: []string{"DE"}}

func newGuard(c Checker) *Guard {
	return New(c, Options{Interval: time.Hour, UnknownRetry: time.Hour, Debounce: 20 * time.Millisecond, Required: []string{"TH"}})
}

func waitState(t *testing.T, g *Guard, want State) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if g.Snapshot().State == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state = %v, want %v", g.Snapshot().State, want)
}

func TestInitialStateForbids(t *testing.T) {
	g := newGuard(&fakeChecker{})
	if g.Allowed() || g.Snapshot().State != StateInitializing {
		t.Fatal("a fresh guard must be INITIALIZING and forbid the app")
	}
}

func TestOnlyAllowedPermits(t *testing.T) {
	for _, s := range []State{StateInitializing, StateChecking, StateBlocked, StateUnknown} {
		if s.Permits() {
			t.Errorf("%v must not permit", s)
		}
	}
	if !StateAllowed.Permits() {
		t.Error("ALLOWED must permit")
	}
}

func TestStartupCheckAllows(t *testing.T) {
	fc := &fakeChecker{results: []Result{allowed("203.0.113.15")}}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateAllowed)
	if g.Snapshot().IPv4 != "203.0.113.15" {
		t.Fatalf("ip = %q", g.Snapshot().IPv4)
	}
}

func TestInvalidateLeavesAllowedImmediately(t *testing.T) {
	fc := &fakeChecker{results: []Result{allowed("1.1.1.1"), blockedDE}}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateAllowed)

	g.Invalidate("vpn disconnect")
	if g.Allowed() {
		t.Fatal("ALLOWED must be dropped synchronously on a network change")
	}
	if s := g.Snapshot().State; s != StateChecking {
		t.Fatalf("state = %v, want CHECKING", s)
	}
	waitState(t, g, StateBlocked)
}

func TestStaleResultDiscarded(t *testing.T) {
	// A check that started before a network change must not produce ALLOWED.
	fc := &fakeChecker{
		results: []Result{allowed("1.1.1.1"), blockedDE},
		gate:    make(chan struct{}),
		started: make(chan struct{}, 10),
	}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)

	<-fc.started          // first check in flight
	g.Invalidate("route") // network changes while it runs
	fc.gate <- struct{}{} // first check returns ALLOWED (stale)

	<-fc.started // second check
	if g.Allowed() {
		t.Fatal("stale ALLOWED result was applied")
	}
	fc.gate <- struct{}{}
	waitState(t, g, StateBlocked)
}

func TestPeriodicCheckKeepsAllowed(t *testing.T) {
	fc := &fakeChecker{
		results: []Result{allowed("1.1.1.1"), allowed("1.1.1.1")},
		started: make(chan struct{}, 10),
		gate:    make(chan struct{}),
	}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	<-fc.started
	fc.gate <- struct{}{}
	waitState(t, g, StateAllowed)

	g.RequestCheck() // periodic / forced check
	<-fc.started
	if !g.Allowed() {
		t.Fatal("a periodic re-check must not leave ALLOWED while running")
	}
	fc.gate <- struct{}{}
	waitState(t, g, StateAllowed)
}

func TestPeriodicCheckCanBlock(t *testing.T) {
	fc := &fakeChecker{results: []Result{allowed("1.1.1.1"), blockedDE}}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateAllowed)
	g.RequestCheck()
	waitState(t, g, StateBlocked)
}

func TestDebounceCoalescesEvents(t *testing.T) {
	fc := &fakeChecker{results: []Result{allowed("1.1.1.1")}}
	g := New(fc, Options{Interval: time.Hour, UnknownRetry: time.Hour, Debounce: 100 * time.Millisecond, Required: []string{"TH"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateAllowed)
	base := fc.Calls()

	for range 10 {
		g.Invalidate("burst")
		time.Sleep(5 * time.Millisecond)
	}
	waitState(t, g, StateAllowed)
	time.Sleep(150 * time.Millisecond)
	if n := fc.Calls() - base; n != 1 {
		t.Fatalf("burst of 10 events caused %d checks, want 1", n)
	}
}

func TestUnexpectedStateBecomesUnknown(t *testing.T) {
	fc := &fakeChecker{results: []Result{{State: StateChecking}}}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateUnknown)
}

func TestCheckNowWaitsForFreshResult(t *testing.T) {
	fc := &fakeChecker{results: []Result{allowed("1.1.1.1"), allowed("2.2.2.2")}}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateAllowed)

	cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
	defer ccancel()
	st, err := g.CheckNow(cctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.IPv4 != "2.2.2.2" {
		t.Fatalf("CheckNow returned %q, want result of a new check", st.IPv4)
	}
}

func TestPermitsForPerApplication(t *testing.T) {
	fc := &fakeChecker{results: []Result{{State: StateAllowed, Country: "SG", Countries: []string{"SG"}}}}
	g := New(fc, Options{Interval: time.Hour, UnknownRetry: time.Hour, Required: []string{"TH", "SG"}})
	if g.PermitsFor(map[string]bool{"SG": true}) {
		t.Fatal("nothing may run before the first check")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateAllowed)
	if !g.PermitsFor(map[string]bool{"SG": true}) {
		t.Fatal("app allowed in SG must run")
	}
	if g.PermitsFor(map[string]bool{"TH": true}) {
		t.Fatal("app allowed only in TH must not run in SG")
	}
	g.Invalidate("route")
	if g.PermitsFor(map[string]bool{"SG": true}) {
		t.Fatal("CHECKING must forbid every app")
	}
}

func TestSetOptionsReevaluatesWithoutRecheck(t *testing.T) {
	fc := &fakeChecker{results: []Result{allowed("1.1.1.1")}}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateAllowed)
	calls := fc.Calls()

	g.SetOptions(Options{Interval: time.Hour, UnknownRetry: time.Hour, Required: []string{"SG"}})
	if s := g.Snapshot().State; s != StateBlocked {
		t.Fatalf("state = %v after removing TH, want BLOCKED", s)
	}
	g.SetOptions(Options{Interval: time.Hour, UnknownRetry: time.Hour, Required: []string{"TH"}})
	if !g.Allowed() {
		t.Fatal("re-adding TH must allow again without a new check")
	}
	if fc.Calls() != calls {
		t.Fatal("changing allowed countries must not trigger a network check")
	}
}

func TestResultWithoutCountriesIsUnknown(t *testing.T) {
	fc := &fakeChecker{results: []Result{{State: StateAllowed, IPv4: "1.1.1.1"}}}
	g := newGuard(fc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	waitState(t, g, StateUnknown)
}

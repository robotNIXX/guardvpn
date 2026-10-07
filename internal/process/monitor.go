package process

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/robotNIXX/guardvpn/internal/logging"
)

// Policy tells the monitor whether an application may run.
type Policy interface {
	Allowed() bool
}

// PolicyFunc adapts a function to Policy.
type PolicyFunc func() bool

// Allowed implements Policy.
func (f PolicyFunc) Allowed() bool { return f() }

// Target is one controlled application.
type Target struct {
	Name     string
	Identity Identity
	Policy   Policy
}

// MonitorOptions configures a Monitor.
type MonitorOptions struct {
	Lister           Lister
	Killer           Killer
	Targets          []Target
	Interval         time.Duration // process scan interval (500 ms)
	TerminateTimeout time.Duration // SIGTERM -> SIGKILL delay
	// Changes triggers an immediate scan (e.g. guard state changes).
	Changes <-chan struct{}
	Log     *logging.Logger
}

// verdictKey includes the path: on macOS exec(2) replaces the image while
// PID and start time stay the same (fork, then exec), so a process first
// seen as /bin/sh may become the target a moment later.
type verdictKey struct {
	Key
	Path   string
	Target int
}

type running struct {
	proc    Proc
	targets []string
}

// Monitor periodically scans processes and terminates every process of a
// target whose policy does not allow it to run.
type Monitor struct {
	lister Lister
	killer Killer
	log    *logging.Logger
	change <-chan struct{}
	retime chan struct{}

	mu          sync.Mutex
	targets     []Target
	interval    time.Duration
	termTimeout time.Duration
	verdicts    map[verdictKey]bool
	running     map[Key]running
	terminating map[Key]bool
}

// NewMonitor creates a process monitor.
func NewMonitor(o MonitorOptions) *Monitor {
	if o.Log == nil {
		o.Log = logging.Discard()
	}
	return &Monitor{
		lister:      o.Lister,
		killer:      o.Killer,
		log:         o.Log,
		change:      o.Changes,
		retime:      make(chan struct{}, 1),
		targets:     o.Targets,
		interval:    o.Interval,
		termTimeout: o.TerminateTimeout,
		verdicts:    map[verdictKey]bool{},
		running:     map[Key]running{},
		terminating: map[Key]bool{},
	}
}

// SetTargets replaces the controlled applications (hot reload) and
// requests an immediate rescan.
func (m *Monitor) SetTargets(ts []Target) {
	m.mu.Lock()
	m.targets = ts
	clear(m.verdicts)
	m.mu.Unlock()
	m.Poke()
}

// SetTiming updates the scan interval and termination timeout.
func (m *Monitor) SetTiming(interval, terminateTimeout time.Duration) {
	m.mu.Lock()
	changed := interval != m.interval
	m.interval, m.termTimeout = interval, terminateTimeout
	m.mu.Unlock()
	if changed {
		m.Poke()
	}
}

// Poke requests an immediate scan.
func (m *Monitor) Poke() {
	select {
	case m.retime <- struct{}{}:
	default:
	}
}

// Run scans until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	m.mu.Lock()
	t := time.NewTicker(m.interval)
	m.mu.Unlock()
	defer t.Stop()
	m.scan(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.change:
		case <-m.retime:
			m.mu.Lock()
			t.Reset(m.interval)
			m.mu.Unlock()
		}
		m.scan(ctx)
	}
}

// PIDs returns running target PIDs grouped by application name.
func (m *Monitor) PIDs() map[string][]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]int{}
	for k, r := range m.running {
		for _, name := range r.targets {
			out[name] = append(out[name], k.PID)
		}
	}
	for _, pids := range out {
		sort.Ints(pids)
	}
	return out
}

func (m *Monitor) scan(ctx context.Context) {
	procs, err := m.lister.List()
	if err != nil {
		m.log.Error("process list failed", "err", err)
		return
	}

	m.mu.Lock()
	live := make(map[Key]bool, len(procs))
	for _, p := range procs {
		live[p.Key()] = true
	}
	for k := range m.verdicts {
		if !live[k.Key] {
			delete(m.verdicts, k)
		}
	}

	current := map[Key]running{}
	deny := map[Key]bool{}
	for ti, t := range m.targets {
		isTarget := func(p Proc) bool {
			k := verdictKey{p.Key(), p.Path, ti}
			if v, ok := m.verdicts[k]; ok {
				return v
			}
			v := t.Identity.IsTarget(p)
			m.verdicts[k] = v
			return v
		}
		matched := SelectTargets(procs, isTarget)
		if len(matched) == 0 {
			continue
		}
		// Policy is read after the process list: a state change in
		// between is picked up by the next scan, which Changes triggers.
		allowed := t.Policy.Allowed()
		for _, p := range matched {
			r := current[p.Key()]
			r.proc = p
			r.targets = append(r.targets, t.Name)
			current[p.Key()] = r
			if !allowed {
				deny[p.Key()] = true // any controlling app forbidding it wins
			}
		}
	}

	var toKill []Proc
	names := map[int]string{}
	for k, r := range current {
		name := strings.Join(r.targets, ",")
		if prev, seen := m.running[k]; !seen || !slices.Equal(prev.targets, r.targets) {
			m.log.Info("application detected", "app", name, "pid", r.proc.PID,
				"ppid", r.proc.PPID, "path", r.proc.Path, "allowed", !deny[k])
		}
		if deny[k] && !m.terminating[k] {
			m.terminating[k] = true
			toKill = append(toKill, r.proc)
			names[r.proc.PID] = name
		}
	}
	for k := range m.terminating {
		if !live[k] {
			delete(m.terminating, k)
		}
	}
	m.running = current
	timeout := m.termTimeout
	m.mu.Unlock()

	if len(toKill) > 0 {
		go m.terminate(ctx, toKill, names, timeout)
	}
}

func (m *Monitor) terminate(ctx context.Context, procs []Proc, names map[int]string, timeout time.Duration) {
	for _, p := range procs {
		m.log.Warn("terminating application", "app", names[p.PID], "pid", p.PID, "path", p.Path)
	}
	results := m.killer.Terminate(ctx, procs, timeout)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range results {
		app := names[r.Proc.PID]
		if r.Err != nil {
			m.log.Error("failed to terminate application", "app", app, "pid", r.Proc.PID, "err", r.Err)
			delete(m.terminating, r.Proc.Key()) // retry on the next scan
			continue
		}
		if r.Forced {
			m.log.Warn("SIGKILL required", "app", app, "pid", r.Proc.PID)
		}
		m.log.Info("application terminated", "app", app, "pid", r.Proc.PID, "forced", r.Forced)
	}
}

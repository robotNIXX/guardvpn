package process

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/robotNIXX/guardvpn/internal/logging"
)

// Policy tells the monitor whether the application may run.
type Policy interface {
	Allowed() bool
}

// MonitorOptions configures a Monitor.
type MonitorOptions struct {
	Lister           Lister
	Identity         Identity
	Killer           Killer
	Policy           Policy
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
	Path string
}

// Monitor periodically scans processes and terminates the application
// whenever the policy does not allow it.
type Monitor struct {
	o MonitorOptions

	mu          sync.Mutex
	verdicts    map[verdictKey]bool // IsTarget cache
	running     map[Key]Proc        // currently running target processes
	terminating map[Key]bool
}

// NewMonitor creates a process monitor.
func NewMonitor(o MonitorOptions) *Monitor {
	if o.Log == nil {
		o.Log = logging.Discard()
	}
	return &Monitor{
		o:           o,
		verdicts:    map[verdictKey]bool{},
		running:     map[Key]Proc{},
		terminating: map[Key]bool{},
	}
}

// Run scans until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.o.Interval)
	defer t.Stop()
	m.scan(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.o.Changes:
		}
		m.scan(ctx)
	}
}

// TargetPIDs returns the PIDs of running target processes.
func (m *Monitor) TargetPIDs() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	pids := make([]int, 0, len(m.running))
	for k := range m.running {
		pids = append(pids, k.PID)
	}
	sort.Ints(pids)
	return pids
}

func (m *Monitor) scan(ctx context.Context) {
	procs, err := m.o.Lister.List()
	if err != nil {
		m.o.Log.Error("process list failed", "err", err)
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
	isTarget := func(p Proc) bool {
		k := verdictKey{p.Key(), p.Path}
		if v, ok := m.verdicts[k]; ok {
			return v
		}
		v := m.o.Identity.IsTarget(p)
		m.verdicts[k] = v
		return v
	}
	targets := SelectTargets(procs, isTarget)

	// Policy is read after the process list: a state change in between is
	// picked up by the next scan, which Changes triggers immediately.
	allowed := m.o.Policy.Allowed()

	current := make(map[Key]Proc, len(targets))
	var toKill []Proc
	for _, p := range targets {
		k := p.Key()
		current[k] = p
		if _, seen := m.running[k]; !seen {
			m.o.Log.Info("application detected", "pid", p.PID, "ppid", p.PPID, "path", p.Path, "allowed", allowed)
		}
		if !allowed && !m.terminating[k] {
			m.terminating[k] = true
			toKill = append(toKill, p)
		}
	}
	for k := range m.terminating {
		if !live[k] {
			delete(m.terminating, k)
		}
	}
	m.running = current
	m.mu.Unlock()

	if len(toKill) > 0 {
		go m.terminate(ctx, toKill)
	}
}

func (m *Monitor) terminate(ctx context.Context, procs []Proc) {
	for _, p := range procs {
		m.o.Log.Warn("terminating application", "pid", p.PID, "path", p.Path)
	}
	results := m.o.Killer.Terminate(ctx, procs, m.o.TerminateTimeout)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range results {
		if r.Err != nil {
			m.o.Log.Error("failed to terminate application", "pid", r.Proc.PID, "err", r.Err)
			// Allow a retry on the next scan.
			delete(m.terminating, r.Proc.Key())
			continue
		}
		if r.Forced {
			m.o.Log.Warn("SIGKILL required", "pid", r.Proc.PID)
		}
		m.o.Log.Info("application terminated", "pid", r.Proc.PID, "forced", r.Forced)
	}
}

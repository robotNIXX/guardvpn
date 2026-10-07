// Package process finds the controlled application's processes and
// terminates them.
package process

import (
	"context"
	"time"
)

// Proc is a running process.
type Proc struct {
	PID  int
	PPID int
	// Start identifies this incarnation of PID (protects against PID reuse).
	// Units are platform-specific; only equality and ordering matter.
	Start int64
	Path  string // full executable path, "" if unavailable
	Name  string
}

// Key uniquely identifies a process incarnation.
type Key struct {
	PID   int
	Start int64
}

// Key returns p's identity.
func (p Proc) Key() Key { return Key{p.PID, p.Start} }

// Lister enumerates running processes.
type Lister interface {
	List() ([]Proc, error)
}

// Identity decides whether a process belongs to the controlled app.
type Identity interface {
	// IsTarget is called once per process incarnation (results are cached).
	IsTarget(p Proc) bool
	// Describe returns key/value pairs for logs and status.
	Describe() []Field
}

// Field is a labelled piece of identity information.
type Field struct{ Name, Value string }

// Killer terminates processes.
type Killer interface {
	// Terminate stops procs: graceful first where the platform supports it,
	// forcibly after timeout. It returns once all procs are gone or the
	// forced kill was issued.
	Terminate(ctx context.Context, procs []Proc, timeout time.Duration) []KillResult
}

// KillResult reports what happened to one process.
type KillResult struct {
	Proc   Proc
	Forced bool  // SIGKILL / TerminateProcess was needed
	Err    error // nil when the process is gone
}

// SelectTargets returns processes matched by isTarget plus all their
// descendants. A child counts as a descendant only if it started after its
// parent, which rules out stale parent PIDs that were reused.
func SelectTargets(procs []Proc, isTarget func(Proc) bool) []Proc {
	byPID := make(map[int]Proc, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	memo := make(map[int]bool, len(procs))
	var match func(p Proc, depth int) bool
	match = func(p Proc, depth int) bool {
		if v, ok := memo[p.PID]; ok {
			return v
		}
		res := isTarget(p)
		if !res && depth < 64 && p.PPID > 0 && p.PPID != p.PID {
			if parent, ok := byPID[p.PPID]; ok && parent.Start <= p.Start {
				res = match(parent, depth+1)
			}
		}
		memo[p.PID] = res
		return res
	}
	var out []Proc
	for _, p := range procs {
		if match(p, 0) {
			out = append(out, p)
		}
	}
	return out
}

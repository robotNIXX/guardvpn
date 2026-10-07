package process

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

func pids(ps []Proc) []int {
	var out []int
	for _, p := range ps {
		out = append(out, p.PID)
	}
	slices.Sort(out)
	return out
}

func TestSelectTargetsIncludesDescendants(t *testing.T) {
	procs := []Proc{
		{PID: 1, PPID: 0, Start: 1, Path: "/sbin/launchd"},
		{PID: 100, PPID: 1, Start: 10, Path: "/Applications/Target.app/Contents/MacOS/Target"},
		{PID: 101, PPID: 100, Start: 11, Path: "/tmp/helper"},
		{PID: 102, PPID: 101, Start: 12, Path: "/tmp/grandchild"},
		{PID: 200, PPID: 1, Start: 10, Path: "/Applications/AnotherApp.app/Contents/MacOS/Target"},
	}
	isTarget := func(p Proc) bool { return p.Path == "/Applications/Target.app/Contents/MacOS/Target" }
	got := pids(SelectTargets(procs, isTarget))
	if !slices.Equal(got, []int{100, 101, 102}) {
		t.Fatalf("got %v", got)
	}
}

func TestSelectTargetsIgnoresReusedParentPID(t *testing.T) {
	// 300's real parent died; its PID was reused by the target which
	// started later. 300 must not be treated as the target's child.
	procs := []Proc{
		{PID: 100, PPID: 1, Start: 50, Path: "target"},
		{PID: 300, PPID: 100, Start: 20, Path: "/usr/bin/unrelated"},
	}
	got := pids(SelectTargets(procs, func(p Proc) bool { return p.Path == "target" }))
	if !slices.Equal(got, []int{100}) {
		t.Fatalf("got %v", got)
	}
}

func TestSelectTargetsHandlesCycles(t *testing.T) {
	procs := []Proc{{PID: 5, PPID: 6, Start: 1}, {PID: 6, PPID: 5, Start: 1}}
	if got := SelectTargets(procs, func(Proc) bool { return false }); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

type fakeLister struct {
	mu    sync.Mutex
	procs []Proc
}

func (f *fakeLister) List() ([]Proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.procs), nil
}

func (f *fakeLister) set(ps []Proc) {
	f.mu.Lock()
	f.procs = ps
	f.mu.Unlock()
}

type pathIdentity string

func (p pathIdentity) IsTarget(pr Proc) bool { return pr.Path == string(p) }
func (pathIdentity) Describe() []Field       { return nil }

type fakeKiller struct {
	mu     sync.Mutex
	killed []int
	lister *fakeLister
}

func (k *fakeKiller) Terminate(_ context.Context, procs []Proc, _ time.Duration) []KillResult {
	k.mu.Lock()
	defer k.mu.Unlock()
	var res []KillResult
	for _, p := range procs {
		k.killed = append(k.killed, p.PID)
		res = append(res, KillResult{Proc: p})
	}
	k.lister.set(nil)
	return res
}

func (k *fakeKiller) Killed() []int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.killed)
}

type flag struct {
	mu sync.Mutex
	v  bool
}

func (f *flag) Allowed() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.v }
func (f *flag) set(v bool)    { f.mu.Lock(); f.v = v; f.mu.Unlock() }

func TestMonitorKillsWhenNotAllowed(t *testing.T) {
	l := &fakeLister{procs: []Proc{{PID: 42, PPID: 1, Start: 5, Path: "target"}, {PID: 7, Path: "other"}}}
	k := &fakeKiller{lister: l}
	pol := &flag{v: true}
	changes := make(chan struct{}, 1)
	m := NewMonitor(MonitorOptions{Lister: l, Killer: k,
		Targets:  []Target{{Name: "T", Identity: pathIdentity("target"), Policy: pol}},
		Interval: time.Hour, TerminateTimeout: time.Second, Changes: changes})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	time.Sleep(50 * time.Millisecond)
	if len(k.Killed()) != 0 {
		t.Fatal("killed while allowed")
	}
	if !slices.Equal(m.PIDs()["T"], []int{42}) {
		t.Fatalf("target pids %v", m.PIDs())
	}

	pol.set(false)
	changes <- struct{}{} // state change triggers an immediate scan
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(k.Killed()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if !slices.Equal(k.Killed(), []int{42}) {
		t.Fatalf("killed %v, want [42]", k.Killed())
	}
}

func TestMonitorReevaluatesAfterExec(t *testing.T) {
	// fork: the child first shows the shell's path, then exec switches it
	// to the target with the same PID and start time.
	l := &fakeLister{procs: []Proc{{PID: 42, PPID: 1, Start: 5, Path: "/bin/zsh"}}}
	k := &fakeKiller{lister: l}
	m := NewMonitor(MonitorOptions{Lister: l, Killer: k,
		Targets:  []Target{{Name: "T", Identity: pathIdentity("target"), Policy: &flag{}}},
		Interval: time.Hour, TerminateTimeout: time.Second})
	ctx := context.Background()
	m.scan(ctx)
	l.set([]Proc{{PID: 42, PPID: 1, Start: 5, Path: "target"}})
	m.scan(ctx)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(k.Killed()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if !slices.Equal(k.Killed(), []int{42}) {
		t.Fatalf("killed %v, want [42]", k.Killed())
	}
}

func TestMonitorPerTargetPolicy(t *testing.T) {
	l := &fakeLister{procs: []Proc{
		{PID: 1, Start: 1, Path: "a"},
		{PID: 2, Start: 1, Path: "b"},
	}}
	k := &fakeKiller{lister: &fakeLister{}}
	m := NewMonitor(MonitorOptions{Lister: l, Killer: k, Interval: time.Hour, TerminateTimeout: time.Second,
		Targets: []Target{
			{Name: "A", Identity: pathIdentity("a"), Policy: &flag{v: true}},
			{Name: "B", Identity: pathIdentity("b"), Policy: &flag{v: false}},
		}})
	m.scan(context.Background())
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(k.Killed()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if !slices.Equal(k.Killed(), []int{2}) {
		t.Fatalf("killed %v, want only B's process [2]", k.Killed())
	}

	// Hot reload: A becomes forbidden.
	m.SetTargets([]Target{{Name: "A", Identity: pathIdentity("a"), Policy: &flag{v: false}}})
	m.scan(context.Background())
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(k.Killed()) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if !slices.Equal(k.Killed(), []int{2, 1}) {
		t.Fatalf("killed %v after reload", k.Killed())
	}
}

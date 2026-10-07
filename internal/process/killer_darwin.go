package process

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
)

type darwinKiller struct{}

// NewKiller returns the macOS killer: SIGTERM, then SIGKILL after timeout.
func NewKiller() Killer { return darwinKiller{} }

func alive(p Proc) bool {
	start, ok := currentStart(p.PID)
	return ok && start == p.Start
}

func signal(p Proc, sig syscall.Signal) error {
	if !alive(p) {
		return nil // already gone (or PID reused: never signal a stranger)
	}
	err := syscall.Kill(p.PID, sig)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (darwinKiller) Terminate(ctx context.Context, procs []Proc, timeout time.Duration) []KillResult {
	results := make([]KillResult, len(procs))
	for i, p := range procs {
		results[i].Proc = p
		if err := signal(p, syscall.SIGTERM); err != nil {
			results[i].Err = fmt.Errorf("SIGTERM: %w", err)
		}
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !anyAlive(procs) {
			for i := range results {
				results[i].Err = nil
			}
			return results
		}
		select {
		case <-ctx.Done():
			return results
		case <-time.After(100 * time.Millisecond):
		}
	}

	for i, p := range procs {
		if !alive(p) {
			continue
		}
		results[i].Forced = true
		if err := signal(p, syscall.SIGKILL); err != nil {
			results[i].Err = fmt.Errorf("SIGKILL: %w", err)
		}
	}
	// SIGKILL cannot be ignored; give the kernel a moment to reap.
	for range 20 {
		if !anyAlive(procs) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for i, p := range procs {
		switch {
		case !alive(p):
			results[i].Err = nil
		case results[i].Err == nil:
			results[i].Err = errors.New("process still running after SIGKILL")
		}
	}
	return results
}

func anyAlive(procs []Proc) bool {
	for _, p := range procs {
		if alive(p) {
			return true
		}
	}
	return false
}

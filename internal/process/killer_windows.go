package process

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

type windowsKiller struct{}

// NewKiller returns the Windows killer. V1 uses TerminateProcess directly:
// a service in session 0 cannot post WM_CLOSE to windows on the user's
// desktop, so there is no graceful step.
func NewKiller() Killer { return windowsKiller{} }

func (windowsKiller) Terminate(ctx context.Context, procs []Proc, timeout time.Duration) []KillResult {
	type pending struct {
		idx int
		h   windows.Handle
	}
	results := make([]KillResult, len(procs))
	var waits []pending
	for i, p := range procs {
		results[i].Proc = p
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(p.PID))
		if err != nil {
			if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				continue // already gone
			}
			results[i].Err = fmt.Errorf("OpenProcess: %w", err)
			continue
		}
		if start, ok := creationTime(h); !ok || start != p.Start {
			windows.CloseHandle(h) // PID reused: never touch a stranger
			continue
		}
		// ERROR_ACCESS_DENIED is also returned when the process is already
		// exiting; the wait below tells the two cases apart.
		if err := windows.TerminateProcess(h, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			results[i].Err = fmt.Errorf("TerminateProcess: %w", err)
			windows.CloseHandle(h)
			continue
		}
		waits = append(waits, pending{i, h})
	}

	deadline := time.Now().Add(timeout)
	for _, w := range waits {
		ms := uint32(0)
		if ctx.Err() == nil {
			ms = uint32(max(time.Until(deadline), 0) / time.Millisecond)
		}
		ev, _ := windows.WaitForSingleObject(w.h, ms)
		windows.CloseHandle(w.h)
		if ev != windows.WAIT_OBJECT_0 {
			results[w.idx].Err = errors.New("process still running after TerminateProcess")
		}
	}
	return results
}

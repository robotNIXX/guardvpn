package service

/*
#cgo LDFLAGS: -framework CoreFoundation -framework IOKit
int vg_power_run(void);
*/
import "C"

import (
	"runtime"
	"sync"
)

var (
	powerMu sync.Mutex
	powerCh chan<- string
)

//export goPowerEvent
func goPowerEvent(kind C.int) {
	powerMu.Lock()
	ch := powerCh
	powerMu.Unlock()
	if ch == nil {
		return
	}
	if kind == 1 {
		send(ch, EventSleep)
	} else {
		send(ch, EventWake)
	}
}

// startPowerNotifications runs an IOKit power run loop on a dedicated
// OS thread for the lifetime of the process.
func startPowerNotifications(ch chan<- string) {
	powerMu.Lock()
	powerCh = ch
	powerMu.Unlock()
	go func() {
		runtime.LockOSThread()
		C.vg_power_run() // blocks forever; on failure the clock-gap detector remains
	}()
}

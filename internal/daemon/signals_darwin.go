package daemon

import (
	"os"
	"os/signal"
	"syscall"
)

// watchSignals calls onHUP on SIGHUP (`sudo launchctl kill HUP system/com.vpnguard.daemon`).
func watchSignals(onHUP func()) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				onHUP()
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(ch); close(done) }
}

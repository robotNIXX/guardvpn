package service

import (
	"context"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows/svc"
)

// Power broadcast event types (WM_POWERBROADCAST / SERVICE_CONTROL_POWEREVENT).
const (
	pbtAPMSuspend         = 0x4
	pbtAPMResumeSuspend   = 0x7
	pbtAPMResumeAutomatic = 0x12
)

// IsService reports whether the process was started by the SCM.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Run runs fn as a Windows service, or in the console when started by hand.
func Run(fn Func) error {
	if !IsService() {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return fn(ctx, make(chan string))
	}
	return svc.Run(ServiceName, &handler{fn: fn})
}

type handler struct{ fn Func }

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	power := make(chan string, 4)
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx, power) }()

	accepts := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case err := <-done:
			if err != nil {
				// A non-zero exit code makes the SCM apply the recovery
				// actions (restart) configured by install.ps1.
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			case svc.PowerEvent:
				switch c.EventType {
				case pbtAPMSuspend:
					send(power, EventSleep)
				case pbtAPMResumeSuspend, pbtAPMResumeAutomatic:
					send(power, EventWake)
				}
			}
		}
	}
}

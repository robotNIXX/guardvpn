// Package service runs the daemon under the platform service manager
// (launchd on macOS, the Service Control Manager on Windows) and delivers
// sleep/wake notifications.
package service

import "context"

// Power events.
const (
	EventSleep = "sleep"
	EventWake  = "wake"
)

// Func is the daemon body. It must return when ctx is cancelled.
type Func func(ctx context.Context, power <-chan string) error

// ServiceName is the Windows service name / launchd label suffix.
const ServiceName = "VPNGuard"

func send(ch chan<- string, ev string) {
	select {
	case ch <- ev:
	default:
	}
}

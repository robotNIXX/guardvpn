package service

import (
	"context"
	"os/signal"
	"syscall"
)

// Run runs fn until SIGTERM/SIGINT (launchd sends SIGTERM on bootout).
func Run(fn Func) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	power := make(chan string, 4)
	startPowerNotifications(power)
	return fn(ctx, power)
}

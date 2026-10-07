package main

import (
	"runtime/debug"

	"github.com/robotNIXX/guardvpn/internal/logging"
	"github.com/robotNIXX/guardvpn/internal/paths"
)

// openDaemonLogs writes to %ProgramData%\VPNGuard\logs. A service has no
// usable stderr, so runtime crash output is redirected to the error log.
func openDaemonLogs() (*logging.Logger, func(), error) {
	p := paths.Get()
	main, err := logging.OpenRotating(p.LogFile, 10<<20, 5)
	if err != nil {
		return nil, nil, err
	}
	errLog, err := logging.OpenRotating(p.ErrorLog, 10<<20, 2)
	if err != nil {
		main.Close()
		return nil, nil, err
	}
	if f := errLog.File(); f != nil {
		_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	}
	return logging.New(main, errLog, logging.LevelInfo), func() { main.Close(); errLog.Close() }, nil
}

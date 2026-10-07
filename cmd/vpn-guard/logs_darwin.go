package main

import (
	"os"

	"github.com/robotNIXX/guardvpn/internal/logging"
	"github.com/robotNIXX/guardvpn/internal/paths"
)

// openDaemonLogs writes events to /var/log/vpn-guard.log (rotated by size).
// ERROR events and runtime crashes go to stderr, which launchd redirects
// to /var/log/vpn-guard-error.log.
func openDaemonLogs() (*logging.Logger, func(), error) {
	f, err := logging.OpenRotating(paths.Get().LogFile, 10<<20, 5)
	if err != nil {
		return nil, nil, err
	}
	return logging.New(f, os.Stderr, logging.LevelInfo), func() { f.Close() }, nil
}

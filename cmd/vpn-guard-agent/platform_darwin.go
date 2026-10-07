package main

import (
	"errors"
	"os/exec"
)

// On macOS members of the admin group may change settings directly.
const elevateSupported = false

func elevate() error { return errors.New("not needed on macOS") }

func openLogs() error {
	return exec.Command("open", "-a", "Console", "/var/log/vpn-guard.log").Start()
}

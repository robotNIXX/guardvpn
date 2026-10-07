package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Changing settings needs an elevated (UAC) token.
const elevateSupported = true

// elevate starts a new agent instance with administrator rights; the
// caller quits the current one.
func elevate() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	args, _ := windows.UTF16PtrFromString("-elevated -show")
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	return windows.ShellExecute(0, verb, file, args, dir, windows.SW_SHOWNORMAL)
}

func openLogs() error {
	dir := filepath.Join(os.Getenv("ProgramData"), "VPNGuard", "logs")
	return exec.Command("explorer.exe", dir).Start()
}

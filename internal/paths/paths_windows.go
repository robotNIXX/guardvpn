package paths

import (
	"os"
	"path/filepath"
)

func programData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}

// Get returns the Windows defaults (%ProgramData%\VPNGuard).
func Get() Defaults {
	d := defaults()
	if v := os.Getenv(IPCOverrideEnv); v != "" {
		d.IPCAddress = v
	}
	return d
}

func defaults() Defaults {
	base := filepath.Join(programData(), "VPNGuard")
	return Defaults{
		Config:     filepath.Join(base, "config.json"),
		LogFile:    filepath.Join(base, "logs", "vpn-guard.log"),
		ErrorLog:   filepath.Join(base, "logs", "vpn-guard-error.log"),
		IPCNetwork: "tcp",
		IPCAddress: "127.0.0.1:47290",
	}
}

package paths

import "os"

// Get returns the macOS defaults described in the specification.
func Get() Defaults {
	d := defaults()
	if v := os.Getenv(IPCOverrideEnv); v != "" {
		d.IPCAddress = v
	}
	return d
}

func defaults() Defaults {
	return Defaults{
		Config:     "/etc/vpn-guard/config.json",
		LogFile:    "/var/log/vpn-guard.log",
		ErrorLog:   "/var/log/vpn-guard-error.log",
		IPCAddress: "/var/run/vpn-guard.sock",
	}
}

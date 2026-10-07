// Package paths defines default filesystem locations for each platform.
package paths

// Defaults bundles the platform-specific locations used by the daemon.
type Defaults struct {
	Config   string
	LogFile  string
	ErrorLog string
	// IPCAddress is a unix socket path (darwin) or a loopback TCP address (windows).
	IPCNetwork string
	IPCAddress string
}

// IPCOverrideEnv overrides Defaults.IPCAddress (development and tests only,
// e.g. running the daemon unprivileged with -console).
const IPCOverrideEnv = "VPN_GUARD_IPC_ADDR"

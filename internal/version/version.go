// Package version holds build metadata injected via -ldflags.
package version

// Set at build time: -ldflags "-X github.com/robotNIXX/guardvpn/internal/version.Version=1.0.0".
var (
	Version = "dev"
	Commit  = "unknown"
)

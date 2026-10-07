package process

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/robotNIXX/guardvpn/internal/config"
)

// darwinIdentity matches a process when any of these holds:
//  1. its executable lies inside the configured bundle (main binary,
//     helpers, XPC services, crashpad, ...);
//  2. it lies inside any .app bundle whose CFBundleIdentifier equals the
//     configured bundle_id (copies of Target.app moved elsewhere);
//  3. its code signature has the bundle's Team ID and signing identifier
//     (binary extracted from the bundle).
//
// A process named "Target" inside another bundle matches none of these.
type darwinIdentity struct {
	bundlePath string // cleaned, symlinks resolved, no trailing slash
	bundleID   string
	executable string
	teamID     string
	signingID  string

	mu          sync.Mutex
	bundleCache map[string]string // bundle dir -> CFBundleIdentifier
	signCache   map[string][2]string
}

// NewIdentity builds the identity from config. The returned identity is
// always usable (for fail-closed enforcement); err reports problems such as
// a bundle ID or Team ID mismatch that must keep the guard blocked.
func NewIdentity(app *config.DarwinApp) (Identity, error) {
	if app == nil {
		return nil, fmt.Errorf("no application.darwin section")
	}
	id := &darwinIdentity{
		bundlePath:  cleanBundle(app.Path),
		bundleID:    app.BundleID,
		teamID:      app.TeamID,
		bundleCache: map[string]string{},
		signCache:   map[string][2]string{},
	}
	if id.bundlePath == "" {
		return id, fmt.Errorf("application path is empty")
	}

	var problems []string
	bid, exe, err := bundleInfo(id.bundlePath)
	switch {
	case err != nil:
		problems = append(problems, fmt.Sprintf("read bundle: %v", err))
	case id.bundleID != "" && bid != id.bundleID:
		problems = append(problems, fmt.Sprintf("bundle %s has identifier %q, expected %q", id.bundlePath, bid, id.bundleID))
	default:
		if id.bundleID == "" {
			id.bundleID = bid
		}
		id.executable = exe
	}

	team, ident, err := signingInfo(id.bundlePath)
	switch {
	case err != nil:
		if app.TeamID != "" {
			problems = append(problems, fmt.Sprintf("team_id configured but %v", err))
		}
	case app.TeamID != "" && team != app.TeamID:
		problems = append(problems, fmt.Sprintf("bundle is signed by team %q, expected %q", team, app.TeamID))
	default:
		id.teamID, id.signingID = team, ident
	}

	if len(problems) > 0 {
		return id, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return id, nil
}

func cleanBundle(p string) string {
	if p == "" {
		return ""
	}
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}

func (d *darwinIdentity) Describe() []Field {
	return []Field{
		{"Application", d.bundlePath},
		{"Bundle ID", d.bundleID},
		{"Executable", d.executable},
		{"Team ID", d.teamID},
		{"Signing ID", d.signingID},
	}
}

var systemPrefixes = []string{"/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/"}

func (d *darwinIdentity) IsTarget(p Proc) bool {
	if p.Path == "" {
		return false
	}
	// Rule 1: inside the configured bundle.
	if strings.HasPrefix(p.Path, d.bundlePath+"/") {
		return true
	}
	for _, sp := range systemPrefixes {
		if strings.HasPrefix(p.Path, sp) {
			return false
		}
	}
	// Rule 2: inside any bundle with the same identifier.
	if d.bundleID != "" {
		for _, b := range enclosingBundles(p.Path) {
			if d.bundleIDOf(b) == d.bundleID {
				return true
			}
		}
	}
	// Rule 3: same signer and signing identifier.
	if d.teamID != "" && d.signingID != "" {
		team, ident := d.signingOf(p.Path)
		if team == d.teamID && ident == d.signingID {
			return true
		}
	}
	return false
}

// enclosingBundles returns every "*.app" directory in path, outermost first.
func enclosingBundles(path string) []string {
	var out []string
	parts := strings.Split(path, "/")
	for i, part := range parts[:len(parts)-1] {
		if strings.HasSuffix(part, ".app") {
			out = append(out, strings.Join(parts[:i+1], "/"))
		}
	}
	return out
}

func (d *darwinIdentity) bundleIDOf(bundle string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.bundleCache[bundle]; ok {
		return v
	}
	id, _, _ := bundleInfo(bundle)
	if len(d.bundleCache) > 4096 {
		clear(d.bundleCache)
	}
	d.bundleCache[bundle] = id
	return id
}

func (d *darwinIdentity) signingOf(path string) (string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.signCache[path]; ok {
		return v[0], v[1]
	}
	team, ident, _ := signingInfo(path)
	if len(d.signCache) > 4096 {
		clear(d.signCache)
	}
	d.signCache[path] = [2]string{team, ident}
	return team, ident
}

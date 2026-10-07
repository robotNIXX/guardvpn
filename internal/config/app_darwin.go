package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// App returns the section for the current platform.
func (a Application) App() *DarwinApp { return a.Darwin }

func validateApplication(a Application) error {
	d := a.Darwin
	if d == nil {
		return errors.New("application.darwin section is required on macOS")
	}
	var p []string
	if d.Path == "" {
		p = append(p, "application.darwin.path is required")
	} else {
		if !strings.HasSuffix(strings.TrimRight(d.Path, "/"), ".app") {
			p = append(p, fmt.Sprintf("application.darwin.path %q must point to an .app bundle", d.Path))
		}
		if st, err := os.Stat(d.Path); err != nil {
			p = append(p, fmt.Sprintf("application.darwin.path %q does not exist", d.Path))
		} else if !st.IsDir() {
			p = append(p, fmt.Sprintf("application.darwin.path %q is not a bundle directory", d.Path))
		}
	}
	if d.BundleID == "" {
		p = append(p, "application.darwin.bundle_id is required")
	}
	if len(p) > 0 {
		return errors.New(strings.Join(p, "; "))
	}
	return nil
}

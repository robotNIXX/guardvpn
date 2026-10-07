package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Current returns the section for this platform (nil if absent).
func (a App) Current() *DarwinApp { return a.Darwin }

func validateCurrent(a App) error {
	d := a.Darwin
	var p []string
	if d.Path == "" {
		p = append(p, "darwin.path is required")
	} else {
		if !strings.HasSuffix(strings.TrimRight(d.Path, "/"), ".app") {
			p = append(p, fmt.Sprintf("%q must point to an .app bundle", d.Path))
		}
		if st, err := os.Stat(d.Path); err != nil {
			p = append(p, fmt.Sprintf("%q does not exist", d.Path))
		} else if !st.IsDir() {
			p = append(p, fmt.Sprintf("%q is not a bundle directory", d.Path))
		}
	}
	if d.BundleID == "" {
		p = append(p, "darwin.bundle_id is required")
	}
	if len(p) > 0 {
		return errors.New(strings.Join(p, "; "))
	}
	return nil
}

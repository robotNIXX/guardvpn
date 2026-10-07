package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Current returns the section for this platform (nil if absent).
func (a App) Current() *WindowsApp { return a.Windows }

func validateCurrent(a App) error {
	w := a.Windows
	var p []string
	if w.Path == "" {
		p = append(p, "windows.path is required")
	} else {
		if !strings.EqualFold(lastExt(w.Path), ".exe") {
			p = append(p, fmt.Sprintf("%q must point to an .exe", w.Path))
		}
		if st, err := os.Stat(w.Path); err != nil {
			p = append(p, fmt.Sprintf("%q does not exist", w.Path))
		} else if st.IsDir() {
			p = append(p, fmt.Sprintf("%q is a directory", w.Path))
		}
	}
	if len(p) > 0 {
		return errors.New(strings.Join(p, "; "))
	}
	return nil
}

func lastExt(p string) string {
	i := strings.LastIndexByte(p, '.')
	if i < 0 {
		return ""
	}
	return p[i:]
}

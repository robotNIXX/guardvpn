package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// App returns the section for the current platform.
func (a Application) App() *WindowsApp { return a.Windows }

func validateApplication(a Application) error {
	w := a.Windows
	if w == nil {
		return errors.New("application.windows section is required on Windows")
	}
	var p []string
	if w.Path == "" {
		p = append(p, "application.windows.path is required")
	} else {
		if !strings.EqualFold(lastExt(w.Path), ".exe") {
			p = append(p, fmt.Sprintf("application.windows.path %q must point to an .exe", w.Path))
		}
		if st, err := os.Stat(w.Path); err != nil {
			p = append(p, fmt.Sprintf("application.windows.path %q does not exist", w.Path))
		} else if st.IsDir() {
			p = append(p, fmt.Sprintf("application.windows.path %q is a directory", w.Path))
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

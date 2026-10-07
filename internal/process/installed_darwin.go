package process

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// InstalledApps lists application bundles in the standard folders
// (one level deep, plus one level of sub-folders such as /Applications/Utilities).
// Only Info.plist is read; signatures are checked when an app is added.
func InstalledApps() []AppInfo {
	home, _ := os.UserHomeDir()
	roots := []string{"/Applications", "/System/Applications", filepath.Join(home, "Applications")}
	seen := map[string]bool{}
	var out []AppInfo
	add := func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		id, exe, name, err := bundlePlist(path)
		if err != nil || id == "" {
			return
		}
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(path), ".app")
		}
		out = append(out, AppInfo{Name: name, Path: path, BundleID: id, Executable: exe})
	}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(root, e.Name())
			if strings.HasSuffix(e.Name(), ".app") {
				add(p)
				continue
			}
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			sub, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, s := range sub {
				if strings.HasSuffix(s.Name(), ".app") {
					add(filepath.Join(p, s.Name()))
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

package process

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Inspect reads the identity of an .app bundle.
func Inspect(path string) (AppInfo, error) {
	path = filepath.Clean(path)
	if !strings.HasSuffix(path, ".app") {
		return AppInfo{}, fmt.Errorf("%s is not an .app bundle", path)
	}
	id, exe, name, err := bundlePlist(path)
	if err != nil {
		return AppInfo{}, err
	}
	if id == "" {
		return AppInfo{}, fmt.Errorf("%s has no CFBundleIdentifier", path)
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), ".app")
	}
	info := AppInfo{Name: name, Path: path, BundleID: id, Executable: exe}
	team, ident, err := signingInfo(path)
	switch {
	case err != nil:
		info.Warning = "приложение не подписано: копии будут распознаваться только по bundle ID"
	case team == "" && strings.HasPrefix(ident, "com.apple."):
		info.SigningID = ident // Apple platform apps carry no Team ID
	case team == "":
		info.SigningID = ident
		info.Warning = "у приложения нет Team ID (ad-hoc подпись): копии будут распознаваться только по bundle ID"
	default:
		info.TeamID, info.SigningID = team, ident
	}
	return info, nil
}

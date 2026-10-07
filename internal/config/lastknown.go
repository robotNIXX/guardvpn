package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SaveLastKnownApps stores the applications of a config that loaded
// successfully. The file is used only to keep *blocking* applications when
// a later config is unreadable; it never grants anything.
func SaveLastKnownApps(path string, apps []App) error {
	data, err := json.MarshalIndent(apps, "", "  ")
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == string(data) {
		return nil
	}
	return WriteFileAtomic(path, data, 0o600)
}

// LoadLastKnownApps reads a list saved by SaveLastKnownApps.
func LoadLastKnownApps(path string) ([]App, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var apps []App
	err = json.Unmarshal(data, &apps)
	return apps, err
}

// WriteFileAtomic writes data to a temp file in the same directory and
// renames it over path, so readers never see a partial file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

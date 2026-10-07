package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SaveLastKnownApplication stores the application section of a config
// that validated successfully. It is used only to keep *blocking* the
// application when a later config is broken; it never grants anything.
func SaveLastKnownApplication(path string, app Application) error {
	data, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == string(data) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".last-known-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadLastKnownApplication reads a section saved by SaveLastKnownApplication.
func LoadLastKnownApplication(path string) (Application, error) {
	var app Application
	data, err := os.ReadFile(path)
	if err != nil {
		return app, err
	}
	err = json.Unmarshal(data, &app)
	return app, err
}

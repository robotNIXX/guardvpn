package process

// InstalledApps is not implemented on Windows: the settings UI uses the
// file dialog to pick an .exe.
func InstalledApps() []AppInfo { return nil }

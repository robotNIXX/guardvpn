package process

// AppInfo describes an application chosen in the settings UI.
type AppInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// macOS
	BundleID   string `json:"bundle_id,omitempty"`
	Executable string `json:"executable,omitempty"`
	TeamID     string `json:"team_id,omitempty"`
	SigningID  string `json:"signing_id,omitempty"`
	// Windows
	Publisher    string `json:"publisher,omitempty"`
	OriginalName string `json:"original_name,omitempty"`
	Product      string `json:"product,omitempty"`
	// Warning is set when the app can be controlled but some identity
	// information (e.g. a code signature) is missing.
	Warning string `json:"warning,omitempty"`
}

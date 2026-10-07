// Package config loads and validates /etc/vpn-guard/config.json
// (%ProgramData%\VPNGuard\config.json on Windows).
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/robotNIXX/guardvpn/internal/logging"
)

// GeoIP provider types with built-in response parsers.
const (
	ProviderIPInfoLite      = "ipinfo_lite"
	ProviderCloudflareTrace = "cloudflare_trace"
)

// GeoIP policies.
const (
	PolicyFirstSuccess = "first_success"
	PolicyAllAgree     = "all_agree"
)

// IPv6 check modes.
const (
	IPv6Auto     = "auto"     // check IPv6 when the host has a global IPv6 address
	IPv6Required = "required" // IPv6 must always be verified
	IPv6Disabled = "disabled" // never check IPv6
)

// Config is the on-disk configuration.
type Config struct {
	// Applications are the controlled applications.
	Applications []App `json:"applications"`
	// Application is the single-app format of V1.0, accepted on load and
	// converted into Applications.
	Application *Application `json:"application,omitempty"`

	// AllowedCountries is the default list for applications that do not
	// define their own.
	AllowedCountries []string `json:"allowed_countries"`

	ProcessCheckIntervalMs      int `json:"process_check_interval_ms"`
	NetworkCheckIntervalSeconds int `json:"network_check_interval_seconds"`
	UnknownRetrySeconds         int `json:"unknown_retry_seconds"`
	NetworkTimeoutMs            int `json:"network_timeout_ms"`
	NetworkDebounceMs           int `json:"network_debounce_ms"`
	TerminateTimeoutMs          int `json:"terminate_timeout_ms"`

	GeoIP   GeoIP   `json:"geoip"`
	Logging Logging `json:"logging"`
}

// App is one controlled application. One file is shared by both
// platforms; each OS reads its own section and ignores apps without one.
type App struct {
	Name string `json:"name"`
	// Disabled apps are not controlled (they may run freely).
	Disabled bool `json:"disabled,omitempty"`
	// AllowedCountries overrides Config.AllowedCountries for this app.
	AllowedCountries []string    `json:"allowed_countries,omitempty"`
	Darwin           *DarwinApp  `json:"darwin,omitempty"`
	Windows          *WindowsApp `json:"windows,omitempty"`
}

// Application is the V1.0 per-platform section (legacy format).
type Application struct {
	Darwin  *DarwinApp  `json:"darwin,omitempty"`
	Windows *WindowsApp `json:"windows,omitempty"`
}

// DarwinApp identifies the app on macOS.
type DarwinApp struct {
	Path     string `json:"path"`              // /Applications/Target.app
	BundleID string `json:"bundle_id"`         // com.vendor.target
	TeamID   string `json:"team_id,omitempty"` // optional, verified against the bundle signature
}

// WindowsApp identifies the app on Windows.
type WindowsApp struct {
	Path      string `json:"path"`                // C:\Program Files\Target\Target.exe
	Publisher string `json:"publisher,omitempty"` // Authenticode signer display name, e.g. "Vendor Ltd"
}

// GeoIP configures external IP/country lookup.
type GeoIP struct {
	Policy    string     `json:"policy"`
	Providers []Provider `json:"providers"`
	IPv6      string     `json:"ipv6"`
}

// Provider is one GeoIP service. URL/URLv6 override built-in endpoints.
type Provider struct {
	Type  string `json:"type"`
	Token string `json:"token,omitempty"`
	URL   string `json:"url,omitempty"`
	URLv6 string `json:"url_v6,omitempty"`
}

// Logging configures log output. Log file locations are fixed per platform
// (see internal/paths).
type Logging struct {
	Level string `json:"level"`
}

// Defaults applied when a field is omitted (zero).
const (
	DefaultProcessCheckIntervalMs      = 500
	DefaultNetworkCheckIntervalSeconds = 30
	DefaultUnknownRetrySeconds         = 5
	DefaultNetworkTimeoutMs            = 3000
	DefaultNetworkDebounceMs           = 300
	DefaultTerminateTimeoutMs          = 2000
)

// ValidationError lists every problem found in a parsed config.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration: " + strings.Join(e.Problems, "; ")
}

// Load reads, parses, applies defaults and validates the config.
// Per-application problems are reported separately by AppProblems.
//
// When the file parses but fails validation, the parsed *Config is returned
// together with a *ValidationError so the daemon can still use whatever is
// usable (e.g. application identity) while staying fail-closed.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse is Load without the file read.
func Parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return &c, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	def(&c.ProcessCheckIntervalMs, DefaultProcessCheckIntervalMs)
	def(&c.NetworkCheckIntervalSeconds, DefaultNetworkCheckIntervalSeconds)
	def(&c.UnknownRetrySeconds, DefaultUnknownRetrySeconds)
	def(&c.NetworkTimeoutMs, DefaultNetworkTimeoutMs)
	def(&c.NetworkDebounceMs, DefaultNetworkDebounceMs)
	def(&c.TerminateTimeoutMs, DefaultTerminateTimeoutMs)
	if c.GeoIP.Policy == "" {
		c.GeoIP.Policy = PolicyFirstSuccess
	}
	if c.GeoIP.IPv6 == "" {
		c.GeoIP.IPv6 = IPv6Auto
	}
	if len(c.GeoIP.Providers) == 0 {
		c.GeoIP.Providers = []Provider{{Type: ProviderCloudflareTrace}}
	}
	normCountries(c.AllowedCountries)

	// Convert the V1.0 single-application format.
	if c.Application != nil {
		if len(c.Applications) == 0 && (c.Application.Darwin != nil || c.Application.Windows != nil) {
			c.Applications = []App{{
				Name:    legacyName(c.Application),
				Darwin:  c.Application.Darwin,
				Windows: c.Application.Windows,
			}}
		}
		c.Application = nil
	}
	for i := range c.Applications {
		a := &c.Applications[i]
		a.Name = strings.TrimSpace(a.Name)
		normCountries(a.AllowedCountries)
	}
}

func normCountries(cs []string) {
	for i, cc := range cs {
		cs[i] = strings.ToUpper(strings.TrimSpace(cc))
	}
}

func legacyName(a *Application) string {
	base := func(p string) string {
		p = strings.TrimRight(strings.ReplaceAll(p, "\\", "/"), "/")
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			p = p[i+1:]
		}
		return strings.TrimSuffix(strings.TrimSuffix(p, ".app"), ".exe")
	}
	if a.Darwin != nil && a.Darwin.Path != "" {
		return base(a.Darwin.Path)
	}
	if a.Windows != nil && a.Windows.Path != "" {
		return base(a.Windows.Path)
	}
	return "Application"
}

// CountriesFor returns the effective allowed countries of an application.
func (c *Config) CountriesFor(a App) []string {
	if len(a.AllowedCountries) > 0 {
		return a.AllowedCountries
	}
	return c.AllowedCountries
}

// Enabled returns the applications controlled on this platform.
func (c *Config) Enabled() []App {
	var out []App
	for _, a := range c.Applications {
		if !a.Disabled && a.Current() != nil {
			out = append(out, a)
		}
	}
	return out
}

// AllCountries returns the union of the allowed countries of every
// enabled application (the default list when there is none).
func (c *Config) AllCountries() []string {
	seen := map[string]bool{}
	var out []string
	add := func(cs []string) {
		for _, cc := range cs {
			if !seen[cc] {
				seen[cc] = true
				out = append(out, cc)
			}
		}
	}
	enabled := c.Enabled()
	if len(enabled) == 0 {
		add(c.AllowedCountries)
	}
	for _, a := range enabled {
		add(c.CountriesFor(a))
	}
	return out
}

// AppProblems checks each application's section for the current platform
// (bundle/exe exists etc.). Problems are per application and do not make
// the whole configuration invalid: the affected app simply stays blocked.
func (c *Config) AppProblems() map[string]error {
	out := map[string]error{}
	for _, a := range c.Applications {
		if a.Disabled || a.Current() == nil {
			continue
		}
		if err := validateCurrent(a); err != nil {
			out[a.Name] = err
		}
	}
	return out
}

var countryRe = regexp.MustCompile(`^[A-Z]{2}$`)

// Validate checks the config; it assumes defaults were applied.
func (c *Config) Validate() error {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	names := map[string]bool{}
	for i, a := range c.Applications {
		switch {
		case a.Name == "":
			add("applications[%d]: name is required", i)
		case names[strings.ToLower(a.Name)]:
			add("applications: duplicate name %q", a.Name)
		}
		names[strings.ToLower(a.Name)] = true
		if a.Darwin == nil && a.Windows == nil {
			add("applications[%d] %q: needs a darwin or windows section", i, a.Name)
		}
		for _, cc := range a.AllowedCountries {
			if !countryRe.MatchString(cc) {
				add("applications[%d] %q: %q is not an ISO 3166-1 alpha-2 code", i, a.Name, cc)
			}
		}
	}

	if len(c.AllowedCountries) == 0 {
		add("allowed_countries must not be empty")
	}
	for _, cc := range c.AllowedCountries {
		if !countryRe.MatchString(cc) {
			add("allowed_countries: %q is not an ISO 3166-1 alpha-2 code", cc)
		}
	}

	for name, v := range map[string]int{
		"process_check_interval_ms":      c.ProcessCheckIntervalMs,
		"network_check_interval_seconds": c.NetworkCheckIntervalSeconds,
		"unknown_retry_seconds":          c.UnknownRetrySeconds,
		"network_timeout_ms":             c.NetworkTimeoutMs,
		"network_debounce_ms":            c.NetworkDebounceMs,
		"terminate_timeout_ms":           c.TerminateTimeoutMs,
	} {
		if v <= 0 {
			add("%s must be > 0", name)
		}
	}

	switch c.GeoIP.Policy {
	case PolicyFirstSuccess, PolicyAllAgree:
	default:
		add("geoip.policy must be %q or %q", PolicyFirstSuccess, PolicyAllAgree)
	}
	switch c.GeoIP.IPv6 {
	case IPv6Auto, IPv6Required, IPv6Disabled:
	default:
		add("geoip.ipv6 must be %q, %q or %q", IPv6Auto, IPv6Required, IPv6Disabled)
	}
	for i, pr := range c.GeoIP.Providers {
		switch pr.Type {
		case ProviderIPInfoLite:
			if pr.Token == "" {
				add("geoip.providers[%d]: ipinfo_lite requires token", i)
			}
		case ProviderCloudflareTrace:
		default:
			add("geoip.providers[%d]: unknown type %q", i, pr.Type)
		}
		for _, u := range []string{pr.URL, pr.URLv6} {
			if u == "" {
				continue
			}
			if err := requireHTTPS(u); err != nil {
				add("geoip.providers[%d]: %v", i, err)
			}
		}
	}

	if _, err := logging.ParseLevel(c.Logging.Level); err != nil {
		add("logging.level: %v", err)
	}

	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("url %q must use https", raw)
	}
	return nil
}

// ProcessCheckInterval etc. are typed accessors.
func (c *Config) ProcessCheckInterval() time.Duration {
	return time.Duration(c.ProcessCheckIntervalMs) * time.Millisecond
}
func (c *Config) NetworkCheckInterval() time.Duration {
	return time.Duration(c.NetworkCheckIntervalSeconds) * time.Second
}
func (c *Config) UnknownRetry() time.Duration {
	return time.Duration(c.UnknownRetrySeconds) * time.Second
}
func (c *Config) NetworkTimeout() time.Duration {
	return time.Duration(c.NetworkTimeoutMs) * time.Millisecond
}
func (c *Config) NetworkDebounce() time.Duration {
	return time.Duration(c.NetworkDebounceMs) * time.Millisecond
}
func (c *Config) TerminateTimeout() time.Duration {
	return time.Duration(c.TerminateTimeoutMs) * time.Millisecond
}

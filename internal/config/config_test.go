package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// appSection returns a valid application section for the current OS.
func appSection(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		exe := filepath.Join(dir, "Target.exe")
		if err := os.WriteFile(exe, []byte("MZ"), 0o644); err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf(`{"windows": {"path": %q}}`, exe)
	}
	app := filepath.Join(dir, "Target.app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"darwin": {"path": %q, "bundle_id": "com.vendor.target"}}`, app)
}

func TestValidConfigAndDefaults(t *testing.T) {
	c, err := Parse([]byte(fmt.Sprintf(`{
		"application": %s,
		"allowed_countries": ["th", "SG"],
		"geoip": {"providers": [{"type": "ipinfo_lite", "token": "x"}, {"type": "cloudflare_trace"}]}
	}`, appSection(t))))
	if err != nil {
		t.Fatal(err)
	}
	if c.ProcessCheckIntervalMs != 500 || c.NetworkCheckIntervalSeconds != 30 ||
		c.NetworkTimeoutMs != 3000 || c.TerminateTimeoutMs != 2000 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.GeoIP.Policy != PolicyFirstSuccess || c.GeoIP.IPv6 != IPv6Auto {
		t.Fatalf("geoip defaults: %+v", c.GeoIP)
	}
	if strings.Join(c.AllowedCountries, ",") != "TH,SG" {
		t.Fatalf("countries not normalised: %v", c.AllowedCountries)
	}
}

func TestInvalidConfigs(t *testing.T) {
	app := appSection(t)
	cases := map[string]string{
		"empty countries":   `{"application": APP, "allowed_countries": []}`,
		"bad country":       `{"application": APP, "allowed_countries": ["Thailand"]}`,
		"negative interval": `{"application": APP, "allowed_countries": ["TH"], "process_check_interval_ms": -1}`,
		"http url":          `{"application": APP, "allowed_countries": ["TH"], "geoip": {"providers": [{"type": "cloudflare_trace", "url": "http://1.1.1.1/cdn-cgi/trace"}]}}`,
		"missing token":     `{"application": APP, "allowed_countries": ["TH"], "geoip": {"providers": [{"type": "ipinfo_lite"}]}}`,
		"unknown provider":  `{"application": APP, "allowed_countries": ["TH"], "geoip": {"providers": [{"type": "nope"}]}}`,
		"bad policy":        `{"application": APP, "allowed_countries": ["TH"], "geoip": {"policy": "any"}}`,
		"app without name":  `{"applications": [{"darwin": {"path": "/a.app", "bundle_id": "a"}}], "allowed_countries": ["TH"]}`,
		"duplicate names":   `{"applications": [{"name": "A", "darwin": {"path": "/a.app", "bundle_id": "a"}}, {"name": "a", "windows": {"path": "C:\\a.exe"}}], "allowed_countries": ["TH"]}`,
		"app without os":    `{"applications": [{"name": "A"}], "allowed_countries": ["TH"]}`,
		"bad app country":   `{"applications": [{"name": "A", "allowed_countries": ["xx1"], "darwin": {"path": "/a.app", "bundle_id": "a"}}], "allowed_countries": ["TH"]}`,
		"bad log level":     `{"application": APP, "allowed_countries": ["TH"], "logging": {"level": "loud"}}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := Parse([]byte(strings.ReplaceAll(js, "APP", app)))
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want ValidationError, got %v", err)
			}
			if c == nil {
				t.Fatal("parsed config must be returned for fail-closed enforcement")
			}
		})
	}
}

func TestBrokenJSON(t *testing.T) {
	if c, err := Parse([]byte(`{"allowed_countries": [`)); err == nil || c != nil {
		t.Fatal("want parse error and nil config")
	}
	if _, err := Parse([]byte(`{"unknown_field": 1}`)); err == nil {
		t.Fatal("unknown fields must be rejected (typos must not silently disable checks)")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("want error")
	}
}

func TestLegacySingleApplicationConverted(t *testing.T) {
	c, err := Parse([]byte(fmt.Sprintf(`{"application": %s, "allowed_countries": ["TH"]}`, appSection(t))))
	if err != nil {
		t.Fatal(err)
	}
	if c.Application != nil || len(c.Applications) != 1 || c.Applications[0].Name != "Target" {
		t.Fatalf("legacy format not converted: %+v", c.Applications)
	}
	if len(c.AppProblems()) != 0 {
		t.Fatalf("unexpected app problems: %v", c.AppProblems())
	}
}

func TestMultipleApplications(t *testing.T) {
	c, err := Parse([]byte(`{
		"applications": [
			{"name": "A", "darwin": {"path": "/nonexistent/A.app", "bundle_id": "a"}, "windows": {"path": "C:\\nonexistent\\a.exe"}},
			{"name": "B", "allowed_countries": ["sg"], "darwin": {"path": "/b.app", "bundle_id": "b"}, "windows": {"path": "C:\\b.exe"}},
			{"name": "C", "disabled": true, "allowed_countries": ["DE"], "darwin": {"path": "/c.app", "bundle_id": "c"}, "windows": {"path": "C:\\c.exe"}},
			{"name": "OtherOS", "allowed_countries": ["US"], "linux_only": null}
		],
		"allowed_countries": ["TH"]
	}`))
	if err == nil {
		t.Fatal("unknown field linux_only must be rejected")
	}

	c, err = Parse([]byte(`{
		"applications": [
			{"name": "A", "darwin": {"path": "/nonexistent/A.app", "bundle_id": "a"}, "windows": {"path": "C:\\nonexistent\\a.exe"}},
			{"name": "B", "allowed_countries": ["sg"], "darwin": {"path": "/b.app", "bundle_id": "b"}, "windows": {"path": "C:\\b.exe"}},
			{"name": "C", "disabled": true, "allowed_countries": ["DE"], "darwin": {"path": "/c.app", "bundle_id": "c"}, "windows": {"path": "C:\\c.exe"}}
		],
		"allowed_countries": ["TH"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.CountriesFor(c.Applications[1]), ","); got != "SG" {
		t.Fatalf("per-app countries not normalised: %s", got)
	}
	if got := strings.Join(c.CountriesFor(c.Applications[0]), ","); got != "TH" {
		t.Fatalf("default countries not used: %s", got)
	}
	if n := len(c.Enabled()); n != 2 {
		t.Fatalf("enabled = %d, want 2 (disabled app excluded)", n)
	}
	if got := strings.Join(c.AllCountries(), ","); got != "TH,SG" {
		t.Fatalf("union = %s, want TH,SG (disabled app's DE excluded)", got)
	}
	// Missing paths are per-application problems, not a global error.
	probs := c.AppProblems()
	if probs["A"] == nil || probs["B"] == nil || probs["C"] != nil {
		t.Fatalf("app problems = %v", probs)
	}
}

func TestSaveLoadLastKnownApps(t *testing.T) {
	p := filepath.Join(t.TempDir(), "last.json")
	apps := []App{{Name: "A", Darwin: &DarwinApp{Path: "/a.app", BundleID: "a"}}}
	if err := SaveLastKnownApps(p, apps); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLastKnownApps(p)
	if err != nil || len(got) != 1 || got[0].Darwin.BundleID != "a" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if st, _ := os.Stat(p); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v", st.Mode().Perm())
	}
}

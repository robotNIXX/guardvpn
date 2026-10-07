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
		"no app section":    `{"application": {}, "allowed_countries": ["TH"]}`,
		"missing app path":  `{"application": {"darwin": {"path": "/nonexistent/X.app", "bundle_id": "a"}, "windows": {"path": "C:\\nonexistent\\x.exe"}}, "allowed_countries": ["TH"]}`,
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

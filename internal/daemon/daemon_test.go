package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/robotNIXX/guardvpn/internal/config"
	"github.com/robotNIXX/guardvpn/internal/guard"
	"github.com/robotNIXX/guardvpn/internal/ipc"
	"github.com/robotNIXX/guardvpn/internal/logging"
	"github.com/robotNIXX/guardvpn/internal/process"
)

type noProcs struct{}

func (noProcs) List() ([]process.Proc, error) { return nil, nil }

type noKill struct{}

func (noKill) Terminate(context.Context, []process.Proc, time.Duration) []process.KillResult {
	return nil
}

// newTestDaemon builds a daemon whose components are not running; only
// configuration handling is exercised.
func newTestDaemon(t *testing.T, cfg string) (*Daemon, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	d := New(path, logging.Discard())
	d.guard = guard.New(unknownChecker{"test"}, guard.Options{Interval: time.Hour, UnknownRetry: time.Hour})
	d.procs = process.NewMonitor(process.MonitorOptions{
		Lister: noProcs{}, Killer: noKill{}, Interval: time.Hour, TerminateTimeout: time.Second,
	})
	return d, path
}

const baseConfig = `{
  "applications": [],
  "allowed_countries": ["TH"],
  "geoip": {"providers": [{"type": "ipinfo_lite", "token": "s3cret"}, {"type": "cloudflare_trace"}]}
}`

func TestConfigMasksSecrets(t *testing.T) {
	d, _ := newTestDaemon(t, baseConfig)
	raw, err := d.Config()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") {
		t.Fatal("token leaked to client")
	}
	if !strings.Contains(string(raw), SecretMask) {
		t.Fatal("token not masked")
	}
}

func TestSetConfigKeepsMaskedToken(t *testing.T) {
	d, path := newTestDaemon(t, baseConfig)
	if err := d.applyConfig("startup", true); err != nil {
		t.Fatal(err)
	}
	raw, _ := d.Config()
	var c map[string]any
	_ = json.Unmarshal(raw, &c)
	c["allowed_countries"] = []string{"SG"}
	in, _ := json.Marshal(c)

	st, err := d.SetConfig(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if st.ConfigError != "" {
		t.Fatalf("config error after save: %s", st.ConfigError)
	}
	saved, _ := config.Load(path)
	if saved.GeoIP.Providers[0].Token != "s3cret" {
		t.Fatalf("token = %q, want the original secret", saved.GeoIP.Providers[0].Token)
	}
	if saved.AllowedCountries[0] != "SG" {
		t.Fatalf("change not saved: %v", saved.AllowedCountries)
	}
}

func TestSetConfigRejectsInvalid(t *testing.T) {
	d, path := newTestDaemon(t, baseConfig)
	before, _ := os.ReadFile(path)
	_, err := d.SetConfig(context.Background(), json.RawMessage(`{"applications": [], "allowed_countries": []}`))
	var pe *ipc.ConfigProblemsError
	if !errors.As(err, &pe) || len(pe.Problems) == 0 {
		t.Fatalf("want ConfigProblemsError, got %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("invalid config must not be written")
	}
	_, err = d.SetConfig(context.Background(), json.RawMessage(`{"bogus": 1}`))
	if !errors.As(err, &pe) {
		t.Fatalf("unknown field must be rejected, got %v", err)
	}
}

func TestFailClosedAndRecovery(t *testing.T) {
	d, path := newTestDaemon(t, baseConfig)
	if err := d.applyConfig("startup", true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"allowed_countries": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.applyConfig("changed", false); err == nil {
		t.Fatal("broken config must fail")
	}
	if st := d.Status(); st.State != "BLOCKED" || st.ConfigError == "" {
		t.Fatalf("status = %s / %q, want BLOCKED with config error", st.State, st.ConfigError)
	}
	if err := os.WriteFile(path, []byte(baseConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.applyConfig("changed", false); err != nil {
		t.Fatal(err)
	}
	if st := d.Status(); st.ConfigError != "" {
		t.Fatalf("still fail-closed: %s", st.ConfigError)
	}
}

func TestUnchangedConfigSkipped(t *testing.T) {
	d, _ := newTestDaemon(t, baseConfig)
	if err := d.applyConfig("startup", true); err != nil {
		t.Fatal(err)
	}
	first := d.Status().LoadedAt
	time.Sleep(5 * time.Millisecond)
	_ = d.applyConfig("fsnotify", false)
	if !d.Status().LoadedAt.Equal(first) {
		t.Fatal("an unchanged file must not be re-applied")
	}
	_ = d.applyConfig("reload requested", true)
	if d.Status().LoadedAt.Equal(first) {
		t.Fatal("a forced reload must re-apply")
	}
}

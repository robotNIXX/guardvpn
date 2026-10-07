// Package daemon wires the guard, the network and process monitors, the
// configuration watcher and the IPC server together.
//
// All components live for the whole process lifetime; a configuration
// change is applied to them in place (hot reload). The verified network
// state survives a reload, so running applications that are still allowed
// keep running.
package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/robotNIXX/guardvpn/internal/config"
	"github.com/robotNIXX/guardvpn/internal/guard"
	"github.com/robotNIXX/guardvpn/internal/ipc"
	"github.com/robotNIXX/guardvpn/internal/logging"
	"github.com/robotNIXX/guardvpn/internal/network"
	"github.com/robotNIXX/guardvpn/internal/process"
	"github.com/robotNIXX/guardvpn/internal/service"
	"github.com/robotNIXX/guardvpn/internal/version"
)

// SecretMask replaces secrets in configs returned to clients.
const SecretMask = "********"

// Daemon is the long-running vpn-guard process.
type Daemon struct {
	configPath string
	log        *logging.Logger
	started    time.Time

	guard  *guard.Guard
	procs  *process.Monitor
	reload chan string

	applyMu sync.Mutex // serialises applyConfig

	mu       sync.Mutex
	cfg      *config.Config // last parsed config (may be invalid)
	cfgErr   error          // non-nil: fail-closed
	apps     []*appRuntime
	ignored  []config.App // disabled apps or apps without a section for this OS
	loadedAt time.Time
	lastHash [32]byte
	netKey   string
}

type appRuntime struct {
	app      config.App
	allowed  []string
	set      map[string]bool
	identity process.Identity
	err      error // misconfigured: the app stays blocked
}

// New creates a daemon.
func New(configPath string, log *logging.Logger) *Daemon {
	return &Daemon{
		configPath: configPath,
		log:        log,
		started:    time.Now(),
		reload:     make(chan string, 1),
	}
}

// unknownChecker is used until a valid configuration is loaded.
type unknownChecker struct{ reason string }

func (u unknownChecker) Check(context.Context) guard.Result {
	return guard.Result{State: guard.StateUnknown, Reason: u.reason}
}

// Run is a service.Func.
func (d *Daemon) Run(ctx context.Context, power <-chan string) error {
	d.log.Info("daemon started", "version", version.Version, "pid", os.Getpid(), "config", d.configPath)
	defer d.log.Info("daemon stopped")

	d.guard = guard.New(unknownChecker{"configuration not loaded"}, guard.Options{
		Interval:     config.DefaultNetworkCheckIntervalSeconds * time.Second,
		UnknownRetry: config.DefaultUnknownRetrySeconds * time.Second,
		Debounce:     config.DefaultNetworkDebounceMs * time.Millisecond,
		Log:          d.log,
	})
	d.procs = process.NewMonitor(process.MonitorOptions{
		Lister:           process.NewLister(),
		Killer:           process.NewKiller(),
		Interval:         config.DefaultProcessCheckIntervalMs * time.Millisecond,
		TerminateTimeout: config.DefaultTerminateTimeoutMs * time.Millisecond,
		Changes:          d.guard.Subscribe(),
		Log:              d.log,
	})
	// Load before starting the monitors so the first scan already knows
	// the applications.
	_ = d.applyConfig("startup", true)

	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	run(d.guard.Run)
	run(network.NewMonitor(d.guard, d.log).Run)
	run(d.procs.Run)
	run(d.watchConfig)
	run(func(ctx context.Context) {
		if err := ipc.Serve(ctx, d, d.log); err != nil {
			d.log.Error("status server failed", "err", err)
		}
	})
	run(func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-power:
				d.log.Info("power event", "event", ev)
				// Nothing verified before sleep may be trusted after wake.
				d.guard.Invalidate("system " + ev)
			}
		}
	})

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case reason := <-d.reload:
			_ = d.applyConfig(reason, false)
		}
	}
}

// requestReload asks the main loop to re-read the config file.
func (d *Daemon) requestReload(reason string) {
	select {
	case d.reload <- reason:
	default:
	}
}

// applyConfig loads the config file and applies it. With force=false an
// unchanged, already applied file is skipped.
func (d *Daemon) applyConfig(reason string, force bool) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()

	data, err := os.ReadFile(d.configPath)
	if err != nil {
		err = fmt.Errorf("read config: %w", err)
		d.failClosed(nil, err)
		return err
	}
	hash := sha256.Sum256(data)
	d.mu.Lock()
	unchanged := hash == d.lastHash && d.cfgErr == nil && d.cfg != nil
	d.mu.Unlock()
	if unchanged && !force {
		d.log.Debug("configuration unchanged", "reason", reason)
		return nil
	}

	cfg, err := config.Parse(data)
	if cfg != nil {
		if lvl, lerr := logging.ParseLevel(cfg.Logging.Level); lerr == nil {
			d.log.SetLevel(lvl)
		}
	}
	if err != nil {
		d.failClosed(cfg, err)
		return err
	}
	checker, err := network.NewCheckerFromConfig(cfg, d.log)
	if err != nil {
		d.failClosed(cfg, err)
		return err
	}

	problems := cfg.AppProblems()
	var apps []*appRuntime
	var ignored []config.App
	var targets []process.Target
	for _, a := range cfg.Applications {
		if a.Disabled || a.Current() == nil {
			ignored = append(ignored, a)
			continue
		}
		rt := &appRuntime{app: a, allowed: cfg.CountriesFor(a)}
		rt.set = toSet(rt.allowed)
		rt.identity, rt.err = process.NewIdentity(a.Current())
		if p := problems[a.Name]; p != nil {
			rt.err = p
		}
		if rt.identity == nil { // defensive: NewIdentity always returns one
			continue
		}
		apps = append(apps, rt)
		targets = append(targets, process.Target{
			Name:     a.Name,
			Identity: rt.identity,
			Policy: process.PolicyFunc(func() bool {
				return rt.err == nil && d.guard.PermitsFor(rt.set)
			}),
		})
	}

	d.guard.SetChecker(checker)
	d.guard.SetOptions(guard.Options{
		Interval:     cfg.NetworkCheckInterval(),
		UnknownRetry: cfg.UnknownRetry(),
		Debounce:     cfg.NetworkDebounce(),
		Required:     cfg.AllCountries(),
	})
	d.procs.SetTiming(cfg.ProcessCheckInterval(), cfg.TerminateTimeout())
	d.procs.SetTargets(targets)

	nk := networkKey(cfg)
	d.mu.Lock()
	recheck := d.netKey != "" && d.netKey != nk
	wasFailClosed := d.cfgErr != nil
	d.cfg, d.cfgErr, d.apps, d.ignored = cfg, nil, apps, ignored
	d.loadedAt, d.lastHash, d.netKey = time.Now(), hash, nk
	d.mu.Unlock()
	if recheck {
		// GeoIP settings changed: verify with the new providers, but keep
		// the current state meanwhile (the network itself did not change).
		d.guard.RequestCheck()
	}

	names := make([]string, 0, len(apps))
	for _, rt := range apps {
		names = append(names, rt.app.Name)
	}
	msg := "configuration loaded"
	if reason != "startup" {
		msg = "configuration reloaded"
	}
	d.log.Info(msg, "reason", reason, "apps", strings.Join(names, ","),
		"default_countries", strings.Join(cfg.AllowedCountries, ","), "providers", len(cfg.GeoIP.Providers),
		"policy", cfg.GeoIP.Policy, "ipv6", cfg.GeoIP.IPv6)
	if wasFailClosed {
		d.log.Info("configuration valid again, leaving fail-closed mode")
	}
	for _, rt := range apps {
		if rt.err != nil {
			d.log.Error("application misconfigured, it stays blocked", "app", rt.app.Name, "err", rt.err)
			continue
		}
		kv := []any{"app", rt.app.Name, "allowed", strings.Join(rt.allowed, ",")}
		for _, f := range rt.identity.Describe() {
			if f.Value != "" {
				kv = append(kv, strings.ReplaceAll(strings.ToLower(f.Name), " ", "_"), f.Value)
			}
		}
		d.log.Info("application identity", kv...)
	}
	if len(apps) == 0 {
		d.log.Warn("no applications are controlled on this platform")
	}
	if err := config.SaveLastKnownApps(d.lastKnownPath(), cfg.Applications); err != nil {
		d.log.Warn("cannot save last known applications", "err", err)
	}
	return nil
}

// failClosed keeps every known application blocked while the
// configuration is unusable. The network state and checker are kept.
func (d *Daemon) failClosed(cfg *config.Config, cause error) {
	var appsCfg []config.App
	if cfg != nil && len(cfg.Applications) > 0 {
		appsCfg = cfg.Applications
	} else if last, err := config.LoadLastKnownApps(d.lastKnownPath()); err == nil {
		d.log.Warn("using last known applications for enforcement", "file", d.lastKnownPath())
		appsCfg = last
	}

	var apps []*appRuntime
	var targets []process.Target
	for _, a := range appsCfg {
		if a.Disabled || a.Current() == nil {
			continue
		}
		ident, _ := process.NewIdentity(a.Current())
		if ident == nil {
			continue
		}
		apps = append(apps, &appRuntime{app: a, identity: ident, err: cause})
		targets = append(targets, process.Target{
			Name: a.Name, Identity: ident, Policy: process.PolicyFunc(func() bool { return false }),
		})
	}
	d.procs.SetTargets(targets)

	d.mu.Lock()
	d.cfg, d.cfgErr, d.apps, d.ignored = cfg, cause, apps, nil
	d.lastHash = [32]byte{}
	d.mu.Unlock()

	d.log.Error("configuration error, staying fail-closed (applications blocked)", "err", cause)
	if len(apps) == 0 {
		d.log.Error("no application can be identified; nothing to enforce until the configuration is fixed")
	}
}

func networkKey(c *config.Config) string {
	b, _ := json.Marshal([]any{c.GeoIP, c.NetworkTimeoutMs})
	return string(b)
}

func toSet(cs []string) map[string]bool {
	m := make(map[string]bool, len(cs))
	for _, c := range cs {
		m[c] = true
	}
	return m
}

func subsetOf(cs []string, set map[string]bool) bool {
	if len(cs) == 0 {
		return false
	}
	for _, c := range cs {
		if !set[c] {
			return false
		}
	}
	return true
}

// lastKnownPath is where the last valid application list is kept so that
// a later broken config still lets the daemon find the apps to block.
func (d *Daemon) lastKnownPath() string {
	return filepath.Join(filepath.Dir(d.configPath), ".last-known-applications.json")
}

// ---- ipc.Handler ----

// Status implements ipc.Handler.
func (d *Daemon) Status() ipc.Status {
	st := d.guard.Snapshot()
	pids := d.procs.PIDs()

	d.mu.Lock()
	defer d.mu.Unlock()
	s := ipc.Status{
		Version:    version.Version,
		StartedAt:  d.started,
		State:      st.State.String(),
		Reason:     st.Reason,
		IPv4:       st.IPv4,
		IPv6:       st.IPv6,
		Country:    st.Country,
		Provider:   st.Provider,
		CheckedAt:  st.CheckedAt,
		ConfigPath: d.configPath,
		LoadedAt:   d.loadedAt,
		Apps:       []ipc.AppStatus{},
	}
	if d.cfgErr != nil {
		s.State = guard.StateBlocked.String()
		s.Reason = "configuration error"
		s.ConfigError = d.cfgErr.Error()
	}
	for _, rt := range d.apps {
		as := ipc.AppStatus{Name: rt.app.Name, Allowed: rt.allowed, PIDs: pids[rt.app.Name]}
		for _, f := range rt.identity.Describe() {
			as.Identity = append(as.Identity, ipc.Field{Name: f.Name, Value: f.Value})
		}
		switch {
		case rt.err != nil:
			as.State, as.Error = guard.StateBlocked.String(), rt.err.Error()
		case st.State.Verified():
			as.State = guard.StateBlocked.String()
			if subsetOf(st.Countries, rt.set) {
				as.State = guard.StateAllowed.String()
			}
		default:
			as.State = st.State.String()
		}
		s.Apps = append(s.Apps, as)
	}
	for _, a := range d.ignored {
		as := ipc.AppStatus{Name: a.Name, Disabled: true, State: "DISABLED"}
		if !a.Disabled {
			as.State, as.Error = "NOT CONFIGURED", "no section for this platform"
		}
		s.Apps = append(s.Apps, as)
	}
	return s
}

// Check implements ipc.Handler.
func (d *Daemon) Check(ctx context.Context) ipc.Status {
	_, _ = d.guard.CheckNow(ctx)
	return d.Status()
}

// Reload implements ipc.Handler.
func (d *Daemon) Reload(context.Context) (ipc.Status, error) {
	err := d.applyConfig("reload requested", true)
	return d.Status(), err
}

// Config implements ipc.Handler: the config file with secrets masked.
func (d *Daemon) Config() (json.RawMessage, error) {
	data, err := os.ReadFile(d.configPath)
	if err != nil {
		return nil, err
	}
	cfg, perr := config.Parse(data)
	if cfg == nil {
		return nil, perr
	}
	for i := range cfg.GeoIP.Providers {
		if cfg.GeoIP.Providers[i].Token != "" {
			cfg.GeoIP.Providers[i].Token = SecretMask
		}
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return out, perr
}

// SetConfig implements ipc.Handler: validate, save atomically, apply.
func (d *Daemon) SetConfig(_ context.Context, raw json.RawMessage) (ipc.Status, error) {
	var in config.Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return ipc.Status{}, &ipc.ConfigProblemsError{Problems: []string{"invalid JSON: " + err.Error()}}
	}

	// Masked tokens keep their current value.
	var cur *config.Config
	if data, err := os.ReadFile(d.configPath); err == nil {
		cur, _ = config.Parse(data)
	}
	for i := range in.GeoIP.Providers {
		p := &in.GeoIP.Providers[i]
		if p.Token != SecretMask {
			continue
		}
		p.Token = ""
		if cur == nil {
			continue
		}
		if i < len(cur.GeoIP.Providers) && cur.GeoIP.Providers[i].Type == p.Type {
			p.Token = cur.GeoIP.Providers[i].Token
		} else if j := slices.IndexFunc(cur.GeoIP.Providers, func(c config.Provider) bool { return c.Type == p.Type }); j >= 0 {
			p.Token = cur.GeoIP.Providers[j].Token
		}
	}

	data, err := json.Marshal(in)
	if err != nil {
		return ipc.Status{}, err
	}
	cfg, err := config.Parse(data)
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		return ipc.Status{}, &ipc.ConfigProblemsError{Problems: ve.Problems}
	}
	if err != nil {
		return ipc.Status{}, &ipc.ConfigProblemsError{Problems: []string{err.Error()}}
	}
	var problems []string
	appProblems := cfg.AppProblems()
	for _, a := range cfg.Applications {
		if a.Disabled || a.Current() == nil {
			continue
		}
		if p := appProblems[a.Name]; p != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", a.Name, p))
			continue
		}
		if _, err := process.NewIdentity(a.Current()); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", a.Name, err))
		}
	}
	if len(problems) > 0 {
		return ipc.Status{}, &ipc.ConfigProblemsError{Problems: problems}
	}

	// Save the normalised form (legacy fields converted, defaults filled).
	data, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return ipc.Status{}, err
	}
	if err := config.WriteFileAtomic(d.configPath, append(data, '\n'), 0o600); err != nil {
		return ipc.Status{}, fmt.Errorf("save config: %w", err)
	}
	err = d.applyConfig("updated from settings", true)
	return d.Status(), err
}

var _ service.Func = (*Daemon)(nil).Run

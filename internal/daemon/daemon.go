// Package daemon wires the guard, the network and process monitors, and
// the status server together.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// configPoll is how often the config file is checked for changes.
const configPoll = 5 * time.Second

// Daemon is the long-running vpn-guard process.
type Daemon struct {
	configPath string
	log        *logging.Logger
	started    time.Time

	mu       sync.Mutex
	statusFn func() ipc.Status
	checkFn  func(ctx context.Context) ipc.Status
}

// New creates a daemon.
func New(configPath string, log *logging.Logger) *Daemon {
	return &Daemon{configPath: configPath, log: log, started: time.Now()}
}

// Status implements ipc.Handler.
func (d *Daemon) Status() ipc.Status {
	d.mu.Lock()
	fn := d.statusFn
	d.mu.Unlock()
	if fn == nil {
		return d.base(guard.StateInitializing.String())
	}
	return fn()
}

// Check implements ipc.Handler.
func (d *Daemon) Check(ctx context.Context) ipc.Status {
	d.mu.Lock()
	fn := d.checkFn
	d.mu.Unlock()
	if fn == nil {
		return d.Status()
	}
	return fn(ctx)
}

func (d *Daemon) setStatus(status func() ipc.Status, check func(context.Context) ipc.Status) {
	d.mu.Lock()
	d.statusFn, d.checkFn = status, check
	d.mu.Unlock()
}

func (d *Daemon) base(state string) ipc.Status {
	return ipc.Status{Version: version.Version, StartedAt: d.started, State: state}
}

// Run is a service.Func.
func (d *Daemon) Run(ctx context.Context, power <-chan string) error {
	d.log.Info("daemon started", "version", version.Version, "pid", os.Getpid(), "config", d.configPath)
	defer d.log.Info("daemon stopped")

	go func() {
		if err := ipc.Serve(ctx, d, d.log); err != nil {
			d.log.Error("status server failed", "err", err)
		}
	}()

	for ctx.Err() == nil {
		stamp := fileStamp(d.configPath)
		cfg, err := config.Load(d.configPath)
		if cfg != nil {
			if lvl, lerr := logging.ParseLevel(cfg.Logging.Level); lerr == nil {
				d.log.SetLevel(lvl)
			}
		}
		if err == nil {
			var ident process.Identity
			ident, err = process.NewIdentity(cfg.Application.App())
			if err == nil {
				d.log.Info("configuration loaded", "allowed_countries", cfg.AllowedCountries,
					"providers", len(cfg.GeoIP.Providers), "policy", cfg.GeoIP.Policy, "ipv6", cfg.GeoIP.IPv6)
				logIdentity(d.log, ident)
				if err := config.SaveLastKnownApplication(d.lastKnownPath(), cfg.Application); err != nil {
					d.log.Warn("cannot save last known application identity", "err", err)
				}
				d.runGuarded(ctx, cfg, ident, stamp, power)
				continue
			}
		}
		d.runFailClosed(ctx, cfg, err, stamp)
	}
	return nil
}

func logIdentity(log *logging.Logger, ident process.Identity) {
	kv := []any{}
	for _, f := range ident.Describe() {
		if f.Value != "" {
			kv = append(kv, strings.ReplaceAll(strings.ToLower(f.Name), " ", "_"), f.Value)
		}
	}
	log.Info("application identity", kv...)
}

// runGuarded runs normal operation until ctx is done or the config changes.
func (d *Daemon) runGuarded(ctx context.Context, cfg *config.Config, ident process.Identity, stamp string, power <-chan string) {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	checker, err := network.NewCheckerFromConfig(cfg, d.log)
	if err != nil { // validated already; defensive
		d.runFailClosed(ctx, cfg, err, stamp)
		return
	}
	g := guard.New(checker, guard.Options{
		Interval:     cfg.NetworkCheckInterval(),
		UnknownRetry: cfg.UnknownRetry(),
		Debounce:     cfg.NetworkDebounce(),
		Required:     cfg.AllowedCountries,
		Log:          d.log,
	})
	pm := process.NewMonitor(process.MonitorOptions{
		Lister:           process.NewLister(),
		Identity:         ident,
		Killer:           process.NewKiller(),
		Policy:           g,
		Interval:         cfg.ProcessCheckInterval(),
		TerminateTimeout: cfg.TerminateTimeout(),
		Changes:          g.Subscribe(),
		Log:              d.log,
	})
	nm := network.NewMonitor(g, d.log)

	fields := toFields(ident.Describe())
	status := func() ipc.Status {
		st := g.Snapshot()
		s := d.base(st.State.String())
		s.Reason, s.IPv4, s.IPv6, s.Country, s.Provider = st.Reason, st.IPv4, st.IPv6, st.Country, st.Provider
		s.CheckedAt = st.CheckedAt
		s.Required = cfg.AllowedCountries
		s.Application = fields
		s.TargetPIDs = pm.TargetPIDs()
		return s
	}
	check := func(c context.Context) ipc.Status {
		_, _ = g.CheckNow(c)
		return status()
	}
	d.setStatus(status, check)

	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(rctx) }()
	}
	run(g.Run)
	run(nm.Run)
	run(pm.Run)
	run(func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-power:
				d.log.Info("power event", "event", ev)
				// Both sleep and wake invalidate: nothing verified before
				// sleep may be trusted after wake.
				g.Invalidate("system " + ev)
			}
		}
	})

	d.waitConfigChange(rctx, stamp)
	cancel()
	wg.Wait()
}

// runFailClosed keeps the application blocked while the configuration is
// unusable. It still terminates the application if it can be identified,
// and returns once the config file changes.
func (d *Daemon) runFailClosed(ctx context.Context, cfg *config.Config, cause error, stamp string) {
	d.log.Error("configuration error, staying fail-closed (application blocked)", "err", cause)

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var fields []ipc.Field
	var pm *process.Monitor
	app := config.Application{}
	if cfg != nil {
		app = cfg.Application
	}
	if app.App() == nil {
		// The file is unreadable or has no usable application section:
		// fall back to the last configuration that worked.
		if last, err := config.LoadLastKnownApplication(d.lastKnownPath()); err == nil && last.App() != nil {
			d.log.Warn("using last known application identity for enforcement", "file", d.lastKnownPath())
			app = last
		}
	}
	if app.App() != nil {
		if ident, _ := process.NewIdentity(app.App()); ident != nil {
			fields = toFields(ident.Describe())
			interval := config.DefaultProcessCheckIntervalMs * time.Millisecond
			term := config.DefaultTerminateTimeoutMs * time.Millisecond
			if cfg != nil && cfg.ProcessCheckIntervalMs > 0 {
				interval = cfg.ProcessCheckInterval()
			}
			if cfg != nil && cfg.TerminateTimeoutMs > 0 {
				term = cfg.TerminateTimeout()
			}
			pm = process.NewMonitor(process.MonitorOptions{
				Lister:           process.NewLister(),
				Identity:         ident,
				Killer:           process.NewKiller(),
				Policy:           denyAll{},
				Interval:         interval,
				TerminateTimeout: term,
				Log:              d.log,
			})
		}
	}
	if pm == nil {
		d.log.Error("application cannot be identified from the configuration; nothing to enforce until it is fixed")
	}

	status := func() ipc.Status {
		s := d.base(guard.StateBlocked.String())
		s.Reason = "configuration error"
		s.ConfigError = cause.Error()
		s.Application = fields
		if cfg != nil {
			s.Required = cfg.AllowedCountries
		}
		if pm != nil {
			s.TargetPIDs = pm.TargetPIDs()
		}
		return s
	}
	d.setStatus(status, func(context.Context) ipc.Status { return status() })

	var wg sync.WaitGroup
	if pm != nil {
		wg.Add(1)
		go func() { defer wg.Done(); pm.Run(rctx) }()
	}
	d.waitConfigChange(rctx, stamp)
	cancel()
	wg.Wait()
}

// lastKnownPath is where the last valid application section is kept so
// that a later broken config still lets the daemon find the app to block.
func (d *Daemon) lastKnownPath() string {
	return filepath.Join(filepath.Dir(d.configPath), ".last-known-application.json")
}

// waitConfigChange blocks until ctx is done or the config file changes.
func (d *Daemon) waitConfigChange(ctx context.Context, stamp string) {
	t := time.NewTicker(configPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s := fileStamp(d.configPath); s != stamp {
				d.log.Info("configuration file changed, reloading")
				return
			}
		}
	}
}

func fileStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "missing"
		}
		return "error"
	}
	return fmt.Sprintf("%d/%d", st.ModTime().UnixNano(), st.Size())
}

func toFields(fs []process.Field) []ipc.Field {
	out := make([]ipc.Field, 0, len(fs))
	for _, f := range fs {
		out = append(out, ipc.Field{Name: f.Name, Value: f.Value})
	}
	return out
}

type denyAll struct{}

func (denyAll) Allowed() bool { return false }

var _ service.Func = (*Daemon)(nil).Run

// Command vpn-guard is the VPN Guard daemon and its diagnostic CLI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/robotNIXX/guardvpn/internal/config"
	"github.com/robotNIXX/guardvpn/internal/daemon"
	"github.com/robotNIXX/guardvpn/internal/guard"
	"github.com/robotNIXX/guardvpn/internal/ipc"
	"github.com/robotNIXX/guardvpn/internal/logging"
	"github.com/robotNIXX/guardvpn/internal/network"
	"github.com/robotNIXX/guardvpn/internal/paths"
	"github.com/robotNIXX/guardvpn/internal/process"
	"github.com/robotNIXX/guardvpn/internal/service"
	"github.com/robotNIXX/guardvpn/internal/version"
)

const usage = `VPN Guard — terminates the controlled application unless the external IP
belongs to an allowed country.

Usage:
  vpn-guard run      [-config PATH] [-console]   run the daemon (launchd / Windows service)
  vpn-guard status   [-json]                     show daemon state
  vpn-guard check    [-local] [-config PATH]     force a network check
  vpn-guard reload                               re-read the configuration (administrators)
  vpn-guard validate [-config PATH]              validate the configuration
  vpn-guard version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var code int
	switch cmd {
	case "run":
		code = cmdRun(args)
	case "status":
		code = cmdStatus(args)
	case "check":
		code = cmdCheck(args)
	case "validate":
		code = cmdValidate(args)
	case "reload":
		code = cmdReload()
	case "version", "-v", "--version":
		fmt.Printf("vpn-guard %s (%s)\n", version.Version, version.Commit)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		code = 2
	}
	os.Exit(code)
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", paths.Get().Config, "configuration file")
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := configFlag(fs)
	console := fs.Bool("console", false, "log to stdout instead of log files")
	_ = fs.Parse(args)

	var log *logging.Logger
	var closeLogs func()
	if *console {
		log = logging.New(os.Stdout, nil, logging.LevelInfo)
		closeLogs = func() {}
	} else {
		var err error
		log, closeLogs, err = openDaemonLogs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "open logs: %v\n", err)
			// Keep running: an unwritable log must not leave the app unguarded.
			log = logging.New(os.Stderr, nil, logging.LevelInfo)
			closeLogs = func() {}
		}
	}
	defer closeLogs()

	d := daemon.New(*cfgPath, log)
	if err := service.Run(d.Run); err != nil {
		log.Error("service failed", "err", err)
		return 1
	}
	return 0
}

func cmdStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print raw JSON")
	_ = fs.Parse(args)

	st, err := ipc.Call("status", 5*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
		return 0
	}
	printStatus(os.Stdout, st)
	return 0
}

func printStatus(w io.Writer, st *ipc.Status) {
	fmt.Fprintf(w, "VPN Guard %s\n\n", st.Version)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-14s %s\n", k+":", v)
		}
	}
	row("State", st.State)
	if st.State != guard.StateAllowed.String() {
		row("Reason", st.Reason)
	}
	row("Config error", st.ConfigError)
	row("External IP", st.IPv4)
	row("External IPv6", st.IPv6)
	row("Country", st.Country)
	row("Provider", st.Provider)
	if !st.CheckedAt.IsZero() {
		row("Last check", st.CheckedAt.Local().Format("2006-01-02 15:04:05"))
	}
	row("Config", st.ConfigPath)

	if len(st.Apps) == 0 {
		fmt.Fprintln(w, "\nNo applications are controlled.")
		return
	}
	for _, a := range st.Apps {
		fmt.Fprintf(w, "\n[%s]\n", a.Name)
		row("  State", a.State)
		row("  Required", strings.Join(a.Allowed, ", "))
		row("  Error", a.Error)
		for _, f := range a.Identity {
			row("  "+f.Name, f.Value)
		}
		if !a.Disabled {
			pids := make([]string, len(a.PIDs))
			for i, p := range a.PIDs {
				pids[i] = strconv.Itoa(p)
			}
			if len(pids) == 0 {
				row("  PID", "not running")
			} else {
				row("  PID", strings.Join(pids, ", "))
			}
		}
	}
}

func cmdReload() int {
	st, err := ipc.Call(ipc.CmdReload, 20*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reload failed:", err)
		if st != nil && st.ConfigError != "" {
			fmt.Fprintln(os.Stderr, st.ConfigError)
		}
		return 1
	}
	fmt.Println("configuration reloaded")
	printStatus(os.Stdout, st)
	return 0
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	local := fs.Bool("local", false, "check in this process instead of asking the daemon")
	cfgPath := configFlag(fs)
	_ = fs.Parse(args)

	fmt.Println("Checking network...")
	fmt.Println()

	var st *ipc.Status
	if !*local {
		var err error
		st, err = ipc.Call("check", 20*time.Second)
		if err != nil {
			if !errors.Is(err, ipc.ErrNotRunning) {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			fmt.Fprintln(os.Stderr, "daemon not reachable, checking locally")
			*local = true
		}
	}
	if *local {
		cfg, err := config.Load(*cfgPath)
		if cfg == nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
		checker, err := network.NewCheckerFromConfig(cfg, logging.Stderr(logging.LevelWarn))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		r := checker.Check(ctx)
		st = &ipc.Status{State: r.State.String(), Reason: r.Reason, IPv4: r.IPv4, IPv6: r.IPv6,
			Country: r.Country, Provider: r.Provider}
	}

	row := func(k, v string) {
		if v != "" {
			fmt.Printf("%s: %s\n", k, v)
		}
	}
	row("External IP", st.IPv4)
	row("External IPv6", st.IPv6)
	row("Country", st.Country)
	row("Provider", st.Provider)
	fmt.Println()
	fmt.Printf("Result: %s\n", st.State)
	if st.State != guard.StateAllowed.String() {
		row("Reason", st.Reason)
		row("Config error", st.ConfigError)
	}
	for _, a := range st.Apps {
		if !a.Disabled {
			fmt.Printf("  %s: %s (required %s)\n", a.Name, a.State, strings.Join(a.Allowed, ", "))
		}
	}
	if st.State != guard.StateAllowed.String() {
		return 1
	}
	return 0
}

func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := configFlag(fs)
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		var ve *config.ValidationError
		if errors.As(err, &ve) {
			fmt.Fprintln(os.Stderr, "configuration is invalid:")
			for _, p := range ve.Problems {
				fmt.Fprintln(os.Stderr, "  -", p)
			}
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return 1
	}
	bad := false
	problems := cfg.AppProblems()
	for _, a := range cfg.Applications {
		switch {
		case a.Disabled:
			fmt.Printf("  %-20s disabled\n", a.Name)
			continue
		case a.Current() == nil:
			fmt.Printf("  %-20s not configured for this platform\n", a.Name)
			continue
		}
		err := problems[a.Name]
		if err == nil {
			_, err = process.NewIdentity(a.Current())
		}
		if err != nil {
			bad = true
			fmt.Printf("  %-20s ERROR: %v\n", a.Name, err)
		} else {
			fmt.Printf("  %-20s OK (allowed: %s)\n", a.Name, strings.Join(cfg.CountriesFor(a), ", "))
		}
	}
	if bad {
		fmt.Fprintln(os.Stderr, "some applications are misconfigured and will stay blocked")
		return 1
	}
	fmt.Printf("configuration OK: %s\n", *cfgPath)
	return 0
}

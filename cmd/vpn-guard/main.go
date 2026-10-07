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
	for _, f := range st.Application {
		row(f.Name, f.Value)
	}
	fmt.Fprintln(w)
	row("State", st.State)
	if st.State != guard.StateAllowed.String() {
		row("Reason", st.Reason)
	}
	row("Config error", st.ConfigError)
	row("External IP", st.IPv4)
	row("External IPv6", st.IPv6)
	row("Country", st.Country)
	row("Required", strings.Join(st.Required, ", "))
	row("Provider", st.Provider)
	if !st.CheckedAt.IsZero() {
		row("Last check", st.CheckedAt.Local().Format("2006-01-02 15:04:05"))
	}
	pids := make([]string, len(st.TargetPIDs))
	for i, p := range st.TargetPIDs {
		pids[i] = strconv.Itoa(p)
	}
	if len(pids) == 0 {
		row("Target PID", "not running")
	} else {
		row("Target PID", strings.Join(pids, ", "))
	}
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
			Country: r.Country, Provider: r.Provider, Required: cfg.AllowedCountries}
	}

	row := func(k, v string) {
		if v != "" {
			fmt.Printf("%s: %s\n", k, v)
		}
	}
	row("External IP", st.IPv4)
	row("External IPv6", st.IPv6)
	row("Country", st.Country)
	row("Required", strings.Join(st.Required, ", "))
	row("Provider", st.Provider)
	fmt.Println()
	fmt.Printf("Result: %s\n", st.State)
	if st.State != guard.StateAllowed.String() {
		row("Reason", st.Reason)
		row("Config error", st.ConfigError)
		return 1
	}
	return 0
}

func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := configFlag(fs)
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err == nil {
		_, err = process.NewIdentity(cfg.Application.App())
	}
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
	fmt.Printf("configuration OK: %s\n", *cfgPath)
	return 0
}

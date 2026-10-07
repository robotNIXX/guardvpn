package main

import (
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"runtime"
	"time"

	"github.com/robotNIXX/guardvpn/internal/ipc"
	"github.com/robotNIXX/guardvpn/internal/process"
	"github.com/robotNIXX/guardvpn/internal/version"
)

//go:embed ui
var uiFS embed.FS

// API serves the settings UI and a small JSON API that proxies the daemon.
// In the app it is the Wails asset handler (reachable only from the
// webview); with -serve it is a localhost HTTP server for development.
type API struct {
	// PickApp opens a native file dialog; nil when unavailable.
	PickApp func() (string, error)
	// Elevate restarts the agent with administrator rights (Windows).
	Elevate func() error
	// OpenLogs opens the daemon logs.
	OpenLogs func() error
	// Changed is called after an action that changes daemon state.
	Changed func()
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("GET /api/info", a.info)
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("POST /api/check", a.simple(ipc.CmdCheck, 20*time.Second))
	mux.HandleFunc("POST /api/reload", a.simple(ipc.CmdReload, 20*time.Second))
	mux.HandleFunc("GET /api/config", a.getConfig)
	mux.HandleFunc("POST /api/config", a.setConfig)
	mux.HandleFunc("POST /api/pick-app", a.pickApp)
	mux.HandleFunc("POST /api/inspect", a.inspect)
	mux.HandleFunc("GET /api/installed", a.installed)
	mux.HandleFunc("POST /api/elevate", a.elevate)
	mux.HandleFunc("POST /api/open-logs", a.openLogs)
	return noCache(mux)
}

func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Error    string   `json:"error"`
	Problems []string `json:"problems,omitempty"`
	// Daemon is false when the daemon could not be reached.
	Daemon bool `json:"daemon"`
}

func writeErr(w http.ResponseWriter, err error) {
	body := errorBody{Error: err.Error(), Daemon: !errors.Is(err, ipc.ErrNotRunning)}
	var re *ipc.RemoteError
	if errors.As(err, &re) {
		body.Problems = re.Problems
	}
	writeJSON(w, body)
}

func (a *API) info(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{
		"os":                runtime.GOOS,
		"version":           version.Version,
		"elevate_supported": a.Elevate != nil,
		"picker":            a.PickApp != nil,
	}
	if resp, err := ipc.Do(ipc.Request{Cmd: ipc.CmdWhoAmI}, 3*time.Second); err == nil && resp.Peer != nil {
		out["user"], out["admin"], out["daemon"] = resp.Peer.User, resp.Peer.Admin, true
	} else {
		out["admin"], out["daemon"] = false, !errors.Is(err, ipc.ErrNotRunning)
		if err != nil {
			out["error"] = err.Error()
		}
	}
	writeJSON(w, out)
}

func (a *API) status(w http.ResponseWriter, _ *http.Request) {
	st, err := ipc.Call(ipc.CmdStatus, 3*time.Second)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"status": st})
}

func (a *API) simple(cmd string, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		resp, err := ipc.Do(ipc.Request{Cmd: cmd}, timeout)
		if a.Changed != nil {
			a.Changed()
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"status": resp.Status})
	}
}

func (a *API) getConfig(w http.ResponseWriter, _ *http.Request) {
	resp, err := ipc.Do(ipc.Request{Cmd: ipc.CmdGetConfig}, 5*time.Second)
	if err != nil {
		body := map[string]any{"error": err.Error(), "daemon": !errors.Is(err, ipc.ErrNotRunning)}
		if resp != nil && len(resp.Config) > 0 {
			body["config"] = resp.Config // parsed but invalid: still editable
		}
		writeJSON(w, body)
		return
	}
	writeJSON(w, map[string]any{"config": resp.Config})
}

func (a *API) setConfig(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, err)
		return
	}
	resp, err := ipc.Do(ipc.Request{Cmd: ipc.CmdSetConfig, Config: raw}, 30*time.Second)
	if a.Changed != nil {
		a.Changed()
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"status": resp.Status})
}

func (a *API) pickApp(w http.ResponseWriter, _ *http.Request) {
	if a.PickApp == nil {
		writeJSON(w, errorBody{Error: "file dialog is not available"})
		return
	}
	path, err := a.PickApp()
	if err != nil {
		writeErr(w, err)
		return
	}
	if path == "" {
		writeJSON(w, map[string]any{"cancelled": true})
		return
	}
	a.inspectPath(w, path)
}

func (a *API) inspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, err)
		return
	}
	a.inspectPath(w, req.Path)
}

func (a *API) inspectPath(w http.ResponseWriter, path string) {
	info, err := process.Inspect(path)
	if err != nil {
		writeJSON(w, errorBody{Error: err.Error(), Daemon: true})
		return
	}
	writeJSON(w, map[string]any{"app": info})
}

func (a *API) installed(w http.ResponseWriter, _ *http.Request) {
	apps := process.InstalledApps()
	if apps == nil {
		apps = []process.AppInfo{}
	}
	writeJSON(w, map[string]any{"apps": apps})
}

func (a *API) elevate(w http.ResponseWriter, _ *http.Request) {
	if a.Elevate == nil {
		writeJSON(w, errorBody{Error: "not supported on this platform"})
		return
	}
	if err := a.Elevate(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *API) openLogs(w http.ResponseWriter, _ *http.Request) {
	if a.OpenLogs == nil {
		writeJSON(w, errorBody{Error: "not supported"})
		return
	}
	if err := a.OpenLogs(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

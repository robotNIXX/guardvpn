// Package ipc is the local channel between the daemon and its clients
// (CLI, tray agent): one JSON request line, one JSON response line.
// macOS uses a unix socket, Windows a named pipe; the daemon identifies the
// connecting user from the OS so that only administrators can change
// settings.
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/robotNIXX/guardvpn/internal/logging"
	"github.com/robotNIXX/guardvpn/internal/paths"
)

// Field is a labelled identity value.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AppStatus is the state of one controlled application.
type AppStatus struct {
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Disabled bool     `json:"disabled,omitempty"`
	Allowed  []string `json:"allowed"`
	PIDs     []int    `json:"pids,omitempty"`
	Error    string   `json:"error,omitempty"`
	Identity []Field  `json:"identity,omitempty"`
}

// Status is the daemon state. It never contains secrets.
type Status struct {
	Version     string      `json:"version"`
	StartedAt   time.Time   `json:"started_at"`
	State       string      `json:"state"`
	Reason      string      `json:"reason,omitempty"`
	IPv4        string      `json:"ipv4,omitempty"`
	IPv6        string      `json:"ipv6,omitempty"`
	Country     string      `json:"country,omitempty"`
	Provider    string      `json:"provider,omitempty"`
	CheckedAt   time.Time   `json:"checked_at,omitempty"`
	Apps        []AppStatus `json:"apps"`
	ConfigPath  string      `json:"config_path,omitempty"`
	ConfigError string      `json:"config_error,omitempty"`
	LoadedAt    time.Time   `json:"loaded_at,omitempty"`
}

// Peer identifies the connected client.
type Peer struct {
	User  string `json:"user"`
	Admin bool   `json:"admin"`
}

// ConfigProblemsError is returned by SetConfig for an invalid config.
type ConfigProblemsError struct{ Problems []string }

func (e *ConfigProblemsError) Error() string {
	return fmt.Sprintf("%d configuration problem(s)", len(e.Problems))
}

// Handler serves requests.
type Handler interface {
	Status() Status
	// Check forces a fresh network check.
	Check(ctx context.Context) Status
	// Reload re-reads the configuration file.
	Reload(ctx context.Context) (Status, error)
	// Config returns the current configuration file with secrets masked.
	Config() (json.RawMessage, error)
	// SetConfig validates, saves and applies a configuration.
	SetConfig(ctx context.Context, cfg json.RawMessage) (Status, error)
}

// Request is a client request.
type Request struct {
	Cmd    string          `json:"cmd"`
	Config json.RawMessage `json:"config,omitempty"`
}

// Response is the daemon's answer.
type Response struct {
	Status   *Status         `json:"status,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
	Peer     *Peer           `json:"peer,omitempty"`
	Problems []string        `json:"problems,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// Commands.
const (
	CmdStatus    = "status"
	CmdCheck     = "check"
	CmdWhoAmI    = "whoami"
	CmdGetConfig = "get_config"
	CmdSetConfig = "set_config"
	CmdReload    = "reload"
)

const maxRequest = 1 << 20

// Serve accepts connections until ctx is cancelled.
func Serve(ctx context.Context, h Handler, log *logging.Logger) error {
	d := paths.Get()
	ln, err := listen(d.IPCAddress)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	s := &server{h: h, log: log}
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				cleanup(d.IPCAddress)
				return nil
			}
			log.Warn("ipc accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.serve(ctx, c)
	}
}

type server struct {
	h   Handler
	log *logging.Logger

	mu        sync.Mutex // serialises forced checks and config writes
	lastCheck time.Time
}

func (s *server) serve(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	peer, perr := peerOf(c)

	var req Request
	if err := json.NewDecoder(io.LimitReader(c, maxRequest)).Decode(&req); err != nil {
		_ = json.NewEncoder(c).Encode(Response{Error: "bad request"})
		return
	}

	resp := s.handle(ctx, req, peer, perr)
	_ = json.NewEncoder(c).Encode(resp)
}

func (s *server) handle(ctx context.Context, req Request, peer Peer, perr error) Response {
	requireAdmin := func() *Response {
		if perr != nil {
			return &Response{Error: "cannot identify client: " + perr.Error()}
		}
		if !peer.Admin {
			return &Response{Error: "administrator rights are required"}
		}
		return nil
	}
	status := func(st Status) Response { return Response{Status: &st} }

	switch req.Cmd {
	case CmdStatus:
		return status(s.h.Status())
	case CmdWhoAmI:
		if perr != nil {
			return Response{Error: perr.Error()}
		}
		return Response{Peer: &peer}
	case CmdCheck:
		s.mu.Lock()
		defer s.mu.Unlock()
		if time.Since(s.lastCheck) < 3*time.Second { // rate limit
			return status(s.h.Status())
		}
		s.lastCheck = time.Now()
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		return status(s.h.Check(cctx))
	case CmdGetConfig:
		cfg, err := s.h.Config()
		if err != nil {
			return Response{Config: cfg, Error: err.Error()}
		}
		return Response{Config: cfg}
	case CmdReload:
		if r := requireAdmin(); r != nil {
			return *r
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.log.Info("reload requested", "user", peer.User)
		st, err := s.h.Reload(ctx)
		if err != nil {
			return Response{Status: &st, Error: err.Error()}
		}
		return status(st)
	case CmdSetConfig:
		if r := requireAdmin(); r != nil {
			return *r
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.log.Info("configuration update requested", "user", peer.User)
		st, err := s.h.SetConfig(ctx, req.Config)
		var pe *ConfigProblemsError
		if errors.As(err, &pe) {
			return Response{Error: "configuration is invalid", Problems: pe.Problems}
		}
		if err != nil {
			return Response{Error: err.Error()}
		}
		return status(st)
	}
	return Response{Error: fmt.Sprintf("unknown command %q", req.Cmd)}
}

// ErrNotRunning means the daemon could not be reached.
var ErrNotRunning = errors.New("vpn-guard daemon is not running or not reachable")

// Do sends a request to the daemon. A daemon-side error is returned as
// *RemoteError together with the response.
func Do(req Request, timeout time.Duration) (*Response, error) {
	c, err := dial(paths.Get().IPCAddress, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.Error != "" {
		return &resp, &RemoteError{Msg: resp.Error, Problems: resp.Problems}
	}
	return &resp, nil
}

// RemoteError is an error reported by the daemon.
type RemoteError struct {
	Msg      string
	Problems []string
}

func (e *RemoteError) Error() string { return e.Msg }

// Call sends a simple command and returns the status.
func Call(cmd string, timeout time.Duration) (*Status, error) {
	resp, err := Do(Request{Cmd: cmd}, timeout)
	if err != nil {
		return nil, err
	}
	if resp.Status == nil {
		return nil, errors.New("empty response")
	}
	return resp.Status, nil
}

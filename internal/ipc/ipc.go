// Package ipc is the local status channel between the daemon and the CLI:
// one JSON request line, one JSON response line. On macOS it is a unix
// socket, on Windows a loopback TCP port (see internal/paths).
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/robotNIXX/guardvpn/internal/logging"
	"github.com/robotNIXX/guardvpn/internal/paths"
)

// Field is a labelled identity value.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Status is the daemon state reported to the CLI. It never contains
// secrets (GeoIP tokens etc.).
type Status struct {
	Version     string    `json:"version"`
	StartedAt   time.Time `json:"started_at"`
	State       string    `json:"state"`
	Reason      string    `json:"reason,omitempty"`
	IPv4        string    `json:"ipv4,omitempty"`
	IPv6        string    `json:"ipv6,omitempty"`
	Country     string    `json:"country,omitempty"`
	Provider    string    `json:"provider,omitempty"`
	Required    []string  `json:"required,omitempty"`
	CheckedAt   time.Time `json:"checked_at,omitempty"`
	Application []Field   `json:"application,omitempty"`
	TargetPIDs  []int     `json:"target_pids,omitempty"`
	ConfigError string    `json:"config_error,omitempty"`
}

// Handler serves requests.
type Handler interface {
	Status() Status
	// Check forces a fresh network check and returns the resulting status.
	Check(ctx context.Context) Status
}

type request struct {
	Cmd string `json:"cmd"`
}

type response struct {
	Status *Status `json:"status,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// Serve accepts connections until ctx is cancelled.
func Serve(ctx context.Context, h Handler, log *logging.Logger) error {
	d := paths.Get()
	ln, err := listen(d.IPCNetwork, d.IPCAddress)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var lastCheck time.Time
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				cleanup(d.IPCNetwork, d.IPCAddress)
				return nil
			}
			log.Warn("ipc accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// Connections are served one at a time: requests are tiny, and
		// this naturally serialises forced checks.
		func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			var req request
			line, err := bufio.NewReader(c).ReadBytes('\n')
			if err != nil || json.Unmarshal(line, &req) != nil {
				_ = json.NewEncoder(c).Encode(response{Error: "bad request"})
				return
			}
			var resp response
			switch req.Cmd {
			case "status":
				st := h.Status()
				resp.Status = &st
			case "check":
				// Rate limit forced checks from unprivileged users.
				if time.Since(lastCheck) < 3*time.Second {
					st := h.Status()
					resp.Status = &st
					break
				}
				lastCheck = time.Now()
				cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
				st := h.Check(cctx)
				cancel()
				resp.Status = &st
			default:
				resp.Error = fmt.Sprintf("unknown command %q", req.Cmd)
			}
			_ = json.NewEncoder(c).Encode(resp)
		}()
	}
}

// ErrNotRunning means the daemon could not be reached.
var ErrNotRunning = errors.New("vpn-guard daemon is not running or not reachable")

// Call sends cmd to the daemon.
func Call(cmd string, timeout time.Duration) (*Status, error) {
	d := paths.Get()
	c, err := net.DialTimeout(d.IPCNetwork, d.IPCAddress, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(c).Encode(request{Cmd: cmd}); err != nil {
		return nil, err
	}
	var resp response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	if resp.Status == nil {
		return nil, errors.New("empty response")
	}
	return resp.Status, nil
}

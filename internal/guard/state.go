// Package guard holds the network state machine.
//
// Only StateAllowed permits the controlled application to run; every other
// state (INITIALIZING, CHECKING, BLOCKED, UNKNOWN) means "terminate it".
package guard

import (
	"context"
	"time"
)

// State is the guard's view of the network.
type State int

const (
	StateInitializing State = iota
	StateChecking
	StateAllowed
	StateBlocked
	StateUnknown
)

func (s State) String() string {
	switch s {
	case StateInitializing:
		return "INITIALIZING"
	case StateChecking:
		return "CHECKING"
	case StateAllowed:
		return "ALLOWED"
	case StateBlocked:
		return "BLOCKED"
	case StateUnknown:
		return "UNKNOWN"
	}
	return "INVALID"
}

// Permits reports whether the controlled application may run in this state.
func (s State) Permits() bool { return s == StateAllowed }

// NetworkState is the last known network verdict. It lives in memory only:
// after a daemon restart the guard always starts from INITIALIZING.
type NetworkState struct {
	State     State     `json:"-"`
	IPv4      string    `json:"ipv4,omitempty"`
	IPv6      string    `json:"ipv6,omitempty"`
	Country   string    `json:"country,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Result is the outcome of one network check. State must be one of
// StateAllowed, StateBlocked or StateUnknown.
type Result struct {
	State    State
	IPv4     string
	IPv6     string
	Country  string
	Provider string
	// Reason is a short human-readable explanation for BLOCKED/UNKNOWN.
	Reason string
}

// Checker performs one external IP / country verification.
// Implementations must honour ctx and never return StateAllowed on error.
type Checker interface {
	Check(ctx context.Context) Result
}

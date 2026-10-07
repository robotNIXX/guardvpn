package network

import (
	"errors"
	"syscall"
)

// Winsock error codes.
const (
	wsaeAddrNotAvail = 10049
	wsaeNetUnreach   = 10051
	wsaeHostUnreach  = 10065
)

func isNoRouteErrno(err error) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	switch en {
	case wsaeAddrNotAvail, wsaeNetUnreach, wsaeHostUnreach:
		return true
	}
	return false
}

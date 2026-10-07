package ipc

import (
	"net"
	"os"
)

func listen(network, addr string) (net.Listener, error) {
	_ = os.Remove(addr) // stale socket from a crashed instance
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	// Status is readable by every local user; it holds no secrets.
	if err := os.Chmod(addr, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func cleanup(_, addr string) { _ = os.Remove(addr) }

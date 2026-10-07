package ipc

import "net"

func listen(network, addr string) (net.Listener, error) { return net.Listen(network, addr) }

func cleanup(_, _ string) {}

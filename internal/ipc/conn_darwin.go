package ipc

import (
	"errors"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const adminGID = 80 // "admin" group on macOS

func listen(addr string) (net.Listener, error) {
	_ = os.Remove(addr) // stale socket from a crashed instance
	ln, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}
	// Any local user may connect (status is public); privileged commands
	// are authorised per connection from the peer credentials.
	if err := os.Chmod(addr, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func cleanup(addr string) { _ = os.Remove(addr) }

func dial(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", addr, timeout)
}

// peerOf reads the connecting process's credentials (LOCAL_PEERCRED).
// root and members of the admin group are administrators.
func peerOf(c net.Conn) (Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var xu *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		xu, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if cerr != nil {
		return Peer{}, cerr
	}
	n := min(int(xu.Ngroups), len(xu.Groups))
	groups := xu.Groups[:n]
	p := Peer{
		User:  strconv.Itoa(int(xu.Uid)),
		Admin: xu.Uid == 0 || slices.Contains(groups, adminGID),
	}
	if u, err := user.LookupId(p.User); err == nil {
		p.User = u.Username
	}
	if !p.Admin {
		// xucred carries at most 16 groups; fall back to the group database.
		if u, err := user.LookupId(strconv.Itoa(int(xu.Uid))); err == nil {
			if gids, err := u.GroupIds(); err == nil && slices.Contains(gids, strconv.Itoa(adminGID)) {
				p.Admin = true
			}
		}
	}
	return p, nil
}

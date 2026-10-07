package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Pipe ACL: full access for SYSTEM and Administrators, read/write for
// authenticated users (status is public; privileged commands are
// authorised per connection from the client's token).
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

func listen(addr string) (net.Listener, error) {
	return winio.ListenPipe(addr, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
}

func cleanup(string) {}

func dial(addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return winio.DialPipeContext(ctx, addr)
}

// peerOf identifies the client process behind the pipe. Administrators are
// LocalSystem and tokens with an *enabled* BUILTIN\Administrators group,
// i.e. elevated (UAC) sessions; a filtered admin token does not qualify.
func peerOf(c net.Conn) (Peer, error) {
	fc, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return Peer{}, errors.New("not a named pipe")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(fc.Fd()), &pid); err != nil {
		return Peer{}, fmt.Errorf("GetNamedPipeClientProcessId: %w", err)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Peer{}, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return Peer{}, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer tok.Close()

	var p Peer
	if tu, err := tok.GetTokenUser(); err == nil {
		if acc, dom, _, err := tu.User.Sid.LookupAccount(""); err == nil {
			p.User = dom + `\` + acc
		} else {
			p.User = tu.User.Sid.String()
		}
		if tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
			p.Admin = true
			return p, nil
		}
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return p, err
	}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return p, err
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.Equals(admins) && g.Attributes&windows.SE_GROUP_ENABLED != 0 {
			p.Admin = true
			break
		}
	}
	return p, nil
}

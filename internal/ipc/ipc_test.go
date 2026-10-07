package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/robotNIXX/guardvpn/internal/logging"
)

type fakeHandler struct{ setCalls, reloadCalls int }

func (f *fakeHandler) Status() Status                   { return Status{State: "ALLOWED"} }
func (f *fakeHandler) Check(context.Context) Status     { return f.Status() }
func (f *fakeHandler) Config() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
func (f *fakeHandler) Reload(context.Context) (Status, error) {
	f.reloadCalls++
	return f.Status(), nil
}
func (f *fakeHandler) SetConfig(context.Context, json.RawMessage) (Status, error) {
	f.setCalls++
	return f.Status(), nil
}

func TestPrivilegedCommandsRequireAdmin(t *testing.T) {
	h := &fakeHandler{}
	s := &server{h: h, log: logging.Discard()}
	ctx := context.Background()
	user := Peer{User: "bob"}
	admin := Peer{User: "root", Admin: true}

	for _, cmd := range []string{CmdSetConfig, CmdReload} {
		if r := s.handle(ctx, Request{Cmd: cmd, Config: json.RawMessage(`{}`)}, user, nil); r.Error == "" {
			t.Fatalf("%s allowed for a non-admin", cmd)
		}
		if r := s.handle(ctx, Request{Cmd: cmd}, admin, errors.New("no peer creds")); r.Error == "" {
			t.Fatalf("%s allowed for an unidentified client", cmd)
		}
	}
	if h.setCalls != 0 || h.reloadCalls != 0 {
		t.Fatal("handler reached without admin rights")
	}
	if r := s.handle(ctx, Request{Cmd: CmdSetConfig, Config: json.RawMessage(`{}`)}, admin, nil); r.Error != "" || h.setCalls != 1 {
		t.Fatalf("admin set_config failed: %+v", r)
	}
	for _, cmd := range []string{CmdStatus, CmdGetConfig, CmdWhoAmI, CmdCheck} {
		if r := s.handle(ctx, Request{Cmd: cmd}, user, nil); r.Error != "" {
			t.Fatalf("%s must be available to every user: %s", cmd, r.Error)
		}
	}
}

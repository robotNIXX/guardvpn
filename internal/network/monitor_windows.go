package network

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	notifyMu sync.Mutex
	notifyCh chan<- string
)

func poke(reason string) {
	notifyMu.Lock()
	ch := notifyCh
	notifyMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- reason:
	default:
	}
}

// Callbacks run on OS threads owned by iphlpapi; they only poke a channel.
var (
	routeCB = windows.NewCallback(func(ctx, row uintptr, typ uint32) uintptr {
		poke("route changed")
		return 0
	})
	addrCB = windows.NewCallback(func(ctx, row uintptr, typ uint32) uintptr {
		poke("address changed")
		return 0
	})
	ifaceCB = windows.NewCallback(func(ctx, row uintptr, typ uint32) uintptr {
		poke("interface changed")
		return 0
	})
)

// startEvents registers iphlpapi change notifications.
func startEvents(ctx context.Context, ch chan<- string) error {
	notifyMu.Lock()
	notifyCh = ch
	notifyMu.Unlock()

	var handles []windows.Handle
	reg := func(name string, f func(uint16, uintptr, unsafe.Pointer, bool, *windows.Handle) error, cb uintptr) error {
		var h windows.Handle
		if err := f(windows.AF_UNSPEC, cb, nil, false, &h); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		handles = append(handles, h)
		return nil
	}
	cancelAll := func() {
		for _, h := range handles {
			_ = windows.CancelMibChangeNotify2(h)
		}
	}
	if err := reg("NotifyRouteChange2", windows.NotifyRouteChange2, routeCB); err != nil {
		cancelAll()
		return err
	}
	if err := reg("NotifyUnicastIpAddressChange", windows.NotifyUnicastIpAddressChange, addrCB); err != nil {
		cancelAll()
		return err
	}
	if err := reg("NotifyIpInterfaceChange", windows.NotifyIpInterfaceChange, ifaceCB); err != nil {
		cancelAll()
		return err
	}
	go func() {
		<-ctx.Done()
		cancelAll()
		notifyMu.Lock()
		notifyCh = nil
		notifyMu.Unlock()
	}()
	return nil
}

// significantRoutes returns default and split-default (/0, /1) routes and
// static host routes (VPN server endpoint routes).
func significantRoutes() ([]string, error) {
	var tbl *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &tbl); err != nil {
		return nil, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(tbl))

	var out []string
	for _, r := range tbl.Rows() {
		if r.Loopback != 0 {
			continue
		}
		dst, ok := sockaddrAddr(&r.DestinationPrefix.Prefix)
		if !ok || dst.IsLinkLocalUnicast() || dst.IsMulticast() || dst.IsLoopback() {
			continue
		}
		plen := int(r.DestinationPrefix.PrefixLength)
		nh, _ := sockaddrAddr(&r.NextHop)
		gw := "-"
		if nh.IsValid() && !nh.IsUnspecified() {
			gw = nh.String()
		}
		switch {
		case plen <= 1:
			out = append(out, fmt.Sprintf("route %s/%d via %s if%d", dst, plen, gw, r.InterfaceIndex))
		case plen == dst.BitLen() && r.Protocol == windows.MIB_IPPROTO_NETMGMT && gw != "-":
			out = append(out, fmt.Sprintf("hostroute %s via %s if%d", dst, gw, r.InterfaceIndex))
		}
	}
	return out, nil
}

func sockaddrAddr(sa *windows.RawSockaddrInet) (netip.Addr, bool) {
	switch sa.Family {
	case windows.AF_INET:
		s4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrFrom4(s4.Addr), true
	case windows.AF_INET6:
		s6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
		return netip.AddrFrom16(s6.Addr), true
	}
	return netip.Addr{}, false
}

package network

import (
	"context"
	"fmt"
	"math/bits"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// startEvents reads the PF_ROUTE socket and pokes ch on every message that
// may describe an interface, address or route change.
func startEvents(ctx context.Context, ch chan<- string) error {
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("route socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		syscall.Close(fd)
	}()
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				return // socket closed
			}
			if n < 4 {
				continue
			}
			typ := int(buf[3]) // rt_msghdr: msglen u16, version u8, type u8
			switch typ {
			case syscall.RTM_GET, syscall.RTM_LOSING, syscall.RTM_MISS,
				syscall.RTM_RESOLVE, syscall.RTM_NEWMADDR, syscall.RTM_DELMADDR,
				syscall.RTM_GET2:
				continue
			}
			select {
			case ch <- rtmName(typ):
			default:
			}
		}
	}()
	return nil
}

func rtmName(t int) string {
	switch t {
	case syscall.RTM_ADD:
		return "route added"
	case syscall.RTM_DELETE:
		return "route deleted"
	case syscall.RTM_CHANGE:
		return "route changed"
	case syscall.RTM_NEWADDR:
		return "address added"
	case syscall.RTM_DELADDR:
		return "address removed"
	case syscall.RTM_IFINFO, syscall.RTM_IFINFO2:
		return "interface changed"
	}
	return fmt.Sprintf("routing message %d", t)
}

// significantRoutes returns default and split-default (/0, /1) routes and
// static host routes via a gateway (VPN server endpoint routes).
func significantRoutes() ([]string, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_UP == 0 {
			continue
		}
		if rm.Flags&(syscall.RTF_WASCLONED|syscall.RTF_LLINFO|syscall.RTF_BROADCAST|syscall.RTF_MULTICAST) != 0 {
			continue
		}
		dst, ok := addrOf(rm.Addrs, syscall.RTAX_DST)
		if !ok || dst.IsLinkLocalUnicast() || dst.IsMulticast() || dst.IsLoopback() {
			continue
		}
		host := rm.Flags&syscall.RTF_HOST != 0
		plen := dst.BitLen()
		if !host {
			plen = maskLen(rm.Addrs, dst.BitLen())
		}
		gw := gatewayOf(rm.Addrs)
		switch {
		case plen <= 1:
			out = append(out, fmt.Sprintf("route %s/%d via %s if%d", dst, plen, gw, rm.Index))
		case host && rm.Flags&syscall.RTF_STATIC != 0 && rm.Flags&syscall.RTF_GATEWAY != 0:
			out = append(out, fmt.Sprintf("hostroute %s via %s if%d", dst, gw, rm.Index))
		}
	}
	return out, nil
}

func addrOf(as []route.Addr, i int) (netip.Addr, bool) {
	if i >= len(as) || as[i] == nil {
		return netip.Addr{}, false
	}
	switch a := as[i].(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP), true
	}
	return netip.Addr{}, false
}

// maskLen returns the prefix length; a missing netmask on a non-host
// route means a default route (/0).
func maskLen(as []route.Addr, bitLen int) int {
	if syscall.RTAX_NETMASK >= len(as) || as[syscall.RTAX_NETMASK] == nil {
		return 0
	}
	n := 0
	switch a := as[syscall.RTAX_NETMASK].(type) {
	case *route.Inet4Addr:
		for _, b := range a.IP {
			n += bits.OnesCount8(b)
		}
	case *route.Inet6Addr:
		for _, b := range a.IP {
			n += bits.OnesCount8(b)
		}
	default:
		return bitLen
	}
	return n
}

func gatewayOf(as []route.Addr) string {
	if syscall.RTAX_GATEWAY >= len(as) || as[syscall.RTAX_GATEWAY] == nil {
		return "-"
	}
	switch a := as[syscall.RTAX_GATEWAY].(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP).String()
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP).String()
	case *route.LinkAddr:
		if a.Name != "" {
			return "link:" + a.Name
		}
		return fmt.Sprintf("link#%d", a.Index)
	}
	return "?"
}

package network

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/robotNIXX/guardvpn/internal/logging"
)

// Invalidator receives "the network may have changed" notifications.
type Invalidator interface {
	Invalidate(reason string)
}

// Monitor watches for network changes and sleep/wake.
//
// OS notifications (routing socket on macOS, iphlpapi on Windows) and a
// 1-second poll both trigger a recomputation of a network fingerprint:
// default/VPN routes, VPN endpoint host routes and interface addresses.
// Only a fingerprint change invalidates the guard, so noise such as ARP
// updates or IPv6 privacy-address rotation does not kill the application.
type Monitor struct {
	inv  Invalidator
	log  *logging.Logger
	poll time.Duration
	// wakeGap: a pause of the 1 s ticker longer than this means the
	// machine was asleep (fallback for missed power notifications).
	wakeGap time.Duration

	fingerprint func() []string
}

// NewMonitor creates a monitor that reports to inv.
func NewMonitor(inv Invalidator, log *logging.Logger) *Monitor {
	return &Monitor{
		inv:         inv,
		log:         log,
		poll:        time.Second,
		wakeGap:     5 * time.Second,
		fingerprint: Fingerprint,
	}
}

// Run blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	events := make(chan string, 1)
	if err := startEvents(ctx, events); err != nil {
		m.log.Error("network event source unavailable, falling back to polling", "err", err)
	}

	fp := m.fingerprint()
	m.log.Debug("network fingerprint", "entries", strings.Join(fp, " | "))

	t := time.NewTicker(m.poll)
	defer t.Stop()
	last := time.Now()

	for {
		reason := ""
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			reason = ev
		case now := <-t.C:
			// Wall clock (Round(0) strips the monotonic reading) and the
			// monotonic clock: on some platforms the latter stops during
			// sleep, on others it does not; a gap in either means wake.
			wall := now.Round(0).Sub(last.Round(0))
			mono := now.Sub(last)
			last = now
			if wall > m.wakeGap || mono > m.wakeGap {
				m.inv.Invalidate(fmt.Sprintf("wake detected (clock gap %s)", max(wall, mono).Round(time.Second)))
				fp = m.fingerprint()
				continue
			}
			reason = "poll"
		}

		next := m.fingerprint()
		if slices.Equal(fp, next) {
			continue
		}
		m.inv.Invalidate(reason + ": " + diff(fp, next))
		fp = next
	}
}

// diff summarises added (+) and removed (-) fingerprint entries.
func diff(old, cur []string) string {
	var parts []string
	for _, s := range old {
		if !slices.Contains(cur, s) {
			parts = append(parts, "-"+s)
		}
	}
	for _, s := range cur {
		if !slices.Contains(old, s) {
			parts = append(parts, "+"+s)
		}
	}
	if len(parts) > 6 {
		parts = append(parts[:6], fmt.Sprintf("(+%d more)", len(parts)-6))
	}
	return strings.Join(parts, " ")
}

// Fingerprint returns a sorted description of the routing-relevant state.
func Fingerprint() []string {
	var out []string
	routes, err := significantRoutes()
	if err != nil {
		out = append(out, "routes-error:"+err.Error())
	}
	out = append(out, routes...)
	out = append(out, interfaceEntries()...)
	slices.Sort(out)
	return slices.Compact(out)
}

// interfaceEntries lists up interfaces with their IPv4 addresses and
// whether they have a global IPv6 address. Exact IPv6 addresses are left
// out on purpose: temporary (privacy) addresses rotate without any change
// of the route.
func interfaceEntries() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return []string{"interfaces-error:" + err.Error()}
	}
	var out []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		v6 := false
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil {
				if ip4.IsLinkLocalUnicast() {
					continue
				}
				out = append(out, fmt.Sprintf("addr %s %s", ifc.Name, ipn.String()))
			} else if isGlobalV6(ipn.IP) {
				v6 = true
			}
		}
		if v6 {
			out = append(out, fmt.Sprintf("addr6 %s global", ifc.Name))
		}
	}
	return out
}

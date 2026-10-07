package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/robotNIXX/guardvpn/internal/config"
	"github.com/robotNIXX/guardvpn/internal/guard"
	"github.com/robotNIXX/guardvpn/internal/logging"
)

// CheckerOptions configures a Checker.
type CheckerOptions struct {
	Providers []Provider
	Policy    string // config.PolicyFirstSuccess | config.PolicyAllAgree
	IPv6Mode  string // config.IPv6Auto | IPv6Required | IPv6Disabled
	Allowed   []string
	Timeout   time.Duration // per HTTP request
	Log       *logging.Logger

	// RootCAs overrides system roots (tests only).
	RootCAs *x509.CertPool
	// HasGlobalIPv6 overrides interface detection (tests only).
	HasGlobalIPv6 func() bool
}

// Checker verifies that the external IP belongs to an allowed country.
// It implements guard.Checker.
type Checker struct {
	opts    CheckerOptions
	allowed map[string]bool
	clients map[Family]*http.Client
	log     *logging.Logger

	mu      sync.Mutex
	lastErr map[string]string // provider/family -> last logged error
}

// NewCheckerFromConfig builds a Checker from the daemon config.
func NewCheckerFromConfig(cfg *config.Config, log *logging.Logger) (*Checker, error) {
	var ps []Provider
	for _, pc := range cfg.GeoIP.Providers {
		p, err := NewProvider(pc)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	return NewChecker(CheckerOptions{
		Providers: ps,
		Policy:    cfg.GeoIP.Policy,
		IPv6Mode:  cfg.GeoIP.IPv6,
		Allowed:   cfg.AllowedCountries,
		Timeout:   cfg.NetworkTimeout(),
		Log:       log,
	}), nil
}

// NewChecker creates a Checker.
func NewChecker(opts CheckerOptions) *Checker {
	if opts.Log == nil {
		opts.Log = logging.Discard()
	}
	if opts.HasGlobalIPv6 == nil {
		opts.HasGlobalIPv6 = HasGlobalIPv6
	}
	c := &Checker{
		opts:    opts,
		allowed: map[string]bool{},
		log:     opts.Log,
		lastErr: map[string]string{},
		clients: map[Family]*http.Client{
			IPv4: newClient("tcp4", opts),
			IPv6: newClient("tcp6", opts),
		},
	}
	for _, cc := range opts.Allowed {
		c.allowed[strings.ToUpper(cc)] = true
	}
	return c
}

// newClient returns a client pinned to one address family. Keep-alives are
// disabled so that every check opens a fresh connection over the *current*
// route, and proxies are ignored: the daemon measures the machine's own
// egress, not a proxy's.
func newClient(network string, opts CheckerOptions) *http.Client {
	d := &net.Dialer{Timeout: opts.Timeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs},
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type famResult struct {
	fam      Family
	answer   Answer
	provider string
	err      error
	// noRoute is true when every provider failed because the family is
	// not routable at all (ENETUNREACH etc.), as opposed to a timeout or a
	// bad answer.
	noRoute bool
}

// Check implements guard.Checker.
func (c *Checker) Check(ctx context.Context) guard.Result {
	fams := []Family{IPv4}
	switch c.opts.IPv6Mode {
	case config.IPv6Required:
		fams = append(fams, IPv6)
	case config.IPv6Auto:
		if c.opts.HasGlobalIPv6() {
			fams = append(fams, IPv6)
		}
	}

	results := make([]famResult, len(fams))
	var wg sync.WaitGroup
	for i, f := range fams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c.checkFamily(ctx, f)
		}()
	}
	wg.Wait()
	return c.combine(results)
}

func (c *Checker) combine(results []famResult) guard.Result {
	var out guard.Result
	var countries, blocked, unknown []string
	for _, r := range results {
		if r.err != nil {
			if r.fam == IPv6 && r.noRoute && c.opts.IPv6Mode == config.IPv6Auto {
				// Global IPv6 address present but no IPv6 route at all
				// (typical when a VPN blocks IPv6): nothing can leak via v6.
				c.log.Debug("ipv6 not routable, skipping", "err", r.err)
				continue
			}
			unknown = append(unknown, fmt.Sprintf("%s: %v", r.fam, r.err))
			continue
		}
		ip := r.answer.IP.String()
		if r.fam == IPv4 {
			out.IPv4 = ip
		} else {
			out.IPv6 = ip
		}
		if out.Provider == "" {
			out.Provider = r.provider
		}
		if !slices.Contains(countries, r.answer.Country) {
			countries = append(countries, r.answer.Country)
		}
		if !c.allowed[r.answer.Country] {
			blocked = append(blocked, fmt.Sprintf("%s country %s not allowed", r.fam, r.answer.Country))
		}
	}
	out.Country = strings.Join(countries, "/")

	switch {
	case len(blocked) > 0:
		out.State = guard.StateBlocked
		out.Reason = strings.Join(append(blocked, unknown...), "; ")
	case len(unknown) > 0:
		out.State = guard.StateUnknown
		out.Reason = strings.Join(unknown, "; ")
	case out.IPv4 == "" && out.IPv6 == "":
		out.State = guard.StateUnknown
		out.Reason = "no address family could be verified"
	default:
		out.State = guard.StateAllowed
	}
	return out
}

func (c *Checker) checkFamily(ctx context.Context, fam Family) famResult {
	if len(c.opts.Providers) == 0 {
		return famResult{fam: fam, err: errors.New("no geoip providers configured")}
	}
	if c.opts.Policy == config.PolicyAllAgree {
		return c.allAgree(ctx, fam)
	}
	return c.firstSuccess(ctx, fam)
}

func (c *Checker) lookup(ctx context.Context, p Provider, fam Family) (Answer, error) {
	rctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	a, err := p.Lookup(rctx, c.clients[fam], fam)
	c.noteError(p.Name(), fam, err)
	return a, err
}

func (c *Checker) firstSuccess(ctx context.Context, fam Family) famResult {
	var errs []string
	noRoute := true
	for _, p := range c.opts.Providers {
		a, err := c.lookup(ctx, p, fam)
		if err == nil {
			return famResult{fam: fam, answer: a, provider: p.Name()}
		}
		noRoute = noRoute && isNoRoute(err)
		errs = append(errs, fmt.Sprintf("%s: %s", p.Name(), describe(err)))
		if ctx.Err() != nil {
			break
		}
	}
	return famResult{fam: fam, err: errors.New(strings.Join(errs, ", ")), noRoute: noRoute}
}

func (c *Checker) allAgree(ctx context.Context, fam Family) famResult {
	type res struct {
		a   Answer
		err error
	}
	rs := make([]res, len(c.opts.Providers))
	var wg sync.WaitGroup
	for i, p := range c.opts.Providers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := c.lookup(ctx, p, fam)
			rs[i] = res{a, err}
		}()
	}
	wg.Wait()

	var errs []string
	noRoute := true
	for i, r := range rs {
		if r.err != nil {
			noRoute = noRoute && isNoRoute(r.err)
			errs = append(errs, fmt.Sprintf("%s: %s", c.opts.Providers[i].Name(), describe(r.err)))
		}
	}
	if len(errs) > 0 {
		return famResult{fam: fam, err: errors.New(strings.Join(errs, ", ")), noRoute: noRoute}
	}
	first := rs[0].a
	for i, r := range rs[1:] {
		if r.a.Country != first.Country || r.a.IP != first.IP {
			return famResult{fam: fam, err: fmt.Errorf("providers disagree: %s=%s/%s, %s=%s/%s",
				c.opts.Providers[0].Name(), first.IP, first.Country,
				c.opts.Providers[i+1].Name(), r.a.IP, r.a.Country)}
		}
	}
	return famResult{fam: fam, answer: first, provider: c.opts.Providers[0].Name()}
}

// noteError logs GeoIP errors, suppressing repeats of the same error.
func (c *Checker) noteError(provider string, fam Family, err error) {
	key := provider + "/" + fam.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		if _, had := c.lastErr[key]; had {
			delete(c.lastErr, key)
			c.log.Info("geoip provider recovered", "provider", provider, "family", fam)
		}
		return
	}
	msg := describe(err)
	if c.lastErr[key] == msg {
		c.log.Debug("geoip error", "provider", provider, "family", fam, "err", msg)
		return
	}
	c.lastErr[key] = msg
	if isTimeout(err) {
		c.log.Warn("geoip timeout", "provider", provider, "family", fam, "err", msg)
	} else {
		c.log.Warn("geoip error", "provider", provider, "family", fam, "err", msg)
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func describe(err error) string {
	switch {
	case isTimeout(err):
		return "timeout"
	case isDNSError(err):
		return "dns error: " + err.Error()
	}
	return err.Error()
}

func isDNSError(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de)
}

// isNoRoute reports whether err means "this address family has no route".
func isNoRoute(err error) bool {
	if err == nil || isDNSError(err) || isTimeout(err) {
		return false
	}
	return isNoRouteErrno(err)
}

// HasGlobalIPv6 reports whether any up, non-loopback interface has a
// global unicast IPv6 address (link-local and ULA are ignored).
func HasGlobalIPv6() bool {
	ifs, err := net.Interfaces()
	if err != nil {
		return true // can't tell: be conservative and check IPv6 too
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() != nil {
				continue
			}
			if isGlobalV6(ipn.IP) {
				return true
			}
		}
	}
	return false
}

func isGlobalV6(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}
	return ip[0]&0xfe != 0xfc // exclude ULA fc00::/7
}

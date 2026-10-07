package network

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robotNIXX/guardvpn/internal/config"
	"github.com/robotNIXX/guardvpn/internal/guard"
)

type server struct {
	*httptest.Server
	hits atomic.Int32
}

func newServer(t *testing.T, h http.HandlerFunc) *server {
	s := &server{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func ipinfoJSON(ip, cc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"ip":%q,"asn":"AS1","country_code":%q,"country":"X"}`, ip, cc)
	}
}

func trace(ip, loc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "fl=1\nh=1.1.1.1\nip=%s\nts=1\nloc=%s\ntls=TLSv1.3\n", ip, loc)
	}
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }
}

func checker(t *testing.T, policy string, servers []*server, types []string) *Checker {
	t.Helper()
	var ps []Provider
	for i, s := range servers {
		p, err := NewProvider(config.Provider{Type: types[i], Token: "tok", URL: s.URL, URLv6: s.URL})
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	pool := servers[0].Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return NewChecker(CheckerOptions{
		Providers:     ps,
		Policy:        policy,
		IPv6Mode:      config.IPv6Disabled,
		Allowed:       []string{"TH", "SG"},
		Timeout:       300 * time.Millisecond,
		RootCAs:       pool,
		HasGlobalIPv6: func() bool { return false },
	})
}

func check(c *Checker) guard.Result { return c.Check(context.Background()) }

func TestIPInfoAllowed(t *testing.T) {
	s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer token")
		}
		if strings.Contains(r.URL.RawQuery, "tok") {
			t.Errorf("token must not be sent in the URL")
		}
		ipinfoJSON("203.0.113.15", "TH")(w, r)
	})
	r := check(checker(t, config.PolicyFirstSuccess, []*server{s}, []string{config.ProviderIPInfoLite}))
	if r.State != guard.StateAllowed || r.Country != "TH" || r.IPv4 != "203.0.113.15" {
		t.Fatalf("got %+v", r)
	}
}

func TestCountryRejected(t *testing.T) {
	s := newServer(t, ipinfoJSON("198.51.100.27", "DE"))
	r := check(checker(t, config.PolicyFirstSuccess, []*server{s}, []string{config.ProviderIPInfoLite}))
	if r.State != guard.StateBlocked || r.Country != "DE" {
		t.Fatalf("got %+v", r)
	}
}

func TestFailuresAreUnknown(t *testing.T) {
	slow := func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) }
	cases := map[string]http.HandlerFunc{
		"http 500":      status(500),
		"http 429":      status(429),
		"invalid json":  func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "{nope") },
		"unknown cc":    ipinfoJSON("203.0.113.15", "XX"),
		"empty cc":      ipinfoJSON("203.0.113.15", ""),
		"bad ip":        ipinfoJSON("not-an-ip", "TH"),
		"wrong family":  ipinfoJSON("2001:db8::1", "TH"),
		"timeout":       slow,
		"redirect":      func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://example.com", 302) },
		"huge response": func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("a", 64<<10)) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, h)
			r := check(checker(t, config.PolicyFirstSuccess, []*server{s}, []string{config.ProviderIPInfoLite}))
			if r.State != guard.StateUnknown {
				t.Fatalf("got %+v, want UNKNOWN", r)
			}
		})
	}
}

func TestTLSErrorIsUnknown(t *testing.T) {
	s := newServer(t, ipinfoJSON("203.0.113.15", "TH"))
	p, _ := NewProvider(config.Provider{Type: config.ProviderIPInfoLite, Token: "t", URL: s.URL})
	c := NewChecker(CheckerOptions{ // no RootCAs: self-signed cert must be rejected
		Providers: []Provider{p}, Policy: config.PolicyFirstSuccess, IPv6Mode: config.IPv6Disabled,
		Allowed: []string{"TH"}, Timeout: time.Second,
	})
	if r := check(c); r.State != guard.StateUnknown {
		t.Fatalf("got %+v", r)
	}
}

func TestFirstSuccessFallsBack(t *testing.T) {
	bad := newServer(t, status(503))
	good := newServer(t, trace("203.0.113.15", "TH"))
	c := checker(t, config.PolicyFirstSuccess, []*server{bad, good},
		[]string{config.ProviderIPInfoLite, config.ProviderCloudflareTrace})
	r := check(c)
	if r.State != guard.StateAllowed || r.Provider != config.ProviderCloudflareTrace {
		t.Fatalf("got %+v", r)
	}
}

func TestFirstSuccessStopsAtFirst(t *testing.T) {
	a := newServer(t, ipinfoJSON("203.0.113.15", "TH"))
	b := newServer(t, trace("203.0.113.15", "TH"))
	check(checker(t, config.PolicyFirstSuccess, []*server{a, b},
		[]string{config.ProviderIPInfoLite, config.ProviderCloudflareTrace}))
	if b.hits.Load() != 0 {
		t.Fatal("fallback provider must not be queried when the primary succeeds")
	}
}

func TestAllAgree(t *testing.T) {
	a := newServer(t, ipinfoJSON("203.0.113.15", "TH"))
	b := newServer(t, trace("203.0.113.15", "TH"))
	types := []string{config.ProviderIPInfoLite, config.ProviderCloudflareTrace}
	if r := check(checker(t, config.PolicyAllAgree, []*server{a, b}, types)); r.State != guard.StateAllowed {
		t.Fatalf("agreeing providers: %+v", r)
	}
	c := newServer(t, trace("203.0.113.15", "SG"))
	if r := check(checker(t, config.PolicyAllAgree, []*server{a, c}, types)); r.State != guard.StateUnknown {
		t.Fatalf("disagreeing providers: %+v", r)
	}
	d := newServer(t, status(500))
	if r := check(checker(t, config.PolicyAllAgree, []*server{a, d}, types)); r.State != guard.StateUnknown {
		t.Fatalf("one failing provider: %+v", r)
	}
}

func TestIPv6MustAlsoPass(t *testing.T) {
	// The test server only listens on IPv4 loopback in most CI setups, so
	// exercise combine() directly.
	c := NewChecker(CheckerOptions{Allowed: []string{"TH"}, IPv6Mode: config.IPv6Auto})
	v4ok := famResult{fam: IPv4, answer: mustAnswer("203.0.113.15", "TH"), provider: "p"}
	cases := []struct {
		name string
		v6   famResult
		want guard.State
	}{
		{"v6 allowed", famResult{fam: IPv6, answer: mustAnswer("2001:db8::1", "TH")}, guard.StateAllowed},
		{"v6 leaks to DE", famResult{fam: IPv6, answer: mustAnswer("2001:db8::1", "DE")}, guard.StateBlocked},
		{"v6 error", famResult{fam: IPv6, err: fmt.Errorf("timeout")}, guard.StateUnknown},
		{"v6 not routable", famResult{fam: IPv6, err: fmt.Errorf("unreachable"), noRoute: true}, guard.StateAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r := c.combine([]famResult{v4ok, tc.v6}); r.State != tc.want {
				t.Fatalf("got %v (%s), want %v", r.State, r.Reason, tc.want)
			}
		})
	}

	c.opts.IPv6Mode = config.IPv6Required
	if r := c.combine([]famResult{v4ok, {fam: IPv6, err: fmt.Errorf("x"), noRoute: true}}); r.State != guard.StateUnknown {
		t.Fatalf("required IPv6 without route must be UNKNOWN, got %v", r.State)
	}
}

func TestIPv4FailureIsUnknown(t *testing.T) {
	c := NewChecker(CheckerOptions{Allowed: []string{"TH"}, IPv6Mode: config.IPv6Auto})
	r := c.combine([]famResult{{fam: IPv4, err: fmt.Errorf("unreachable"), noRoute: true}})
	if r.State != guard.StateUnknown {
		t.Fatalf("got %v", r.State)
	}
}

func mustAnswer(ip, cc string) Answer {
	fam := IPv4
	if strings.Contains(ip, ":") {
		fam = IPv6
	}
	a, err := validate(ip, cc, fam)
	if err != nil {
		panic(err)
	}
	return a
}

func TestCloudflareParse(t *testing.T) {
	s := newServer(t, trace("203.0.113.15", "sg"))
	r := check(checker(t, config.PolicyFirstSuccess, []*server{s}, []string{config.ProviderCloudflareTrace}))
	if r.State != guard.StateAllowed || r.Country != "SG" {
		t.Fatalf("got %+v", r)
	}
	bad := newServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ip=1.2.3.4\n") })
	if r := check(checker(t, config.PolicyFirstSuccess, []*server{bad}, []string{config.ProviderCloudflareTrace})); r.State != guard.StateUnknown {
		t.Fatalf("missing loc: %+v", r)
	}
}

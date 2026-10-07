// Package network determines the external IP/country and watches for
// network changes.
package network

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/robotNIXX/guardvpn/internal/config"
)

// Family is an IP address family used for a lookup.
type Family int

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

func (f Family) String() string {
	if f == IPv6 {
		return "ipv6"
	}
	return "ipv4"
}

// Answer is a GeoIP lookup result.
type Answer struct {
	IP      netip.Addr
	Country string
}

// Provider looks up the caller's external IP and its country.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, c *http.Client, fam Family) (Answer, error)
}

const maxBody = 16 << 10

// Built-in endpoints.
const (
	ipinfoLiteURL     = "https://api.ipinfo.io/lite/me"
	ipinfoLiteURLv6   = "https://v6.api.ipinfo.io/lite/me"
	cloudflareTraceV4 = "https://1.1.1.1/cdn-cgi/trace"
	cloudflareTraceV6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
)

// NewProvider builds a provider from config.
func NewProvider(p config.Provider) (Provider, error) {
	pick := func(override, def string) string {
		if override != "" {
			return override
		}
		return def
	}
	switch p.Type {
	case config.ProviderIPInfoLite:
		return &ipinfoLite{
			token: p.Token,
			v4:    pick(p.URL, ipinfoLiteURL),
			v6:    pick(p.URLv6, ipinfoLiteURLv6),
		}, nil
	case config.ProviderCloudflareTrace:
		return &cloudflareTrace{
			v4: pick(p.URL, cloudflareTraceV4),
			v6: pick(p.URLv6, cloudflareTraceV6),
		}, nil
	}
	return nil, fmt.Errorf("unknown geoip provider %q", p.Type)
}

// HTTPStatusError is returned for non-200 responses (429, 5xx, ...).
type HTTPStatusError struct{ Code int }

func (e *HTTPStatusError) Error() string { return fmt.Sprintf("http status %d", e.Code) }

func fetch(ctx context.Context, c *http.Client, url string, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("User-Agent", "vpn-guard")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{Code: resp.StatusCode}
	}
	if len(body) > maxBody {
		return nil, errors.New("response too large")
	}
	return body, nil
}

var countryRe = regexp.MustCompile(`^[A-Z]{2}$`)

// Codes that GeoIP databases use for "unknown"/non-country regions.
var pseudoCountries = map[string]bool{"XX": true, "ZZ": true, "EU": true, "AP": true, "T1": true, "A1": true, "A2": true, "O1": true}

func validate(ipStr, country string, fam Family) (Answer, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return Answer{}, fmt.Errorf("invalid ip %q", ipStr)
	}
	ip = ip.Unmap()
	if (fam == IPv4) != ip.Is4() {
		return Answer{}, fmt.Errorf("got %s address %s for %s lookup", familyOf(ip), ip, fam)
	}
	cc := strings.ToUpper(strings.TrimSpace(country))
	if !countryRe.MatchString(cc) || pseudoCountries[cc] {
		return Answer{}, fmt.Errorf("unknown country %q", country)
	}
	return Answer{IP: ip, Country: cc}, nil
}

func familyOf(ip netip.Addr) Family {
	if ip.Is4() {
		return IPv4
	}
	return IPv6
}

// ipinfoLite implements https://ipinfo.io/developers/lite-api.
type ipinfoLite struct{ token, v4, v6 string }

func (p *ipinfoLite) Name() string { return config.ProviderIPInfoLite }

func (p *ipinfoLite) Lookup(ctx context.Context, c *http.Client, fam Family) (Answer, error) {
	url := p.v4
	if fam == IPv6 {
		url = p.v6
	}
	// The token goes into a header, not the URL, so it never shows up in
	// error messages or logs.
	body, err := fetch(ctx, c, url, map[string]string{"Authorization": "Bearer " + p.token})
	if err != nil {
		return Answer{}, err
	}
	var r struct {
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return Answer{}, fmt.Errorf("invalid json: %w", err)
	}
	return validate(r.IP, r.CountryCode, fam)
}

// cloudflareTrace parses https://1.1.1.1/cdn-cgi/trace (key=value lines).
type cloudflareTrace struct{ v4, v6 string }

func (p *cloudflareTrace) Name() string { return config.ProviderCloudflareTrace }

func (p *cloudflareTrace) Lookup(ctx context.Context, c *http.Client, fam Family) (Answer, error) {
	url := p.v4
	if fam == IPv6 {
		url = p.v6
	}
	body, err := fetch(ctx, c, url, nil)
	if err != nil {
		return Answer{}, err
	}
	var ip, loc string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			ip = v
		case "loc":
			loc = v
		}
	}
	if ip == "" || loc == "" {
		return Answer{}, errors.New("invalid trace response: missing ip or loc")
	}
	return validate(ip, loc, fam)
}

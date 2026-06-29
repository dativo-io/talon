package sovereignty

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// ErrEgressBlocked is returned when an outbound request targets a host outside
// the air-gap allowlist.
var ErrEgressBlocked = errors.New("egress blocked by air-gap guard")

// EgressGuard is an http.RoundTripper that denies outbound requests to hosts
// outside the configured allowlist. Used in air_gap deployment mode to catch
// surprise egress at the transport layer (defense in depth with policy egress).
type EgressGuard struct {
	base       http.RoundTripper
	allowed    map[string]struct{}
	violations atomic.Int64
}

// NewEgressGuard creates a guard wrapping the given base transport (or
// http.DefaultTransport when base is nil).
func NewEgressGuard(allowedHosts []string, base ...http.RoundTripper) *EgressGuard {
	allowed := make(map[string]struct{})
	for _, h := range allowedHosts {
		if host, err := hostFromAllowEntry(h); err == nil && host != "" {
			allowed[host] = struct{}{}
		}
	}
	// Always permit loopback.
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		allowed[h] = struct{}{}
	}
	var rt http.RoundTripper
	if len(base) > 0 && base[0] != nil {
		rt = base[0]
	} else {
		rt = http.DefaultTransport
		if rt == nil {
			rt = &http.Transport{}
		}
	}
	return &EgressGuard{base: rt, allowed: allowed}
}

func hostFromAllowEntry(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		return normalizeHost(u.Hostname()), nil
	}
	return normalizeHost(raw), nil
}

// RoundTrip implements http.RoundTripper.
func (g *EgressGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("egress guard: nil request")
	}
	host := normalizeHost(req.URL.Hostname())
	if host == "" {
		g.violations.Add(1)
		return nil, fmt.Errorf("%w: empty host", ErrEgressBlocked)
	}
	if _, ok := g.allowed[host]; !ok {
		g.violations.Add(1)
		return nil, fmt.Errorf("%w: host %q not in allowlist", ErrEgressBlocked, host)
	}
	return g.base.RoundTrip(req)
}

// SetBase replaces the underlying transport. Used by HTTPClientForGateway to
// inject the timeout-aware transport after guard construction.
func (g *EgressGuard) SetBase(rt http.RoundTripper) {
	if rt != nil {
		g.base = rt
	}
}

// Violations returns the number of blocked egress attempts since creation.
func (g *EgressGuard) Violations() int64 {
	return g.violations.Load()
}

// AllowlistSize returns the number of hosts permitted by the guard, including
// the always-allowed loopback addresses.
func (g *EgressGuard) AllowlistSize() int {
	return len(g.allowed)
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	// Strip brackets from IPv6 literals for map lookup.
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

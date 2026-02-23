package gateway

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
)

var (
	ErrCallerNotFound   = errors.New("caller not found")
	ErrCallerIDRequired = errors.New("caller identification required")
)

// ResolveCaller identifies the caller from the request using API key or source IP.
// Uses timing-safe comparison for API key lookup. Returns the CallerConfig or an error.
func (c *GatewayConfig) ResolveCaller(r *http.Request) (*CallerConfig, error) {
	apiKey := extractAPIKey(r)
	if apiKey != "" {
		if caller := c.resolveCallerByAPIKey(r, apiKey); caller != nil {
			return caller, nil
		}
		if c.DefaultPolicy.CallerIDRequired() {
			return nil, ErrCallerNotFound
		}
	}

	if clientIP := c.clientIPFromRequest(r); clientIP != nil {
		if caller := c.resolveCallerBySourceIP(clientIP); caller != nil {
			return caller, nil
		}
	}

	if c.DefaultPolicy.CallerIDRequired() {
		return nil, ErrCallerIDRequired
	}
	return &CallerConfig{Name: "anonymous", TenantID: "default"}, nil
}

// resolveCallerByAPIKey finds a caller by API key (timing-safe). Returns nil if no match.
func (c *GatewayConfig) resolveCallerByAPIKey(_ *http.Request, apiKey string) *CallerConfig {
	for i := range c.Callers {
		caller := &c.Callers[i]
		if caller.IdentifyBy == "source_ip" || caller.APIKey == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(caller.APIKey), []byte(apiKey)) == 1 {
			return caller
		}
	}
	return nil
}

// resolveCallerBySourceIP finds a caller whose source_ip_ranges contain clientIP. Returns nil if no match.
func (c *GatewayConfig) resolveCallerBySourceIP(clientIP net.IP) *CallerConfig {
	for i := range c.Callers {
		caller := &c.Callers[i]
		if caller.IdentifyBy != "source_ip" || len(caller.SourceIPRanges) == 0 {
			continue
		}
		for _, cidrStr := range caller.SourceIPRanges {
			_, network, err := net.ParseCIDR(cidrStr)
			if err != nil {
				continue
			}
			if network.Contains(clientIP) {
				return caller
			}
		}
	}
	return nil
}

func extractAPIKey(r *http.Request) string {
	// OpenAI-style and common: Authorization: Bearer <key>
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	// Anthropic: x-api-key
	if k := r.Header.Get("x-api-key"); k != "" {
		return strings.TrimSpace(k)
	}
	return ""
}

// clientIPFromRequest returns the client IP for source_ip caller identification.
// It uses X-Forwarded-For only when the direct peer (RemoteAddr) is in TrustedProxyCIDRs;
// otherwise it uses only RemoteAddr to prevent clients from spoofing X-Forwarded-For to bypass policy.
func (c *GatewayConfig) clientIPFromRequest(r *http.Request) net.IP {
	directPeer := peerIPFromAddr(r.RemoteAddr)
	if directPeer == nil {
		return nil
	}
	if len(c.TrustedProxyCIDRs) > 0 && c.isTrustedProxy(directPeer) {
		if ip := c.clientIPFromXFF(r); ip != nil {
			return ip
		}
	}
	return directPeer
}

// peerIPFromAddr extracts the IP from "host:port" or returns nil.
func peerIPFromAddr(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ParseIP(addr)
	}
	return net.ParseIP(host)
}

func (c *GatewayConfig) isTrustedProxy(ip net.IP) bool {
	for _, cidrStr := range c.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *GatewayConfig) clientIPFromXFF(r *http.Request) net.IP {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(xff), ",")
	if len(parts) == 0 {
		return nil
	}
	ipStr := strings.TrimSpace(parts[0])
	if ip := net.ParseIP(ipStr); ip != nil {
		return ip
	}
	return nil
}

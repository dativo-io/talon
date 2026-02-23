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
	// 1. Try API key (Authorization: Bearer or x-api-key)
	apiKey := extractAPIKey(r)
	if apiKey != "" {
		for i := range c.Callers {
			caller := &c.Callers[i]
			if caller.IdentifyBy == "source_ip" || caller.APIKey == "" {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(caller.APIKey), []byte(apiKey)) == 1 {
				return caller, nil
			}
		}
		// Key provided but no match
		if apiKey != "" {
			return nil, ErrCallerNotFound
		}
	}

	// 2. Try source IP matching (for DNS-intercepted traffic)
	clientIP := clientIPFromRequest(r)
	if clientIP != nil {
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
					return caller, nil
				}
			}
		}
	}

	// 3. No caller identified
	if c.DefaultPolicy.CallerIDRequired() {
		return nil, ErrCallerIDRequired
	}
	return nil, ErrCallerNotFound
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

// clientIPFromRequest returns the client IP, considering X-Forwarded-For when behind a proxy.
func clientIPFromRequest(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First value is the client (rest are proxies)
		parts := strings.Split(strings.TrimSpace(xff), ",")
		if len(parts) > 0 {
			ipStr := strings.TrimSpace(parts[0])
			if ip := net.ParseIP(ipStr); ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

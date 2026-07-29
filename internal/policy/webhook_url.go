package policy

import (
	"net/url"
	"strings"
)

// AllowedWebhookURL reports whether a URL is safe for an outbound
// operator-configured webhook POST: HTTPS anywhere, or HTTP to loopback only.
// This is the SSRF rule the runner's budget_alert_webhook shipped with; the
// org-wide cost webhook (#144) applies the identical rule so there is one
// vocabulary for "where Talon will POST".
func AllowedWebhookURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := strings.ToLower(u.Hostname())
		return h == "localhost" || h == "127.0.0.1" || strings.HasSuffix(h, ".localhost")
	default:
		return false
	}
}

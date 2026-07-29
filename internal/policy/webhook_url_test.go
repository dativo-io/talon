package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// One SSRF rule for every operator-configured webhook (#144): HTTPS anywhere,
// HTTP to loopback only — the runner budget_alert_webhook contract.
func TestAllowedWebhookURL(t *testing.T) {
	allowed := []string{
		"https://hooks.example.com/talon",
		"https://hooks.example.com:8443/path?x=1",
		"http://localhost:9000/hook",
		"http://127.0.0.1/hook",
		"http://dev.localhost/hook",
	}
	for _, u := range allowed {
		assert.True(t, AllowedWebhookURL(u), "should allow %s", u)
	}
	rejected := []string{
		"",
		"http://internal.corp/hook",       // HTTP to non-loopback
		"http://169.254.169.254/metadata", // cloud metadata endpoint
		"http://10.0.0.5/hook",
		"ftp://example.com/hook",
		"file:///etc/passwd",
		"hooks.example.com/no-scheme",
		"://garbage",
	}
	for _, u := range rejected {
		assert.False(t, AllowedWebhookURL(u), "should reject %s", u)
	}
}

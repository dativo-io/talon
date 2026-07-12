package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadGatewayConfig(t *testing.T) {
	path := writeConfig(t, `
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: enforce
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
    ollama:
      enabled: true
      base_url: "http://localhost:11434"
  organization_policy:
    default_pii_action: warn
    max_daily_cost: 100
`)
	cfg, err := LoadGatewayConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled true")
	}
	if cfg.ListenPrefix != "/v1/proxy" {
		t.Errorf("listen_prefix = %q", cfg.ListenPrefix)
	}
	if cfg.OrganizationPolicy.DefaultPIIAction != "warn" || cfg.OrganizationPolicy.MaxDailyCost != 100 {
		t.Errorf("organization_policy = %+v", cfg.OrganizationPolicy)
	}
	prov, ok := cfg.Provider("openai")
	if !ok || !prov.Enabled || prov.BaseURL != "https://api.openai.com" {
		t.Errorf("openai provider = %+v", prov)
	}
}

// Legacy caller-model keys must fail validation with an explicit
// breaking-change error — yaml.v3 would otherwise silently drop them and the
// config would run ungoverned (#266).
func TestLoadGatewayConfigRejectsLegacyKeys(t *testing.T) {
	base := `
gateway:
  enabled: true
  mode: enforce
  providers:
    ollama:
      enabled: true
      base_url: "http://localhost:11434"
`
	cases := []struct {
		name    string
		snippet string
		wantKey string
	}{
		{"callers", `
  callers:
    - name: legacy
      tenant_key: "talon-gw-abc"
`, `"callers"`},
		{"default_policy", `
  default_policy:
    default_pii_action: warn
`, `"default_policy"`},
		{"trusted_proxy_cidrs", `
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`, `"trusted_proxy_cidrs"`},
		{"require_caller_id", `
  organization_policy:
    require_caller_id: false
`, `"organization_policy.require_caller_id"`},
		{"per_caller_requests_per_min", `
  rate_limits:
    per_caller_requests_per_min: 60
`, `"rate_limits.per_caller_requests_per_min"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, base+tc.snippet)
			_, err := LoadGatewayConfig(path)
			if err == nil {
				t.Fatalf("expected legacy key %s to fail validation", tc.wantKey)
			}
			if !strings.Contains(err.Error(), tc.wantKey) || !strings.Contains(err.Error(), "#266") {
				t.Errorf("error should name the removed key and the breaking change, got: %v", err)
			}
		})
	}
}

func TestParseTimeouts(t *testing.T) {
	cfg := &GatewayConfig{
		Timeouts: TimeoutsConfig{
			ConnectTimeout:        "5s",
			RequestTimeout:        "30s",
			ResponseHeaderTimeout: "25s",
			StreamIdleTimeout:     "60s",
		},
	}
	pt, err := cfg.ParseTimeouts()
	if err != nil {
		t.Fatal(err)
	}
	if pt.ConnectTimeout != 5*time.Second || pt.RequestTimeout != 30*time.Second || pt.StreamIdleTimeout != 60*time.Second {
		t.Errorf("ParseTimeouts = %+v", pt)
	}
	if pt.ResponseHeaderTimeout != 25*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 25s", pt.ResponseHeaderTimeout)
	}
}

// Unset response_header_timeout must fall back to request_timeout — the header
// wait must never be cut shorter than the operator's request budget (#230).
func TestParseTimeouts_ResponseHeaderDefaultsToRequestTimeout(t *testing.T) {
	cfg := &GatewayConfig{
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "10s",
			RequestTimeout:    "120s",
			StreamIdleTimeout: "60s",
		},
	}
	pt, err := cfg.ParseTimeouts()
	if err != nil {
		t.Fatal(err)
	}
	if pt.ResponseHeaderTimeout != 120*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want request_timeout (120s)", pt.ResponseHeaderTimeout)
	}
}

func TestParseTimeouts_Invalid(t *testing.T) {
	cfg := &GatewayConfig{Timeouts: TimeoutsConfig{ConnectTimeout: "invalid"}}
	_, err := cfg.ParseTimeouts()
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestParseTimeouts_InvalidResponseHeader(t *testing.T) {
	cfg := &GatewayConfig{Timeouts: TimeoutsConfig{
		ConnectTimeout:        "10s",
		RequestTimeout:        "120s",
		ResponseHeaderTimeout: "bogus",
		StreamIdleTimeout:     "60s",
	}}
	_, err := cfg.ParseTimeouts()
	if err == nil {
		t.Error("expected error for invalid response_header_timeout")
	}
}

// Tenant scoping derives from the identity registry — agents declare tenants,
// the config does not (#266).
func TestRegistryMetricsTenantScope(t *testing.T) {
	t.Run("single_tenant", func(t *testing.T) {
		reg := testRegistry(
			testIdentity("a", "demo", "k1", nil),
			testIdentity("b", "demo", "k2", nil),
		)
		if got := reg.MetricsTenantScope(); got != "demo" {
			t.Fatalf("MetricsTenantScope() = %q, want demo", got)
		}
	})
	t.Run("multi_tenant", func(t *testing.T) {
		reg := testRegistry(
			testIdentity("a", "demo", "k1", nil),
			testIdentity("b", "prod", "k2", nil),
		)
		if got := reg.MetricsTenantScope(); got != "" {
			t.Fatalf("MetricsTenantScope() = %q, want empty for multi-tenant", got)
		}
	})
}

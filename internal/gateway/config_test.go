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
    defaults:
      pii_action: warn
      daily_cost: 100
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
	if cfg.OrganizationPolicy.Defaults.PIIAction != "warn" || cfg.OrganizationPolicy.Defaults.DailyCost != 100 {
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

// Pre-split flat organization_policy keys must fail load with a migration
// error naming the new defaults/constraints location — strict decoding would
// reject them anyway, but with a generic unknown-field message (#287).
func TestLoadGatewayConfigRejectsPreSplitOrgKeys(t *testing.T) {
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
		name     string
		snippet  string
		wantKey  string
		wantHint string
	}{
		{"default_pii_action", "  organization_policy:\n    default_pii_action: warn\n", `"organization_policy.default_pii_action"`, "defaults.pii_action"},
		{"max_daily_cost", "  organization_policy:\n    max_daily_cost: 100\n", `"organization_policy.max_daily_cost"`, "defaults.daily_cost"},
		{"max_monthly_cost", "  organization_policy:\n    max_monthly_cost: 500\n", `"organization_policy.max_monthly_cost"`, "constraints.max_monthly_cost"},
		{"allowed_models", "  organization_policy:\n    allowed_models: [\"gpt-4o\"]\n", `"organization_policy.allowed_models"`, "constraints.allowed_models"},
		{"forbidden_tools", "  organization_policy:\n    forbidden_tools: [\"delete_*\"]\n", `"organization_policy.forbidden_tools"`, "constraints.forbidden_tools"},
		{"tool_policy_action", "  organization_policy:\n    tool_policy_action: block\n", `"organization_policy.tool_policy_action"`, "defaults.tool_policy_action"},
		{"egress", "  organization_policy:\n    egress:\n      default_action: allow\n", `"organization_policy.egress"`, "constraints.egress"},
		{"attachment_policy", "  organization_policy:\n    attachment_policy:\n      action: warn\n", `"organization_policy.attachment_policy"`, "defaults.attachment_policy"},
		{"max_data_tier", "  organization_policy:\n    max_data_tier: 1\n", `"organization_policy.max_data_tier"`, "constraints.max_data_tier"},
		{"allowed_providers", "  organization_policy:\n    allowed_providers: [\"ollama\"]\n", `"organization_policy.allowed_providers"`, "constraints.allowed_providers"},
		{"response_pii_action", "  organization_policy:\n    response_pii_action: redact\n", `"organization_policy.response_pii_action"`, "defaults.response_pii_action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, base+tc.snippet)
			_, err := LoadGatewayConfig(path)
			if err == nil {
				t.Fatalf("expected pre-split key %s to fail load", tc.wantKey)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.wantKey) || !strings.Contains(msg, tc.wantHint) || !strings.Contains(msg, "#287") {
				t.Errorf("error should name the removed key, its new location, and #287, got: %v", err)
			}
		})
	}
	// Operational scalars did NOT move — they must still load at the top level.
	path := writeConfig(t, base+"  organization_policy:\n    log_prompts: true\n    scan_tool_content: off\n")
	cfg, err := LoadGatewayConfig(path)
	if err != nil {
		t.Fatalf("top-level operational keys must still load: %v", err)
	}
	if !cfg.OrganizationPolicy.LogPrompts || cfg.OrganizationPolicy.ScanToolContent != ScanToolContentOff {
		t.Errorf("operational keys mis-parsed: %+v", cfg.OrganizationPolicy)
	}
}

// Org budget bounds are validated as a set (#287): defaults must fit under
// the org's own ceilings, and nothing may be negative.
func TestValidateBudgetBounds(t *testing.T) {
	base := `
gateway:
  enabled: true
  mode: enforce
  providers:
    ollama:
      enabled: true
      base_url: "http://localhost:11434"
  organization_policy:
`
	t.Run("default above ceiling rejected", func(t *testing.T) {
		path := writeConfig(t, base+"    defaults:\n      daily_cost: 100\n    constraints:\n      max_daily_cost: 50\n")
		_, err := LoadGatewayConfig(path)
		if err == nil || !strings.Contains(err.Error(), "exceeds organization_policy.constraints.max_daily_cost") {
			t.Fatalf("want default-above-ceiling error, got: %v", err)
		}
	})
	t.Run("negative ceiling rejected", func(t *testing.T) {
		path := writeConfig(t, base+"    constraints:\n      max_monthly_cost: -1\n")
		_, err := LoadGatewayConfig(path)
		if err == nil || !strings.Contains(err.Error(), "must not be negative") {
			t.Fatalf("want negative-ceiling error, got: %v", err)
		}
	})
	t.Run("consistent bounds accepted", func(t *testing.T) {
		path := writeConfig(t, base+"    defaults:\n      daily_cost: 10\n      monthly_cost: 100\n    constraints:\n      max_daily_cost: 50\n      max_monthly_cost: 500\n")
		cfg, err := LoadGatewayConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.OrganizationPolicy.Constraints.MaxDailyCost != 50 || cfg.OrganizationPolicy.Defaults.DailyCost != 10 {
			t.Errorf("bounds mis-parsed: %+v", cfg.OrganizationPolicy)
		}
	})
	// The implicit baseline (100/2000 when unset) is ceiling-aware: an
	// operator setting only constraints.max_daily_cost must not trip
	// validation over a built-in default they never wrote — the implicit
	// baseline clamps to the ceiling instead (#287).
	t.Run("implicit default clamps to explicit ceiling", func(t *testing.T) {
		path := writeConfig(t, base+"    constraints:\n      max_daily_cost: 20\n")
		cfg, err := LoadGatewayConfig(path)
		if err != nil {
			t.Fatalf("ceiling-only config must load: %v", err)
		}
		if cfg.OrganizationPolicy.Defaults.DailyCost != 20 {
			t.Errorf("implicit daily baseline = %v, want clamped to ceiling 20", cfg.OrganizationPolicy.Defaults.DailyCost)
		}
	})
}

// Org allowed_providers entries must name configured providers (#284):
// matching is exact and case-sensitive, so a typo would silently deny every
// request at runtime instead of failing at load.
func TestValidateOrgAllowedProvidersAgainstConfigured(t *testing.T) {
	base := `
gateway:
  enabled: true
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
    constraints:
`
	t.Run("case typo rejected at load", func(t *testing.T) {
		path := writeConfig(t, base+"      allowed_providers: [\"OpenAI\"]\n")
		_, err := LoadGatewayConfig(path)
		if err == nil || !strings.Contains(err.Error(), `"OpenAI" does not match any configured provider`) {
			t.Fatalf("want configured-provider mismatch error, got: %v", err)
		}
		if !strings.Contains(err.Error(), "ollama, openai") {
			t.Errorf("error should list configured providers sorted, got: %v", err)
		}
	})
	t.Run("unknown name rejected at load", func(t *testing.T) {
		path := writeConfig(t, base+"      allowed_providers: [\"mistral-eu\"]\n")
		_, err := LoadGatewayConfig(path)
		if err == nil || !strings.Contains(err.Error(), "#284") {
			t.Fatalf("want mismatch error referencing #284, got: %v", err)
		}
	})
	t.Run("configured names accepted", func(t *testing.T) {
		path := writeConfig(t, base+"      allowed_providers: [\"openai\", \"ollama\"]\n")
		if _, err := LoadGatewayConfig(path); err != nil {
			t.Fatalf("configured provider names must validate: %v", err)
		}
	})
	t.Run("empty list stays unrestricted", func(t *testing.T) {
		path := writeConfig(t, base+"      allowed_providers: []\n")
		if _, err := LoadGatewayConfig(path); err != nil {
			t.Fatalf("empty list must load: %v", err)
		}
	})
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

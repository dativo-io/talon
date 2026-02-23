package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadGatewayConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	content := `
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
  callers:
    - name: test
      api_key: "talon-gw-abc"
      tenant_id: "default"
  default_policy:
    default_pii_action: warn
    max_daily_cost: 100
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
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
	if len(cfg.Callers) != 1 || cfg.Callers[0].Name != "test" {
		t.Errorf("callers = %+v", cfg.Callers)
	}
	prov, ok := cfg.Provider("openai")
	if !ok || !prov.Enabled || prov.BaseURL != "https://api.openai.com" {
		t.Errorf("openai provider = %+v", prov)
	}
}

func TestParseTimeouts(t *testing.T) {
	cfg := &GatewayConfig{
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	pt, err := cfg.ParseTimeouts()
	if err != nil {
		t.Fatal(err)
	}
	if pt.ConnectTimeout != 5*time.Second || pt.RequestTimeout != 30*time.Second || pt.StreamIdleTimeout != 60*time.Second {
		t.Errorf("ParseTimeouts = %+v", pt)
	}
}

func TestParseTimeouts_Invalid(t *testing.T) {
	cfg := &GatewayConfig{Timeouts: TimeoutsConfig{ConnectTimeout: "invalid"}}
	_, err := cfg.ParseTimeouts()
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestCallerByName(t *testing.T) {
	cfg := &GatewayConfig{
		Callers: []CallerConfig{
			{Name: "a", TenantID: "t1"},
			{Name: "b", TenantID: "t2"},
		},
	}
	c := cfg.CallerByName("b")
	if c == nil || c.TenantID != "t2" {
		t.Errorf("CallerByName(b) = %+v", c)
	}
	if cfg.CallerByName("missing") != nil {
		t.Error("expected nil for missing caller")
	}
}

package gateway

import (
	"context"
	"testing"
)

func TestQuickstartConfig_Defaults(t *testing.T) {
	cfg, err := QuickstartConfig(QuickstartOptions{})
	if err != nil {
		t.Fatalf("QuickstartConfig() error = %v", err)
	}

	if !cfg.Enabled {
		t.Fatal("expected enabled quickstart config")
	}
	if cfg.Mode != ModeEnforce {
		t.Fatalf("mode = %q, want %q", cfg.Mode, ModeEnforce)
	}
	if cfg.ListenPrefix != "/v1/proxy" {
		t.Fatalf("listen prefix = %q", cfg.ListenPrefix)
	}
	if cfg.OrganizationPolicy.DefaultPIIAction != "redact" {
		t.Fatalf("default pii action = %q", cfg.OrganizationPolicy.DefaultPIIAction)
	}
	prov, ok := cfg.Provider("openai")
	if !ok {
		t.Fatal("openai provider missing")
	}
	if prov.UpstreamAuthMode != "client_bearer" {
		t.Fatalf("upstream auth mode = %q", prov.UpstreamAuthMode)
	}
	if prov.BaseURL != "https://api.openai.com" {
		t.Fatalf("base url = %q", prov.BaseURL)
	}
	if len(prov.AllowedModels) == 0 {
		t.Fatal("expected non-empty default model allowlist")
	}
}

// Quickstart identity is synthetic and context-injected — the config carries
// no identity at all (#266).
func TestQuickstartIdentityShape(t *testing.T) {
	id := NewQuickstartIdentity()
	if id.Name != quickstartAgentName || id.TenantID != quickstartTenantID {
		t.Fatalf("identity = %+v", id)
	}
	if !id.HasTag("quickstart") {
		t.Fatal("expected quickstart tag")
	}
	// The openai-only restriction rides the standard override channel so it
	// flows through ResolveEffectivePolicy like every real agent's (#266).
	if id.Override == nil || len(id.Override.AllowedProviders) != 1 || id.Override.AllowedProviders[0] != "openai" {
		t.Fatalf("override = %+v", id.Override)
	}
}

func TestQuickstartConfig_EnvOverrides(t *testing.T) {
	t.Setenv("TALON_QUICKSTART_MODE", "shadow")
	t.Setenv("TALON_QUICKSTART_OPENAI_BASE_URL", "http://localhost:4000")
	t.Setenv("TALON_QUICKSTART_ALLOW_ALL_MODELS", "true")

	cfg, err := QuickstartConfig(QuickstartOptions{})
	if err != nil {
		t.Fatalf("QuickstartConfig() error = %v", err)
	}
	if cfg.Mode != ModeShadow {
		t.Fatalf("mode = %q, want %q", cfg.Mode, ModeShadow)
	}
	prov, _ := cfg.Provider("openai")
	if prov.BaseURL != "http://localhost:4000" {
		t.Fatalf("base url = %q", prov.BaseURL)
	}
	if len(prov.AllowedModels) != 0 {
		t.Fatalf("allowed models = %v, want empty when allow-all is set", prov.AllowedModels)
	}
}

func TestQuickstartConfig_UnsafeListenOption(t *testing.T) {
	cfg, err := QuickstartConfig(QuickstartOptions{UnsafeListen: true})
	if err != nil {
		t.Fatalf("QuickstartConfig() error = %v", err)
	}
	if !cfg.QuickstartUnsafeListen {
		t.Fatal("expected QuickstartUnsafeListen=true to be propagated from options")
	}

	cfgOff, err := QuickstartConfig(QuickstartOptions{})
	if err != nil {
		t.Fatalf("QuickstartConfig() error = %v", err)
	}
	if cfgOff.QuickstartUnsafeListen {
		t.Fatal("expected QuickstartUnsafeListen=false by default")
	}

	// The field must be ignored by YAML marshaling so it cannot be persisted or
	// loaded via talon.config.yaml — this is a quickstart-only runtime signal.
	if err := cfgOff.Validate(); err != nil {
		t.Fatalf("validate default quickstart config: %v", err)
	}
}

func TestGatewayAnnotations_UnsafeListenFromConfigNotEnv(t *testing.T) {
	// Ensure the annotation comes from GatewayConfig.QuickstartUnsafeListen and
	// not from any process environment variable, so quickstart does not need
	// env mutation to surface the degraded bind.
	t.Setenv("TALON_QUICKSTART_UNSAFE_LISTEN", "1")
	cfg, err := QuickstartConfig(QuickstartOptions{})
	if err != nil {
		t.Fatalf("QuickstartConfig() error = %v", err)
	}
	gw := &Gateway{config: cfg}
	ann := gatewayAnnotationsForEvidence(context.Background(), gw, NewQuickstartIdentity())
	for _, a := range ann {
		if a == "quickstart_unsafe_listen" {
			t.Fatalf("annotation should not be set from env var, got %v", ann)
		}
	}

	cfg2, err := QuickstartConfig(QuickstartOptions{UnsafeListen: true})
	if err != nil {
		t.Fatalf("QuickstartConfig(UnsafeListen) error = %v", err)
	}
	gw2 := &Gateway{config: cfg2}
	ann2 := gatewayAnnotationsForEvidence(context.Background(), gw2, NewQuickstartIdentity())
	found := false
	for _, a := range ann2 {
		if a == "quickstart_unsafe_listen" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected quickstart_unsafe_listen annotation when config field is set, got %v", ann2)
	}
}

func TestGatewayConfigValidate_UpstreamAuthMode(t *testing.T) {
	cfg := &GatewayConfig{
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", UpstreamAuthMode: "client_bearer"},
		},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	// client_bearer only validates under the in-process quickstart profile
	// (#266) — a YAML-loaded gateway config can never carry it.
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for client_bearer outside the quickstart profile")
	}
	cfg.EnableQuickstartProfile()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	cfg.Providers["openai"] = ProviderConfig{Enabled: true, BaseURL: "https://api.openai.com", UpstreamAuthMode: "invalid"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid upstream_auth_mode")
	}
}

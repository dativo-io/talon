package gateway

import "testing"

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
	if cfg.ServerDefaults.DefaultPIIAction != "redact" {
		t.Fatalf("default pii action = %q", cfg.ServerDefaults.DefaultPIIAction)
	}
	if cfg.ServerDefaults.CallerIDRequired() {
		t.Fatal("quickstart should not require caller id")
	}
	if len(cfg.Callers) != 1 {
		t.Fatalf("callers len = %d", len(cfg.Callers))
	}
	if cfg.Callers[0].Name != quickstartCallerName || cfg.Callers[0].TenantID != quickstartTenantID {
		t.Fatalf("caller = %+v", cfg.Callers[0])
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
	ann := gatewayAnnotationsForEvidence(gw, &cfg.Callers[0])
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
	ann2 := gatewayAnnotationsForEvidence(gw2, &cfg2.Callers[0])
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
		Callers: []CallerConfig{
			{Name: "quickstart-local", TenantID: "quickstart"},
		},
		ServerDefaults: ServerDefaults{RequireCallerID: boolPtr(false)},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	cfg.Providers["openai"] = ProviderConfig{Enabled: true, BaseURL: "https://api.openai.com", UpstreamAuthMode: "invalid"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid upstream_auth_mode")
	}
}

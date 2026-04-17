package gateway

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	quickstartCallerName = "quickstart-local"
	quickstartTenantID   = "quickstart"
)

// QuickstartOptions configures the in-memory proxy quickstart profile.
type QuickstartOptions struct {
	OpenAIBaseURL string
	// UnsafeListen signals that serve was invoked with --unsafe-listen and is
	// binding a non-loopback address. It is surfaced on evidence records via
	// gateway_annotations so operators can see the degradation without needing
	// process-wide environment flags.
	UnsafeListen bool
}

// QuickstartConfig builds a minimal in-memory gateway config for local
// OpenAI-compatible proxy quickstart mode. It is intentionally narrow and
// should not become a general configuration system.
func QuickstartConfig(opts QuickstartOptions) (*GatewayConfig, error) {
	mode := ModeEnforce
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TALON_QUICKSTART_MODE")), "shadow") {
		mode = ModeShadow
	}

	baseURL := strings.TrimSpace(opts.OpenAIBaseURL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("TALON_QUICKSTART_OPENAI_BASE_URL"))
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com"
	}

	provider := ProviderConfig{
		Enabled:          true,
		BaseURL:          baseURL,
		UpstreamAuthMode: "client_bearer",
		AllowedModels:    []string{"gpt-4o-mini", "gpt-4o"},
	}

	annotations := []string{"quickstart_mode"}
	if parseQuickstartBoolEnv("TALON_QUICKSTART_ALLOW_ALL_MODELS") {
		provider.AllowedModels = nil
		annotations = append(annotations, "quickstart_model_allowlist_disabled")
	}

	requireCallerID := false
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: DefaultListenPrefix,
		Mode:         mode,
		Providers: map[string]ProviderConfig{
			"openai": provider,
		},
		Callers: []CallerConfig{
			{
				Name:             quickstartCallerName,
				TenantID:         quickstartTenantID,
				Tags:             []string{"quickstart"},
				AllowedProviders: []string{"openai"},
			},
		},
		ServerDefaults: ServerDefaults{
			DefaultPIIAction: "redact",
			MaxDailyCost:     50,
			MaxMonthlyCost:   500,
			RequireCallerID:  &requireCallerID,
			LogPrompts:       false,
			LogResponses:     false,
		},
		RateLimits: RateLimitsConfig{
			GlobalRequestsPerMin:    600,
			PerCallerRequestsPerMin: 300,
		},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    DefaultConnectTimeout,
			RequestTimeout:    DefaultRequestTimeout,
			StreamIdleTimeout: DefaultStreamIdleTimeout,
		},
		QuickstartUnsafeListen: opts.UnsafeListen,
	}
	_ = annotations // annotations are recorded per-request by gateway evidence path.

	if err := cfg.ApplyDefaults(); err != nil {
		return nil, fmt.Errorf("applying quickstart defaults: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating quickstart config: %w", err)
	}
	return cfg, nil
}

func parseQuickstartBoolEnv(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

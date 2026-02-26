// Package gateway implements the LLM API Gateway — a provider-compatible
// reverse proxy that adds PII scanning, policy enforcement, cost governance,
// and immutable audit trails.
package gateway

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode is the gateway operation mode.
type Mode string

const (
	ModeEnforce Mode = "enforce"  // Full pipeline with blocking
	ModeShadow  Mode = "shadow"   // Log everything, never block
	ModeLogOnly Mode = "log_only" // Only generate evidence, no policy evaluation
)

// GatewayConfig is the top-level gateway configuration (server-wide).
//
//revive:disable-next-line:exported
type GatewayConfig struct {
	Enabled             bool                       `yaml:"enabled" json:"enabled"`
	ListenPrefix        string                     `yaml:"listen_prefix" json:"listen_prefix"`
	Mode                Mode                       `yaml:"mode" json:"mode"`
	Providers           map[string]ProviderConfig  `yaml:"providers" json:"providers"`
	Callers             []CallerConfig             `yaml:"callers" json:"callers"`
	DefaultPolicy       DefaultPolicyConfig        `yaml:"default_policy" json:"default_policy"`
	ResponseScanning    ResponseScanningConfig     `yaml:"response_scanning" json:"response_scanning"`
	RateLimits          RateLimitsConfig           `yaml:"rate_limits" json:"rate_limits"`
	Timeouts            TimeoutsConfig             `yaml:"timeouts" json:"timeouts"`
	NetworkInterception *NetworkInterceptionConfig `yaml:"network_interception,omitempty" json:"network_interception,omitempty"`
	// TrustedProxyCIDRs: when set, X-Forwarded-For is used for client IP only when the direct peer (RemoteAddr) is in one of these CIDRs. Prevents spoofing when gateway is not behind a trusted proxy. Empty = never trust X-Forwarded-For for source_ip.
	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs,omitempty" json:"trusted_proxy_cidrs,omitempty"`
}

// ProviderConfig holds per-provider gateway settings.
type ProviderConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	SecretName    string   `yaml:"secret_name,omitempty" json:"secret_name,omitempty"`
	BaseURL       string   `yaml:"base_url" json:"base_url"`
	AllowedModels []string `yaml:"allowed_models,omitempty" json:"allowed_models,omitempty"`
	BlockedModels []string `yaml:"blocked_models,omitempty" json:"blocked_models,omitempty"`
}

// CallerConfig identifies an application or team that uses the gateway.
type CallerConfig struct {
	Name             string                 `yaml:"name" json:"name"`
	APIKey           string                 `yaml:"api_key,omitempty" json:"api_key,omitempty"` // #nosec G117 -- auth identifier from config, not a hardcoded secret
	TenantID         string                 `yaml:"tenant_id" json:"tenant_id"`
	Team             string                 `yaml:"team,omitempty" json:"team,omitempty"`
	IdentifyBy       string                 `yaml:"identify_by,omitempty" json:"identify_by,omitempty"` // "source_ip" for IP-based
	SourceIPRanges   []string               `yaml:"source_ip_ranges,omitempty" json:"source_ip_ranges,omitempty"`
	AllowedProviders []string               `yaml:"allowed_providers,omitempty" json:"allowed_providers,omitempty"`
	PolicyOverrides  *CallerPolicyOverrides `yaml:"policy_overrides,omitempty" json:"policy_overrides,omitempty"`
}

// CallerPolicyOverrides are per-caller policy overrides.
type CallerPolicyOverrides struct {
	MaxDailyCost      float64                 `yaml:"max_daily_cost,omitempty" json:"max_daily_cost,omitempty"`
	MaxMonthlyCost    float64                 `yaml:"max_monthly_cost,omitempty" json:"max_monthly_cost,omitempty"`
	PIIAction         string                  `yaml:"pii_action,omitempty" json:"pii_action,omitempty"`                   // block | redact | warn | allow
	ResponsePIIAction string                  `yaml:"response_pii_action,omitempty" json:"response_pii_action,omitempty"` // block | redact | warn | allow; inherits from pii_action
	AllowedModels     []string                `yaml:"allowed_models,omitempty" json:"allowed_models,omitempty"`
	BlockedModels     []string                `yaml:"blocked_models,omitempty" json:"blocked_models,omitempty"`
	MaxDataTier       *int                    `yaml:"max_data_tier,omitempty" json:"max_data_tier,omitempty"` // 0, 1, or 2
	AttachmentPolicy  *AttachmentPolicyConfig `yaml:"attachment_policy,omitempty" json:"attachment_policy,omitempty"`
}

// AttachmentPolicyConfig controls scanning of base64-encoded file attachments
// embedded in LLM API requests (PDFs, images, HTML, etc.).
type AttachmentPolicyConfig struct {
	Action          string   `yaml:"action" json:"action"`                                         // block | strip | warn | allow (default: warn)
	InjectionAction string   `yaml:"injection_action,omitempty" json:"injection_action,omitempty"` // block | strip | warn (default: warn)
	MaxFileSizeMB   int      `yaml:"max_file_size_mb,omitempty" json:"max_file_size_mb,omitempty"` // default: 10
	AllowedTypes    []string `yaml:"allowed_types,omitempty" json:"allowed_types,omitempty"`
	BlockedTypes    []string `yaml:"blocked_types,omitempty" json:"blocked_types,omitempty"`
}

// DefaultPolicyConfig holds server-wide default policy for the gateway.
type DefaultPolicyConfig struct {
	DefaultPIIAction        string                  `yaml:"default_pii_action" json:"default_pii_action"`                       // warn | block | redact | allow
	ResponsePIIAction       string                  `yaml:"response_pii_action,omitempty" json:"response_pii_action,omitempty"` // block | redact | warn | allow; inherits from default_pii_action
	MaxDailyCost            float64                 `yaml:"max_daily_cost" json:"max_daily_cost"`
	MaxMonthlyCost          float64                 `yaml:"max_monthly_cost" json:"max_monthly_cost"`
	RequireCallerID         *bool                   `yaml:"require_caller_id" json:"require_caller_id"` // nil = true (default)
	LogPrompts              bool                    `yaml:"log_prompts" json:"log_prompts"`
	LogResponses            bool                    `yaml:"log_responses" json:"log_responses"`
	LogResponsePreviewChars int                     `yaml:"log_response_preview_chars" json:"log_response_preview_chars"`
	AttachmentPolicy        *AttachmentPolicyConfig `yaml:"attachment_policy,omitempty" json:"attachment_policy,omitempty"`
}

// CallerIDRequired returns whether anonymous requests must be rejected. Default is true when unset.
func (d *DefaultPolicyConfig) CallerIDRequired() bool {
	if d == nil || d.RequireCallerID == nil {
		return true
	}
	return *d.RequireCallerID
}

// ResponseScanningConfig controls scanning LLM responses for PII (Phase 2).
type ResponseScanningConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// RateLimitsConfig holds gateway rate limits.
type RateLimitsConfig struct {
	GlobalRequestsPerMin    int `yaml:"global_requests_per_min" json:"global_requests_per_min"`
	PerCallerRequestsPerMin int `yaml:"per_caller_requests_per_min" json:"per_caller_requests_per_min"`
}

// TimeoutsConfig holds gateway timeouts. Values are stored as strings (e.g. "10s") and parsed to time.Duration.
type TimeoutsConfig struct {
	ConnectTimeout    string `yaml:"connect_timeout" json:"connect_timeout"`
	RequestTimeout    string `yaml:"request_timeout" json:"request_timeout"`
	StreamIdleTimeout string `yaml:"stream_idle_timeout" json:"stream_idle_timeout"`
}

// ParsedTimeouts holds parsed time.Duration values for use at runtime.
type ParsedTimeouts struct {
	ConnectTimeout    time.Duration
	RequestTimeout    time.Duration
	StreamIdleTimeout time.Duration
}

// NetworkInterceptionConfig is for enterprise DNS interception (Phase 2).
type NetworkInterceptionConfig struct {
	Enabled        bool                    `yaml:"enabled" json:"enabled"`
	InterceptHosts []InterceptHostConfig   `yaml:"intercept_hosts,omitempty" json:"intercept_hosts,omitempty"`
	TLS            *NetworkInterceptionTLS `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// InterceptHostConfig maps an original host to a provider.
type InterceptHostConfig struct {
	Original string `yaml:"original" json:"original"`
	Provider string `yaml:"provider" json:"provider"`
	Note     string `yaml:"note,omitempty" json:"note,omitempty"`
}

// NetworkInterceptionTLS holds TLS cert paths for intercepted domains.
type NetworkInterceptionTLS struct {
	CertDir string `yaml:"cert_dir" json:"cert_dir"`
}

// Default gateway config values.
const (
	DefaultListenPrefix            = "/v1/proxy"
	DefaultMode                    = ModeEnforce
	DefaultRequireCallerID         = true
	DefaultLogPrompts              = true
	DefaultPIIAction               = "warn"
	DefaultGlobalRPM               = 300
	DefaultPerCallerRPM            = 60
	DefaultConnectTimeout          = "10s"
	DefaultRequestTimeout          = "120s"
	DefaultStreamIdleTimeout       = "60s"
	DefaultAttachmentAction        = "warn"
	DefaultAttachmentInjAction     = "warn"
	DefaultAttachmentMaxFileSizeMB = 10
)

// LoadGatewayConfig loads gateway configuration from a YAML file.
// If the file has a top-level "gateway" key, that subtree is unmarshaled; otherwise the whole file is GatewayConfig.
func LoadGatewayConfig(path string) (*GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading gateway config %s: %w", path, err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing gateway config: %w", err)
	}

	var cfg GatewayConfig
	if g, ok := raw["gateway"]; ok {
		sub, _ := yaml.Marshal(g)
		if err := yaml.Unmarshal(sub, &cfg); err != nil {
			return nil, fmt.Errorf("unmarshaling gateway block: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("unmarshaling gateway config: %w", err)
		}
	}

	if err := cfg.ApplyDefaults(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ApplyDefaults sets default values for missing fields.
func (c *GatewayConfig) ApplyDefaults() error {
	if c.ListenPrefix == "" {
		c.ListenPrefix = DefaultListenPrefix
	}
	if c.Mode == "" {
		c.Mode = DefaultMode
	}
	if c.Providers == nil {
		c.Providers = make(map[string]ProviderConfig)
	}
	if c.Callers == nil {
		c.Callers = []CallerConfig{}
	}
	if c.DefaultPolicy.DefaultPIIAction == "" {
		c.DefaultPolicy.DefaultPIIAction = DefaultPIIAction
	}
	if c.DefaultPolicy.MaxDailyCost == 0 {
		c.DefaultPolicy.MaxDailyCost = 100
	}
	if c.DefaultPolicy.MaxMonthlyCost == 0 {
		c.DefaultPolicy.MaxMonthlyCost = 2000
	}
	if c.RateLimits.GlobalRequestsPerMin == 0 {
		c.RateLimits.GlobalRequestsPerMin = DefaultGlobalRPM
	}
	if c.RateLimits.PerCallerRequestsPerMin == 0 {
		c.RateLimits.PerCallerRequestsPerMin = DefaultPerCallerRPM
	}
	if c.Timeouts.ConnectTimeout == "" {
		c.Timeouts.ConnectTimeout = DefaultConnectTimeout
	}
	if c.Timeouts.RequestTimeout == "" {
		c.Timeouts.RequestTimeout = DefaultRequestTimeout
	}
	if c.Timeouts.StreamIdleTimeout == "" {
		c.Timeouts.StreamIdleTimeout = DefaultStreamIdleTimeout
	}
	c.DefaultPolicy.AttachmentPolicy = applyAttachmentPolicyDefaults(c.DefaultPolicy.AttachmentPolicy)
	return nil
}

// applyAttachmentPolicyDefaults fills in missing values for an AttachmentPolicyConfig.
func applyAttachmentPolicyDefaults(p *AttachmentPolicyConfig) *AttachmentPolicyConfig {
	if p == nil {
		p = &AttachmentPolicyConfig{}
	}
	if p.Action == "" {
		p.Action = DefaultAttachmentAction
	}
	if p.InjectionAction == "" {
		p.InjectionAction = DefaultAttachmentInjAction
	}
	if p.MaxFileSizeMB <= 0 {
		p.MaxFileSizeMB = DefaultAttachmentMaxFileSizeMB
	}
	return p
}

// Validate checks that the configuration is valid.
//
//nolint:gocyclo // validation branches are independent checks
func (c *GatewayConfig) Validate() error {
	if c.ListenPrefix == "" {
		return fmt.Errorf("gateway listen_prefix is required")
	}
	switch c.Mode {
	case ModeEnforce, ModeShadow, ModeLogOnly:
	default:
		return fmt.Errorf("gateway mode must be enforce, shadow, or log_only")
	}
	for name, p := range c.Providers {
		if !p.Enabled {
			continue
		}
		if p.BaseURL == "" && (name == "openai" || name == "anthropic" || name == "ollama") {
			return fmt.Errorf("gateway provider %q: base_url is required", name)
		}
		if name != "ollama" && p.SecretName == "" {
			return fmt.Errorf("gateway provider %q: secret_name is required", name)
		}
	}
	if p := c.DefaultPolicy.AttachmentPolicy; p != nil {
		switch p.Action {
		case "block", "strip", "warn", "allow":
		default:
			return fmt.Errorf("gateway default_policy.attachment_policy.action must be block, strip, warn, or allow")
		}
		switch p.InjectionAction {
		case "block", "strip", "warn", "":
		default:
			return fmt.Errorf("gateway default_policy.attachment_policy.injection_action must be block, strip, or warn")
		}
	}
	for i := range c.Callers {
		caller := &c.Callers[i]
		if caller.Name == "" {
			return fmt.Errorf("gateway caller at index %d: name is required", i)
		}
		if caller.TenantID == "" {
			caller.TenantID = "default"
		}
		if caller.IdentifyBy == "source_ip" {
			if len(caller.SourceIPRanges) == 0 {
				return fmt.Errorf("gateway caller %q: source_ip_ranges required when identify_by is source_ip", caller.Name)
			}
		} else if caller.APIKey == "" {
			return fmt.Errorf("gateway caller %q: api_key or identify_by=source_ip with source_ip_ranges is required", caller.Name)
		}
	}
	return nil
}

// ResolveAttachmentPolicy returns the effective attachment policy for a caller,
// merging caller overrides on top of the server default.
func ResolveAttachmentPolicy(defaultPolicy *DefaultPolicyConfig, overrides *CallerPolicyOverrides) *AttachmentPolicyConfig {
	base := defaultPolicy.AttachmentPolicy
	if base == nil {
		base = &AttachmentPolicyConfig{
			Action:          DefaultAttachmentAction,
			InjectionAction: DefaultAttachmentInjAction,
			MaxFileSizeMB:   DefaultAttachmentMaxFileSizeMB,
		}
	}
	if overrides == nil || overrides.AttachmentPolicy == nil {
		return base
	}
	merged := *base
	ov := overrides.AttachmentPolicy
	if ov.Action != "" {
		merged.Action = ov.Action
	}
	if ov.InjectionAction != "" {
		merged.InjectionAction = ov.InjectionAction
	}
	if ov.MaxFileSizeMB > 0 {
		merged.MaxFileSizeMB = ov.MaxFileSizeMB
	}
	if len(ov.AllowedTypes) > 0 {
		merged.AllowedTypes = ov.AllowedTypes
	}
	if len(ov.BlockedTypes) > 0 {
		merged.BlockedTypes = ov.BlockedTypes
	}
	return &merged
}

// ParseTimeouts returns parsed time.Duration values for the configured timeout strings.
func (c *GatewayConfig) ParseTimeouts() (ParsedTimeouts, error) {
	var pt ParsedTimeouts
	var err error
	pt.ConnectTimeout, err = time.ParseDuration(c.Timeouts.ConnectTimeout)
	if err != nil {
		return pt, fmt.Errorf("connect_timeout %q: %w", c.Timeouts.ConnectTimeout, err)
	}
	pt.RequestTimeout, err = time.ParseDuration(c.Timeouts.RequestTimeout)
	if err != nil {
		return pt, fmt.Errorf("request_timeout %q: %w", c.Timeouts.RequestTimeout, err)
	}
	pt.StreamIdleTimeout, err = time.ParseDuration(c.Timeouts.StreamIdleTimeout)
	if err != nil {
		return pt, fmt.Errorf("stream_idle_timeout %q: %w", c.Timeouts.StreamIdleTimeout, err)
	}
	return pt, nil
}

// CallerByName returns the caller config by name.
func (c *GatewayConfig) CallerByName(name string) *CallerConfig {
	for i := range c.Callers {
		if c.Callers[i].Name == name {
			return &c.Callers[i]
		}
	}
	return nil
}

// Provider returns the provider config for the given provider name (e.g. "openai", "anthropic", "ollama").
func (c *GatewayConfig) Provider(name string) (ProviderConfig, bool) {
	p, ok := c.Providers[name]
	return p, ok
}

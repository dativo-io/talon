// Package gateway implements the LLM API Gateway — a provider-compatible
// reverse proxy that adds PII scanning, policy enforcement, cost governance,
// and immutable audit trails.
package gateway

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
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

// GatewayConfig is the top-level gateway configuration from talon.config.yaml
// (infrastructure config, owned by DevOps/platform team).
//
//revive:disable-next-line:exported
type GatewayConfig struct {
	Enabled             bool                       `yaml:"enabled" json:"enabled"`
	ListenPrefix        string                     `yaml:"listen_prefix" json:"listen_prefix"`
	Mode                Mode                       `yaml:"mode" json:"mode"`
	Providers           map[string]ProviderConfig  `yaml:"providers" json:"providers"`
	Callers             []CallerConfig             `yaml:"callers" json:"callers"`
	ServerDefaults      ServerDefaults             `yaml:"default_policy" json:"default_policy"`
	ResponseScanning    ResponseScanningConfig     `yaml:"response_scanning" json:"response_scanning"`
	RateLimits          RateLimitsConfig           `yaml:"rate_limits" json:"rate_limits"`
	Timeouts            TimeoutsConfig             `yaml:"timeouts" json:"timeouts"`
	NetworkInterception *NetworkInterceptionConfig `yaml:"network_interception,omitempty" json:"network_interception,omitempty"`
	// TrustedProxyCIDRs: when set, X-Forwarded-For is used for client IP only when the direct peer (RemoteAddr) is in one of these CIDRs. Prevents spoofing when gateway is not behind a trusted proxy. Empty = never trust X-Forwarded-For for source_ip.
	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs,omitempty" json:"trusted_proxy_cidrs,omitempty"`
	// DashboardListen is the optional separate bind address for the gateway
	// dashboard (e.g. "127.0.0.1:9091"). When empty, routes are served on the
	// main API server. Binding to localhost prevents accidental exposure.
	DashboardListen string `yaml:"dashboard_listen,omitempty" json:"dashboard_listen,omitempty"`
	// QuickstartUnsafeListen marks that the serving process bound the
	// OpenAI-compatible quickstart facade to a non-loopback address with
	// --unsafe-listen. Set by QuickstartConfig only; never populated from YAML.
	// The gateway uses this at evidence time to annotate requests with
	// quickstart_unsafe_listen without relying on process-wide environment state.
	QuickstartUnsafeListen bool `yaml:"-" json:"-"`
	// UpstreamTransport when set wraps the gateway upstream HTTP client (air-gap egress guard).
	UpstreamTransport http.RoundTripper `yaml:"-" json:"-"`
	// EffectiveSovereigntyMode is set at runtime by serve from operator config (not YAML).
	EffectiveSovereigntyMode string `yaml:"-" json:"-"`
}

// ProviderConfig holds per-provider gateway settings.
type ProviderConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	SecretName string `yaml:"secret_name,omitempty" json:"secret_name,omitempty"`
	// UpstreamAuthMode controls how Talon authenticates to the upstream provider.
	// "secret" (default) reads provider credentials from Talon's secret store.
	// "client_bearer" forwards the caller bearer token upstream and is intended
	// for proxy quickstart mode only.
	UpstreamAuthMode string `yaml:"upstream_auth_mode,omitempty" json:"upstream_auth_mode,omitempty"` // secret | client_bearer
	BaseURL          string `yaml:"base_url" json:"base_url"`
	// Region is the jurisdiction of the upstream endpoint ("EU", "US",
	// "LOCAL", ...) recorded in data-flow evidence. When empty, Talon falls
	// back to registered provider metadata, then "unknown" — never a guess.
	Region           string   `yaml:"region,omitempty" json:"region,omitempty"`
	AllowedModels    []string `yaml:"allowed_models,omitempty" json:"allowed_models,omitempty"`
	BlockedModels    []string `yaml:"blocked_models,omitempty" json:"blocked_models,omitempty"`
	ForbiddenTools   []string `yaml:"forbidden_tools,omitempty" json:"forbidden_tools,omitempty"`
	ToolPolicyAction string   `yaml:"tool_policy_action,omitempty" json:"tool_policy_action,omitempty"` // filter | block
	// APIFamily declares the provider's wire format: "openai" or "anthropic".
	// Used for fallback-chain validation and upstream auth conventions
	// (x-api-key + anthropic-version vs Authorization: Bearer). When empty it
	// defaults by provider name: "anthropic" → anthropic, everything else →
	// openai-compatible. Set it explicitly for aliased endpoints (e.g. an
	// "anthropic-eu" provider pointing at an Anthropic-compatible base_url).
	APIFamily string `yaml:"api_family,omitempty" json:"api_family,omitempty"`
	// Fallback is the ordered error-driven fallback chain for this provider:
	// on a transient upstream failure (timeout / connection error / 429 / 5xx)
	// the gateway retries the request against each target in order, subject to
	// the candidate filter pipeline (sovereignty under eu_strict). All chain
	// members must share the provider's API family (the request body is
	// forwarded as-is except for an optional model rewrite).
	Fallback []FallbackTarget `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	// ResponsesStoreMode controls the OpenAI Responses API "store" field:
	// "preserve" (default) forwards client intent untouched — an explicit
	// store:false is honored for every client (#213); "force_if_absent" sets
	// store:true only when the field is missing (opt-in for
	// previous_response_id continuity, e.g. OpenClaw); "force_true" always
	// stores, recording any override of an explicit store:false in signed
	// evidence.
	ResponsesStoreMode string `yaml:"responses_store_mode,omitempty" json:"responses_store_mode,omitempty"` // preserve (default) | force_if_absent | force_true
	// InjectStreamUsage, when not false, adds stream_options.include_usage to
	// OpenAI chat-completions streaming requests so the upstream emits a final
	// usage chunk — otherwise streamed chat cost is estimate-only (#196).
	// nil = true (default). Set false to forward the client body unchanged.
	InjectStreamUsage *bool `yaml:"inject_stream_usage,omitempty" json:"inject_stream_usage,omitempty"`
}

// InjectsStreamUsage reports whether the gateway adds
// stream_options.include_usage to streaming chat requests for this provider.
// Default true when unset.
func (p ProviderConfig) InjectsStreamUsage() bool {
	return p.InjectStreamUsage == nil || *p.InjectStreamUsage
}

// FallbackTarget is one candidate in a provider's error-driven fallback chain.
type FallbackTarget struct {
	Provider string `yaml:"provider" json:"provider"`
	// Model, when set, replaces the "model" field of the forwarded JSON body
	// (the only rewrite performed; the wire format must already match).
	Model string `yaml:"model,omitempty" json:"model,omitempty"`
}

// providerAPIFamily resolves a provider's wire format: the explicit
// api_family config field wins; otherwise the name convention applies —
// "anthropic" uses the Anthropic Messages API, every other provider is
// treated as OpenAI-compatible (matching WriteProviderError).
func (c *GatewayConfig) providerAPIFamily(name string) string {
	if p, ok := c.Providers[name]; ok && p.APIFamily != "" {
		return p.APIFamily
	}
	if name == "anthropic" {
		return "anthropic"
	}
	return "openai"
}

// CallerConfig identifies an application or team that uses the gateway.
type CallerConfig struct {
	Name             string                 `yaml:"name" json:"name"`
	TenantKey        string                 `yaml:"tenant_key,omitempty" json:"tenant_key,omitempty"` // #nosec G117 -- auth identifier from config, not a hardcoded secret
	TenantID         string                 `yaml:"tenant_id" json:"tenant_id"`
	Team             string                 `yaml:"team,omitempty" json:"team,omitempty"`
	Tags             []string               `yaml:"tags,omitempty" json:"tags,omitempty"`               // e.g. ["copaw"] for OTel/dashboard classification
	IdentifyBy       string                 `yaml:"identify_by,omitempty" json:"identify_by,omitempty"` // "source_ip" for IP-based
	SourceIPRanges   []string               `yaml:"source_ip_ranges,omitempty" json:"source_ip_ranges,omitempty"`
	AllowedProviders []string               `yaml:"allowed_providers,omitempty" json:"allowed_providers,omitempty"`
	PolicyOverrides  *CallerPolicyOverrides `yaml:"policy_overrides,omitempty" json:"policy_overrides,omitempty"`
	// AcceptClientMetadata controls whether client-asserted orchestration
	// identity (session/subagent/parent, from x-claude-code-* / Codex / generic
	// X-Talon-* headers) is recorded in evidence for this caller. nil = true
	// (default). It gates recording only — identity is never a policy input in
	// v1 (evidence-only until attestation, #149). #194.
	AcceptClientMetadata *bool `yaml:"accept_client_metadata,omitempty" json:"accept_client_metadata,omitempty"`
}

// AcceptsClientMetadata reports whether client-asserted orchestration identity
// is recorded for this caller. Default is true when unset.
func (c *CallerConfig) AcceptsClientMetadata() bool {
	return c == nil || c.AcceptClientMetadata == nil || *c.AcceptClientMetadata
}

// CallerPolicyOverrides are per-caller policy overrides.
type CallerPolicyOverrides struct {
	MaxDailyCost   float64 `yaml:"max_daily_cost,omitempty" json:"max_daily_cost,omitempty"`
	MaxMonthlyCost float64 `yaml:"max_monthly_cost,omitempty" json:"max_monthly_cost,omitempty"`
	// MaxSessionCost is a soft cap on accumulated spend per coding session
	// (#198): a new request is denied once session spend + the pre-request
	// estimate exceeds it. In-flight requests can overshoot (atomic
	// reservation is #144). Applies only to client/vendor-asserted sessions.
	MaxSessionCost    float64                 `yaml:"max_session_cost,omitempty" json:"max_session_cost,omitempty"`
	PIIAction         string                  `yaml:"pii_action,omitempty" json:"pii_action,omitempty"`                   // block | redact | warn | allow
	ResponsePIIAction string                  `yaml:"response_pii_action,omitempty" json:"response_pii_action,omitempty"` // block | redact | warn | allow; inherits from pii_action
	AllowedModels     []string                `yaml:"allowed_models,omitempty" json:"allowed_models,omitempty"`
	BlockedModels     []string                `yaml:"blocked_models,omitempty" json:"blocked_models,omitempty"`
	MaxDataTier       *TierLevel              `yaml:"max_data_tier,omitempty" json:"max_data_tier,omitempty"` // 0/public, 1/internal, or 2/confidential
	AttachmentPolicy  *AttachmentPolicyConfig `yaml:"attachment_policy,omitempty" json:"attachment_policy,omitempty"`
	AllowedTools      []string                `yaml:"allowed_tools,omitempty" json:"allowed_tools,omitempty"`
	ForbiddenTools    []string                `yaml:"forbidden_tools,omitempty" json:"forbidden_tools,omitempty"`
	ToolPolicyAction  string                  `yaml:"tool_policy_action,omitempty" json:"tool_policy_action,omitempty"` // filter | block
	// Egress replaces the server default egress policy for this caller when set.
	Egress *EgressPolicyConfig `yaml:"egress,omitempty" json:"egress,omitempty"`
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

// ServerDefaults holds server-wide gateway defaults (PII action, cost limits,
// tool governance, attachment scanning). Lives in talon.config.yaml under
// gateway.default_policy. Not related to config.DefaultPolicy which is the
// agent policy filename (agent.talon.yaml).
type ServerDefaults struct {
	DefaultPIIAction        string                  `yaml:"default_pii_action" json:"default_pii_action"`                       // warn | block | redact | allow
	ResponsePIIAction       string                  `yaml:"response_pii_action,omitempty" json:"response_pii_action,omitempty"` // block | redact | warn | allow; inherits from default_pii_action
	MaxDailyCost            float64                 `yaml:"max_daily_cost" json:"max_daily_cost"`
	MaxMonthlyCost          float64                 `yaml:"max_monthly_cost" json:"max_monthly_cost"`
	RequireCallerID         *bool                   `yaml:"require_caller_id" json:"require_caller_id"` // nil = true (default)
	LogPrompts              bool                    `yaml:"log_prompts" json:"log_prompts"`
	LogResponses            bool                    `yaml:"log_responses" json:"log_responses"`
	LogResponsePreviewChars int                     `yaml:"log_response_preview_chars" json:"log_response_preview_chars"`
	AttachmentPolicy        *AttachmentPolicyConfig `yaml:"attachment_policy,omitempty" json:"attachment_policy,omitempty"`
	ForbiddenTools          []string                `yaml:"forbidden_tools,omitempty" json:"forbidden_tools,omitempty"`
	ToolPolicyAction        string                  `yaml:"tool_policy_action,omitempty" json:"tool_policy_action,omitempty"` // filter (default) | block
	// ScanToolContent controls the observation-only PII scan of tool-related
	// request content (tool_use inputs, tool_result outputs, function-call
	// arguments): "evidence_only" (default) records findings in evidence
	// without influencing enforcement; "off" disables the scan. Enforcement
	// on tool content is deliberately not offered until per-block-type tool
	// redaction exists (#212).
	ScanToolContent string `yaml:"scan_tool_content,omitempty" json:"scan_tool_content,omitempty"` // evidence_only (default) | off
	// Egress restricts which destinations (providers/regions) each data tier
	// may egress to. When nil, egress is not evaluated.
	Egress *EgressPolicyConfig `yaml:"egress,omitempty" json:"egress,omitempty"`
}

// ScanToolContent modes.
const (
	ScanToolContentEvidenceOnly = "evidence_only"
	ScanToolContentOff          = "off"
)

// CallerIDRequired returns whether anonymous requests must be rejected. Default is true when unset.
func (d *ServerDefaults) CallerIDRequired() bool {
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
	ConnectTimeout string `yaml:"connect_timeout" json:"connect_timeout"`
	RequestTimeout string `yaml:"request_timeout" json:"request_timeout"`
	// ResponseHeaderTimeout bounds the wait for upstream response headers
	// (time-to-first-byte) after the request is fully written. Non-streaming
	// LLM calls can legitimately take minutes before the first header, so
	// this defaults to request_timeout, not connect_timeout (#230).
	ResponseHeaderTimeout string `yaml:"response_header_timeout" json:"response_header_timeout"`
	StreamIdleTimeout     string `yaml:"stream_idle_timeout" json:"stream_idle_timeout"`
}

// ParsedTimeouts holds parsed time.Duration values for use at runtime.
type ParsedTimeouts struct {
	ConnectTimeout        time.Duration
	RequestTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	StreamIdleTimeout     time.Duration
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
	DefaultToolPolicyAction        = "filter" // "filter" removes disallowed tools; "block" rejects the request
	DefaultUpstreamAuthMode        = "secret"
)

// LoadGatewayConfig loads gateway configuration from a YAML file (typically talon.config.yaml).
// If the file has a top-level "gateway" key, that subtree is unmarshaled; otherwise the whole file is treated as GatewayConfig.
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
// applyDefaults fills zero-valued server-wide policy defaults.
func (d *ServerDefaults) applyDefaults() {
	if d.DefaultPIIAction == "" {
		d.DefaultPIIAction = DefaultPIIAction
	}
	if d.ScanToolContent == "" {
		d.ScanToolContent = ScanToolContentEvidenceOnly
	}
	if d.MaxDailyCost == 0 {
		d.MaxDailyCost = 100
	}
	if d.MaxMonthlyCost == 0 {
		d.MaxMonthlyCost = 2000
	}
}

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
	c.ServerDefaults.applyDefaults()
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
	// Default header wait to the operator's request budget: slow-TTFB
	// non-streaming calls must not be cut short of request_timeout (#230).
	if c.Timeouts.ResponseHeaderTimeout == "" {
		c.Timeouts.ResponseHeaderTimeout = c.Timeouts.RequestTimeout
	}
	if c.Timeouts.StreamIdleTimeout == "" {
		c.Timeouts.StreamIdleTimeout = DefaultStreamIdleTimeout
	}
	c.ServerDefaults.AttachmentPolicy = applyAttachmentPolicyDefaults(c.ServerDefaults.AttachmentPolicy)
	c.ServerDefaults.Egress.applyDefaults()
	normalizeProviderRegions(c.Providers)
	for i := range c.Callers {
		if ov := c.Callers[i].PolicyOverrides; ov != nil {
			ov.Egress.applyDefaults()
		}
	}
	return nil
}

func normalizeProviderRegions(providers map[string]ProviderConfig) {
	for name := range providers {
		p := providers[name]
		if p.Region != "" {
			p.Region = normalizeEgressRegion(p.Region)
		}
		for i := range p.Fallback {
			p.Fallback[i].Provider = strings.ToLower(strings.TrimSpace(p.Fallback[i].Provider))
		}
		p.APIFamily = strings.ToLower(strings.TrimSpace(p.APIFamily))
		providers[name] = p
	}
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
	switch c.ServerDefaults.ScanToolContent {
	case "", ScanToolContentEvidenceOnly, ScanToolContentOff:
	default:
		return fmt.Errorf("gateway default_policy scan_tool_content must be evidence_only or off")
	}
	for name := range c.Providers {
		p := c.Providers[name]
		if !p.Enabled {
			c.Providers[name] = p
			continue
		}
		if p.UpstreamAuthMode == "" {
			p.UpstreamAuthMode = DefaultUpstreamAuthMode
		}
		switch p.UpstreamAuthMode {
		case "secret", "client_bearer":
		default:
			return fmt.Errorf("gateway provider %q: upstream_auth_mode must be secret or client_bearer", name)
		}
		switch p.APIFamily {
		case "", "openai", "anthropic":
		default:
			return fmt.Errorf("gateway provider %q: api_family must be openai or anthropic", name)
		}
		if p.UpstreamAuthMode == "client_bearer" && (p.APIFamily == "anthropic" || name == "anthropic") {
			return fmt.Errorf("gateway provider %q: upstream_auth_mode client_bearer is not supported for the anthropic API family (Anthropic uses x-api-key, not bearer tokens)", name)
		}
		if p.BaseURL == "" && (name == "openai" || name == "anthropic" || name == "ollama") {
			return fmt.Errorf("gateway provider %q: base_url is required", name)
		}
		if name != "ollama" && p.UpstreamAuthMode == "secret" && p.SecretName == "" {
			return fmt.Errorf("gateway provider %q: secret_name is required", name)
		}
		switch p.ResponsesStoreMode {
		case "", ResponsesStorePreserve, ResponsesStoreForceIfAbsent, ResponsesStoreForceTrue:
		default:
			return fmt.Errorf("gateway provider %q: responses_store_mode must be preserve, force_if_absent, or force_true", name)
		}
		c.Providers[name] = p
	}
	for name := range c.Providers {
		p := c.Providers[name]
		if !p.Enabled {
			continue
		}
		if err := c.validateFallbackChain(name, p); err != nil {
			return err
		}
	}
	if p := c.ServerDefaults.AttachmentPolicy; p != nil {
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
	if err := validateEgressPolicy("default_policy", c.ServerDefaults.Egress); err != nil {
		return err
	}
	for i := range c.Callers {
		caller := &c.Callers[i]
		if caller.Name == "" {
			return fmt.Errorf("gateway caller at index %d: name is required", i)
		}
		if caller.PolicyOverrides != nil {
			if err := validateEgressPolicy("caller "+caller.Name, caller.PolicyOverrides.Egress); err != nil {
				return err
			}
		}
		if caller.TenantID == "" {
			caller.TenantID = "default"
		}
		if caller.IdentifyBy == "source_ip" {
			if len(caller.SourceIPRanges) == 0 {
				return fmt.Errorf("gateway caller %q: source_ip_ranges required when identify_by is source_ip", caller.Name)
			}
		} else if caller.TenantKey == "" && c.ServerDefaults.CallerIDRequired() {
			return fmt.Errorf("gateway caller %q: tenant_key or identify_by=source_ip with source_ip_ranges is required", caller.Name)
		}
	}
	return nil
}

// validateFallbackChain checks a provider's error-driven fallback chain at
// load time: every target must exist, be enabled, differ from the owner,
// appear at most once, and share the owner's API family (the body is
// forwarded verbatim apart from a model rewrite, so cross-family fallback
// would send an incompatible payload).
func (c *GatewayConfig) validateFallbackChain(owner string, p ProviderConfig) error {
	seen := map[string]bool{owner: true}
	family := c.providerAPIFamily(owner)
	for i, target := range p.Fallback {
		tname := strings.ToLower(strings.TrimSpace(target.Provider))
		if tname == "" {
			return fmt.Errorf("gateway provider %q: fallback[%d]: provider is required", owner, i)
		}
		if seen[tname] {
			return fmt.Errorf("gateway provider %q: fallback[%d]: duplicate or self-referencing target %q", owner, i, tname)
		}
		seen[tname] = true
		tp, ok := c.Providers[tname]
		if !ok || !tp.Enabled {
			return fmt.Errorf("gateway provider %q: fallback[%d]: target %q is not an enabled gateway provider", owner, i, tname)
		}
		if tf := c.providerAPIFamily(tname); tf != family {
			return fmt.Errorf("gateway provider %q: fallback[%d]: target %q API family %q does not match %q — fallback forwards the request body as-is (only the model field is rewritten)", owner, i, tname, tf, family)
		}
	}
	return nil
}

// ResolveCostCaps returns the effective daily and monthly cost caps for a
// caller: the server default, replaced by a per-caller override when that
// override is set (> 0). This is the single source of truth for "what cap does
// this caller actually run against" — budget enforcement (via the policy input,
// gateway_access.rego) and budget-utilization metrics/alerts must both read it,
// or the dashboard disagrees with what runtime enforced (#216).
func ResolveCostCaps(defaults *ServerDefaults, overrides *CallerPolicyOverrides) (daily, monthly float64) {
	daily, monthly = defaults.MaxDailyCost, defaults.MaxMonthlyCost
	if overrides == nil {
		return daily, monthly
	}
	if overrides.MaxDailyCost > 0 {
		daily = overrides.MaxDailyCost
	}
	if overrides.MaxMonthlyCost > 0 {
		monthly = overrides.MaxMonthlyCost
	}
	return daily, monthly
}

// ResolveAttachmentPolicy returns the effective attachment policy for a caller,
// merging caller overrides on top of the server default.
func ResolveAttachmentPolicy(defaultPolicy *ServerDefaults, overrides *CallerPolicyOverrides) *AttachmentPolicyConfig {
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

// ToolPolicyResolution holds the resolved tool governance parameters from the
// three-level config hierarchy (default → provider → caller).
type ToolPolicyResolution struct {
	AllowedTools   []string // Most-specific non-empty list wins; empty = allow all.
	ForbiddenTools []string // Union across all levels (additive).
	Action         string   // "filter" (default) or "block".
}

// ResolveToolPolicy merges tool governance config from default policy, provider,
// and caller overrides. allowed_tools: most-specific non-empty list wins.
// forbidden_tools: union of all levels. action: most-specific wins.
func ResolveToolPolicy(dp *ServerDefaults, prov ProviderConfig, overrides *CallerPolicyOverrides) ToolPolicyResolution {
	res := ToolPolicyResolution{Action: DefaultToolPolicyAction}

	// Action: most-specific wins (caller > provider > default).
	if dp.ToolPolicyAction != "" {
		res.Action = dp.ToolPolicyAction
	}
	if prov.ToolPolicyAction != "" {
		res.Action = prov.ToolPolicyAction
	}
	if overrides != nil && overrides.ToolPolicyAction != "" {
		res.Action = overrides.ToolPolicyAction
	}

	// Allowed tools: most-specific non-empty list wins.
	if overrides != nil && len(overrides.AllowedTools) > 0 {
		res.AllowedTools = overrides.AllowedTools
	}

	// Forbidden tools: union across all levels.
	seen := make(map[string]bool)
	for _, lists := range [][]string{
		dp.ForbiddenTools,
		prov.ForbiddenTools,
	} {
		for _, f := range lists {
			if !seen[f] {
				seen[f] = true
				res.ForbiddenTools = append(res.ForbiddenTools, f)
			}
		}
	}
	if overrides != nil {
		for _, f := range overrides.ForbiddenTools {
			if !seen[f] {
				seen[f] = true
				res.ForbiddenTools = append(res.ForbiddenTools, f)
			}
		}
	}
	return res
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
	if c.Timeouts.ResponseHeaderTimeout == "" {
		pt.ResponseHeaderTimeout = pt.RequestTimeout
	} else {
		pt.ResponseHeaderTimeout, err = time.ParseDuration(c.Timeouts.ResponseHeaderTimeout)
		if err != nil {
			return pt, fmt.Errorf("response_header_timeout %q: %w", c.Timeouts.ResponseHeaderTimeout, err)
		}
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

// UniqueTenantIDs returns distinct tenant_id values from configured callers.
func (c *GatewayConfig) UniqueTenantIDs() []string {
	seen := make(map[string]struct{})
	for i := range c.Callers {
		id := strings.TrimSpace(c.Callers[i].TenantID)
		if id == "" {
			id = "default"
		}
		seen[id] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// MetricsTenantScope returns the tenant_id filter for dashboard SQL aggregates.
// Single-tenant gateways scope to that tenant; multi-tenant gateways use "" (all tenants).
func (c *GatewayConfig) MetricsTenantScope() string {
	ids := c.UniqueTenantIDs()
	if len(ids) == 1 {
		return ids[0]
	}
	return ""
}

// TenantKeyMap returns a map of tenant_key -> tenant_id from configured callers.
func (c *GatewayConfig) TenantKeyMap() map[string]string {
	m := make(map[string]string)
	for i := range c.Callers {
		caller := c.Callers[i]
		key := strings.TrimSpace(caller.TenantKey)
		if key == "" {
			continue
		}
		tenantID := caller.TenantID
		if tenantID == "" {
			tenantID = "default"
		}
		m[key] = tenantID
	}
	return m
}

// Provider returns the provider config for the given provider name (e.g. "openai", "anthropic", "ollama").
func (c *GatewayConfig) Provider(name string) (ProviderConfig, bool) {
	p, ok := c.Providers[name]
	return p, ok
}

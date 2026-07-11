// Package gateway implements the LLM API Gateway — a provider-compatible
// reverse proxy that adds PII scanning, policy enforcement, cost governance,
// and immutable audit trails.
package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
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
// (infrastructure config, owned by DevOps/platform team). Traffic identity is
// NOT configured here: agents are defined in agent.talon.yaml files and
// resolved through the IdentityRegistry (#266).
//
//revive:disable-next-line:exported
type GatewayConfig struct {
	Enabled      bool                      `yaml:"enabled" json:"enabled"`
	ListenPrefix string                    `yaml:"listen_prefix" json:"listen_prefix"`
	Mode         Mode                      `yaml:"mode" json:"mode"`
	Providers    map[string]ProviderConfig `yaml:"providers" json:"providers"`
	// OrganizationPolicy is the organization baseline — the shared policy
	// every agent inherits before its one explicit override applies.
	OrganizationPolicy  OrganizationPolicy         `yaml:"organization_policy" json:"organization_policy"`
	ResponseScanning    ResponseScanningConfig     `yaml:"response_scanning" json:"response_scanning"`
	RateLimits          RateLimitsConfig           `yaml:"rate_limits" json:"rate_limits"`
	Timeouts            TimeoutsConfig             `yaml:"timeouts" json:"timeouts"`
	NetworkInterception *NetworkInterceptionConfig `yaml:"network_interception,omitempty" json:"network_interception,omitempty"`
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

	// quickstartProfile marks a config built in-process for --proxy-quickstart
	// (see QuickstartConfig / EnableQuickstartProfile). Only that profile may
	// use upstream_auth_mode client_bearer: in a normal gateway the presented
	// bearer is a TALON AGENT KEY, and client_bearer would forward it verbatim
	// to the upstream provider (#266 review). Unexported and untagged —
	// structurally impossible to set from YAML.
	quickstartProfile bool
}

// EnableQuickstartProfile marks this config as the in-process quickstart
// profile, unlocking upstream_auth_mode client_bearer in Validate. Callers:
// QuickstartConfig and the quickstart facade tests — never YAML-loaded configs.
func (c *GatewayConfig) EnableQuickstartProfile() { c.quickstartProfile = true }

// ProviderConfig holds per-provider gateway settings.
type ProviderConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	SecretName string `yaml:"secret_name,omitempty" json:"secret_name,omitempty"`
	// UpstreamAuthMode controls how Talon authenticates to the upstream provider.
	// "secret" (default) reads provider credentials from Talon's secret store.
	// "client_bearer" forwards the agent bearer token upstream and is intended
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

// AttachmentPolicyConfig controls scanning of base64-encoded file attachments
// embedded in LLM API requests (PDFs, images, HTML, etc.).
type AttachmentPolicyConfig struct {
	Action          string   `yaml:"action" json:"action"`                                         // block | strip | warn | allow (default: warn)
	InjectionAction string   `yaml:"injection_action,omitempty" json:"injection_action,omitempty"` // block | strip | warn (default: warn)
	MaxFileSizeMB   int      `yaml:"max_file_size_mb,omitempty" json:"max_file_size_mb,omitempty"` // default: 10
	AllowedTypes    []string `yaml:"allowed_types,omitempty" json:"allowed_types,omitempty"`
	BlockedTypes    []string `yaml:"blocked_types,omitempty" json:"blocked_types,omitempty"`
}

// OrganizationPolicy is the organization baseline (PII action, cost limits,
// tool governance, attachment scanning) — the shared policy every agent
// inherits before its one explicit override applies (#266). Lives in
// talon.config.yaml under gateway.organization_policy.
type OrganizationPolicy struct {
	DefaultPIIAction        string                  `yaml:"default_pii_action" json:"default_pii_action"`                       // warn | block | redact | allow
	ResponsePIIAction       string                  `yaml:"response_pii_action,omitempty" json:"response_pii_action,omitempty"` // block | redact | warn | allow; inherits from default_pii_action
	MaxDailyCost            float64                 `yaml:"max_daily_cost" json:"max_daily_cost"`
	MaxMonthlyCost          float64                 `yaml:"max_monthly_cost" json:"max_monthly_cost"`
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

	// Organization-wide HARD CONSTRAINTS (#266): unlike the baselines above,
	// these are not replaced by an agent's override — an agent may only
	// narrow further within them.
	//
	// AllowedProviders limits which gateway providers ANY agent may reach
	// (empty = all enabled providers).
	AllowedProviders []string `yaml:"allowed_providers,omitempty" json:"allowed_providers,omitempty"`
	// AllowedModels / BlockedModels bound the model space for every agent
	// (empty allowed list = no allowlist constraint).
	AllowedModels []string `yaml:"allowed_models,omitempty" json:"allowed_models,omitempty"`
	BlockedModels []string `yaml:"blocked_models,omitempty" json:"blocked_models,omitempty"`
	// MaxDataTier caps the request data tier organization-wide; an agent's
	// max_data_tier can only lower it further. nil = no org cap.
	MaxDataTier *TierLevel `yaml:"max_data_tier,omitempty" json:"max_data_tier,omitempty"`
}

// ScanToolContent modes.
const (
	ScanToolContentEvidenceOnly = "evidence_only"
	ScanToolContentOff          = "off"
)

// ResponseScanningConfig controls scanning LLM responses for PII (Phase 2).
type ResponseScanningConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// RateLimitsConfig holds gateway rate limits.
type RateLimitsConfig struct {
	GlobalRequestsPerMin   int `yaml:"global_requests_per_min" json:"global_requests_per_min"`
	PerAgentRequestsPerMin int `yaml:"per_agent_requests_per_min" json:"per_agent_requests_per_min"`
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
	DefaultLogPrompts              = true
	DefaultPIIAction               = "warn"
	DefaultGlobalRPM               = 300
	DefaultPerAgentRPM             = 60
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

	gatewayRaw := raw
	if g, ok := raw["gateway"]; ok {
		if m, ok := g.(map[string]interface{}); ok {
			gatewayRaw = m
		}
	}

	// Removed config surfaces get an explicit, friendly breaking-change error
	// BEFORE strict decoding — a config written for the legacy caller model
	// must name its replacement, not die on a generic unknown-field error (#266).
	if err := rejectLegacyGatewayKeys(gatewayRaw); err != nil {
		return nil, err
	}

	var cfg GatewayConfig
	if g, ok := raw["gateway"]; ok {
		// Strict decoding (#266 review): organization_policy and provider
		// entries enforce security boundaries, so a typo'd key (e.g.
		// "allowed_provider") must fail loudly instead of silently disabling
		// an intended hard constraint. KnownFields rejects every unknown key
		// in the gateway subtree.
		sub, _ := yaml.Marshal(g)
		dec := yaml.NewDecoder(bytes.NewReader(sub))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("unmarshaling gateway block (unknown keys are rejected — see schemas/talon.config.schema.json for the accepted surface): %w", err)
		}
	} else {
		// Legacy top-level layout (no gateway: block): kept permissive — it
		// yields a disabled gateway config; serve --gateway then refuses to
		// start. The documented layout is the strict gateway: subtree above.
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

// rejectLegacyGatewayKeys fails closed on configuration written for the
// removed agent identity model. Breaking change (#266): traffic identity
// lives in agent.talon.yaml (agent.key.secret_name); the baseline block is
// gateway.organization_policy.
func rejectLegacyGatewayKeys(gatewayRaw map[string]interface{}) error {
	if gatewayRaw == nil {
		return nil
	}
	legacy := map[string]string{
		"callers":             "define one agent.talon.yaml per AI use case with agent.key.secret_name instead",
		"default_policy":      "the organization baseline moved to gateway.organization_policy",
		"trusted_proxy_cidrs": "source-IP identity was removed; every request authenticates with an agent key",
	}
	for key, hint := range legacy {
		if _, present := gatewayRaw[key]; present {
			return fmt.Errorf("gateway config uses removed key %q — %s (breaking change, see #266)", key, hint)
		}
	}
	if op, ok := gatewayRaw["organization_policy"].(map[string]interface{}); ok {
		if _, present := op["require_caller_id"]; present {
			return fmt.Errorf("gateway config uses removed key \"organization_policy.require_caller_id\" — unknown keys are always rejected; quickstart mode is the only keyless path (breaking change, see #266)")
		}
	}
	if rl, ok := gatewayRaw["rate_limits"].(map[string]interface{}); ok {
		if _, present := rl["per_caller_requests_per_min"]; present {
			return fmt.Errorf("gateway config uses removed key \"rate_limits.per_caller_requests_per_min\" — use per_agent_requests_per_min (breaking change, see #266)")
		}
	}
	return nil
}

// ApplyDefaults sets default values for missing fields.
// applyDefaults fills zero-valued organization baseline defaults.
func (d *OrganizationPolicy) applyDefaults() {
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
	c.OrganizationPolicy.applyDefaults()
	if c.RateLimits.GlobalRequestsPerMin == 0 {
		c.RateLimits.GlobalRequestsPerMin = DefaultGlobalRPM
	}
	if c.RateLimits.PerAgentRequestsPerMin == 0 {
		c.RateLimits.PerAgentRequestsPerMin = DefaultPerAgentRPM
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
	c.OrganizationPolicy.AttachmentPolicy = applyAttachmentPolicyDefaults(c.OrganizationPolicy.AttachmentPolicy)
	c.OrganizationPolicy.Egress.applyDefaults()
	normalizeProviderRegions(c.Providers)
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
	switch c.OrganizationPolicy.ScanToolContent {
	case "", ScanToolContentEvidenceOnly, ScanToolContentOff:
	default:
		return fmt.Errorf("gateway organization_policy scan_tool_content must be evidence_only or off")
	}
	if t := c.OrganizationPolicy.MaxDataTier; t != nil && (*t < 0 || *t > 2) {
		return fmt.Errorf("gateway organization_policy.max_data_tier must be 0, 1, or 2, got %d", int(*t))
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
		if p.UpstreamAuthMode == "client_bearer" && !c.quickstartProfile {
			return fmt.Errorf("gateway provider %q: upstream_auth_mode client_bearer is only available in --proxy-quickstart mode — in a normal gateway the presented bearer is a Talon agent key and client_bearer would forward it to the upstream provider; use secret with secret_name instead (#266)", name)
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
	if p := c.OrganizationPolicy.AttachmentPolicy; p != nil {
		switch p.Action {
		case "block", "strip", "warn", "allow":
		default:
			return fmt.Errorf("gateway organization_policy.attachment_policy.action must be block, strip, warn, or allow")
		}
		switch p.InjectionAction {
		case "block", "strip", "warn", "":
		default:
			return fmt.Errorf("gateway organization_policy.attachment_policy.injection_action must be block, strip, or warn")
		}
	}
	return validateEgressPolicy("organization_policy", c.OrganizationPolicy.Egress)
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

// Provider returns the provider config for the given provider name (e.g. "openai", "anthropic", "ollama").
func (c *GatewayConfig) Provider(name string) (ProviderConfig, bool) {
	p, ok := c.Providers[name]
	return p, ok
}

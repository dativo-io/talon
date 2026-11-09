package console

import (
	"context"
	"errors"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/mcp"
	"github.com/dativo-io/talon/internal/policy"
)

// ConfigSources names the configuration files the console reads for the
// Configuration page (#543). They are the files the operator pointed the
// console process at, never paths taken from a request.
type ConfigSources struct {
	AgentsDir     string
	DefaultPolicy string
	GatewayConfig string
	ProxyConfig   string // optional; "" means not configured for this console
}

// Configuration is the Configuration page: semantic summaries of the
// configuration files as they read NOW. Every field is copied from an
// explicit allowlist of parsed values; credentials, secret values, webhook
// URLs and URL user-info/paths/queries are never copied (a secret NAME is a
// vault reference and is shown). File contents are not proof of what a
// running process enforces: ActiveGeneration stays unknown until the runtime
// probe (#538), EffectivePolicy until the provenance contract (#305).
type Configuration struct {
	Meta             Meta                 `json:"meta"`
	ReadAt           time.Time            `json:"read_at"`
	Organization     OrganizationConfig   `json:"organization"`
	UseCases         UseCaseConfigList    `json:"use_cases"`
	MCPProxy         ProxyConfigView      `json:"mcp_proxy"`
	EffectivePolicy  Availability         `json:"effective_policy"`
	ActiveGeneration Availability         `json:"active_generation"`
	Issues           []ConfigurationIssue `json:"issues,omitempty"`
}

// ConfigurationIssue is a configuration file that could not be used.
type ConfigurationIssue struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// OrganizationConfig summarises the gateway file's organization policy and
// providers.
type OrganizationConfig struct {
	Availability Availability `json:"availability"`
	SourcePath   string       `json:"source_path,omitempty"`

	PIIAction         string   `json:"pii_action,omitempty"`
	ResponsePIIAction string   `json:"response_pii_action,omitempty"`
	DailyCost         float64  `json:"daily_cost,omitempty"`
	MonthlyCost       float64  `json:"monthly_cost,omitempty"`
	SessionCost       float64  `json:"session_cost,omitempty"`
	ToolPolicyAction  string   `json:"tool_policy_action,omitempty"`
	Retry             *Retry   `json:"retry,omitempty"`
	AllowedProviders  []string `json:"allowed_providers,omitempty"`
	AllowedModels     []string `json:"allowed_models,omitempty"`
	BlockedModels     []string `json:"blocked_models,omitempty"`
	AllowedTools      []string `json:"allowed_tools,omitempty"`
	ForbiddenTools    []string `json:"forbidden_tools,omitempty"`
	MaxDailyCost      float64  `json:"max_daily_cost,omitempty"`
	MaxMonthlyCost    float64  `json:"max_monthly_cost,omitempty"`
	MaxSessionCost    float64  `json:"max_session_cost,omitempty"`
	LogPrompts        bool     `json:"log_prompts"`
	LogResponses      bool     `json:"log_responses"`
	CostWebhook       bool     `json:"cost_webhook_configured"`

	Providers []ProviderView `json:"providers,omitempty"`
}

// Retry is a retry policy.
type Retry struct {
	MaxAttempts    int    `json:"max_attempts"`
	InitialBackoff string `json:"initial_backoff,omitempty"`
	MaxBackoff     string `json:"max_backoff,omitempty"`
}

// ProviderView is one configured provider without credentials.
type ProviderView struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	Endpoint         string   `json:"endpoint,omitempty"` // scheme://host only
	Region           string   `json:"region,omitempty"`
	SecretName       string   `json:"secret_name,omitempty"` // vault reference, never the value
	AuthMode         string   `json:"upstream_auth_mode,omitempty"`
	AllowedModels    []string `json:"allowed_models,omitempty"`
	BlockedModels    []string `json:"blocked_models,omitempty"`
	ForbiddenTools   []string `json:"forbidden_tools,omitempty"`
	ToolPolicyAction string   `json:"tool_policy_action,omitempty"`
	Fallback         []string `json:"fallback,omitempty"` // provider[/model]
}

// UseCaseConfigList is every discovered agent file.
type UseCaseConfigList struct {
	Availability Availability    `json:"availability"`
	Source       string          `json:"source,omitempty"` // agents_dir or the default policy file
	Items        []UseCaseConfig `json:"items"`
}

// UseCaseConfig summarises one agent.talon.yaml (one AI use case).
type UseCaseConfig struct {
	Name         string `json:"name"`
	TenantID     string `json:"tenant_id"`
	Description  string `json:"description,omitempty"`
	Version      string `json:"version,omitempty"`
	Enabled      bool   `json:"enabled"`
	SourcePath   string `json:"source_path"`
	PolicyDigest string `json:"policy_digest,omitempty"`
	KeySecret    string `json:"key_secret_name,omitempty"` // vault reference
	ModelTier    int    `json:"model_tier"`

	AllowedProviders []string    `json:"allowed_providers,omitempty"`
	AllowedModels    []string    `json:"allowed_models,omitempty"`
	BlockedModels    []string    `json:"blocked_models,omitempty"`
	ModelRouting     []TierRoute `json:"model_routing,omitempty"`
	Retry            *Retry      `json:"retry,omitempty"`

	CostPerRequest float64 `json:"cost_per_request,omitempty"`
	CostDaily      float64 `json:"cost_daily,omitempty"`
	CostMonthly    float64 `json:"cost_monthly,omitempty"`
	SessionMaxCost float64 `json:"session_max_cost,omitempty"`
	BudgetWebhook  bool    `json:"budget_alert_webhook_configured"`

	RequestsPerMinute    int `json:"requests_per_minute,omitempty"`
	ConcurrentExecutions int `json:"concurrent_executions,omitempty"`

	AllowedTools     []string `json:"allowed_tools,omitempty"`
	ForbiddenTools   []string `json:"forbidden_tools,omitempty"`
	ToolPolicyAction string   `json:"tool_policy_action,omitempty"`

	InputScan  bool `json:"input_scan"`
	OutputScan bool `json:"output_scan"`
	RedactPII  bool `json:"redact_pii"`
	BlockOnPII bool `json:"block_on_pii"`

	AuditLogLevel         string `json:"audit_log_level,omitempty"`
	AuditRetentionDays    int    `json:"audit_retention_days,omitempty"`
	AuditIncludePrompts   bool   `json:"audit_include_prompts"`
	AuditIncludeResponses bool   `json:"audit_include_responses"`

	UseCase *UseCaseRecord `json:"use_case,omitempty"`
}

// UseCaseRecord is the optional operating record of an agent file.
type UseCaseRecord struct {
	Purpose        string `json:"purpose,omitempty"`
	Department     string `json:"department,omitempty"`
	Criticality    string `json:"criticality,omitempty"`
	OwnerBusiness  string `json:"owner_business,omitempty"`
	OwnerTechnical string `json:"owner_technical,omitempty"`
}

// TierRoute is one model routing tier.
type TierRoute struct {
	Tier          int      `json:"tier"`
	Primary       string   `json:"primary,omitempty"`
	Fallback      string   `json:"fallback,omitempty"`
	FallbackChain []string `json:"fallback_chain,omitempty"`
	Location      string   `json:"location,omitempty"`
}

// ProxyConfigView summarises the MCP proxy file.
type ProxyConfigView struct {
	Availability      Availability `json:"availability"`
	SourcePath        string       `json:"source_path,omitempty"`
	Name              string       `json:"name,omitempty"`
	Vendor            string       `json:"vendor,omitempty"`
	Endpoint          string       `json:"endpoint,omitempty"` // scheme://host only
	Region            string       `json:"region,omitempty"`
	AuthSecretName    string       `json:"auth_secret_name,omitempty"`
	AllowedTools      []string     `json:"allowed_tools,omitempty"`
	ForbiddenTools    []string     `json:"forbidden_tools,omitempty"`
	RequestsPerMinute int          `json:"requests_per_minute,omitempty"`
}

const configNote = "contents of the configuration files as they read now; not proof that a running process loaded them"

// Configuration builds the Configuration page. tenant "" lists every use case.
func (s *Service) Configuration(ctx context.Context, tenant string) *Configuration {
	now := s.now()
	out := &Configuration{
		Meta:   s.meta(tenant),
		ReadAt: now,
		EffectivePolicy: Availability{
			State: StateUnknown, Source: SourceNone,
			Note: "effective-policy provenance not available: owned by #305; values are not merged from YAML here",
		},
		ActiveGeneration: runtimeUnknown().Availability,
	}
	src := s.cfg.ConfigSources
	out.Organization = organizationView(src.GatewayConfig, now)
	out.UseCases, out.Issues = useCaseConfigs(ctx, src, tenant, now)
	out.MCPProxy = proxyView(ctx, src.ProxyConfig, now)
	return out
}

func organizationView(path string, now time.Time) OrganizationConfig {
	out := OrganizationConfig{SourcePath: path}
	if path == "" {
		out.Availability = Availability{State: StateUnknown, Source: SourceNone, Note: "no gateway config is configured for this console"}
		return out
	}
	gw, err := gateway.LoadGatewayConfig(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		out.Availability = Availability{State: StateEmpty, Source: SourceConfigFiles, AsOf: now, Note: "no gateway config file: agent-only installation"}
		return out
	case err != nil:
		out.Availability = Availability{State: StateUnavailable, Source: SourceConfigFiles, AsOf: now, Error: err.Error()}
		return out
	}
	org := gw.OrganizationPolicy
	d, c := org.Defaults, org.Constraints
	out.PIIAction, out.ResponsePIIAction = d.PIIAction, d.ResponsePIIAction
	out.DailyCost, out.MonthlyCost, out.SessionCost = d.DailyCost, d.MonthlyCost, d.SessionCost
	out.ToolPolicyAction = d.ToolPolicyAction
	if d.Retry != nil {
		out.Retry = &Retry{MaxAttempts: d.Retry.MaxAttempts, InitialBackoff: d.Retry.InitialBackoff, MaxBackoff: d.Retry.MaxBackoff}
	}
	out.AllowedProviders, out.AllowedModels, out.BlockedModels = c.AllowedProviders, c.AllowedModels, c.BlockedModels
	out.AllowedTools, out.ForbiddenTools = c.AllowedTools, c.ForbiddenTools
	out.MaxDailyCost, out.MaxMonthlyCost, out.MaxSessionCost = c.MaxDailyCost, c.MaxMonthlyCost, c.MaxSessionCost
	out.LogPrompts, out.LogResponses = org.LogPrompts, org.LogResponses
	out.CostWebhook = strings.TrimSpace(org.CostWebhookURL) != ""
	names := make([]string, 0, len(gw.Providers))
	for n := range gw.Providers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := gw.Providers[n]
		v := ProviderView{
			Name: n, Enabled: p.Enabled, Endpoint: endpointOnly(p.BaseURL), Region: p.Region,
			SecretName: p.SecretName, AuthMode: p.UpstreamAuthMode,
			AllowedModels: p.AllowedModels, BlockedModels: p.BlockedModels,
			ForbiddenTools: p.ForbiddenTools, ToolPolicyAction: p.ToolPolicyAction,
		}
		for _, f := range p.Fallback {
			target := f.Provider
			if f.Model != "" {
				target += "/" + f.Model
			}
			v.Fallback = append(v.Fallback, target)
		}
		out.Providers = append(out.Providers, v)
	}
	out.Availability = Availability{State: StateOK, Source: SourceConfigFiles, AsOf: now, Note: configNote}
	return out
}

func useCaseConfigs(ctx context.Context, src ConfigSources, tenant string, now time.Time) (UseCaseConfigList, []ConfigurationIssue) {
	out := UseCaseConfigList{Items: []UseCaseConfig{}}
	if src.AgentsDir == "" && src.DefaultPolicy == "" {
		out.Availability = Availability{State: StateUnknown, Source: SourceNone, Note: "no agent configuration source is configured for this console"}
		return out, nil
	}
	scan, err := fleetview.Scan(ctx, src.AgentsDir, src.DefaultPolicy)
	if err != nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceConfigFiles, AsOf: now, Error: err.Error()}
		return out, nil
	}
	out.Source = scan.Source
	var issues []ConfigurationIssue
	for _, is := range scan.Issues {
		issues = append(issues, ConfigurationIssue{Path: is.Path, Status: is.Status, Reason: is.Reason})
	}
	for i := range scan.Agents {
		a := scan.Agents[i]
		if tenant != "" && a.TenantID != tenant {
			continue
		}
		out.Items = append(out.Items, useCaseConfig(a.Name, a.TenantID, a.Path, a.PolicyDigest, a.Enabled, a.Policy))
	}
	sort.Slice(out.Items, func(i, j int) bool { return out.Items[i].Name < out.Items[j].Name })
	out.Availability = Availability{State: StateOK, Source: SourceConfigFiles, AsOf: now, Note: configNote}
	if len(out.Items) == 0 {
		out.Availability.State = StateEmpty
	}
	return out, issues
}

func useCaseConfig(name, tenant, path, digest string, enabled bool, p *policy.Policy) UseCaseConfig {
	v := UseCaseConfig{Name: name, TenantID: tenant, SourcePath: path, PolicyDigest: digest, Enabled: enabled}
	if p == nil {
		return v
	}
	v.Description, v.Version, v.ModelTier = p.Agent.Description, p.Agent.Version, p.Agent.ModelTier
	if p.Agent.Key != nil {
		v.KeySecret = p.Agent.Key.SecretName
	}
	if uc := p.Agent.UseCase; uc != nil {
		v.UseCase = &UseCaseRecord{Purpose: uc.Purpose, Department: uc.Department, Criticality: uc.Criticality}
		if uc.Owners != nil {
			v.UseCase.OwnerBusiness, v.UseCase.OwnerTechnical = uc.Owners.Business, uc.Owners.Technical
		}
	}
	routingView(p, &v)
	limitsView(p, &v)
	return v
}

// routingView copies providers, models, routing tiers and retries.
func routingView(p *policy.Policy, v *UseCaseConfig) {
	pol := p.Policies
	v.AllowedProviders = pol.AllowedProviders
	if pol.Models != nil {
		v.AllowedModels, v.BlockedModels = pol.Models.Allowed, pol.Models.Blocked
	}
	if mr := pol.ModelRouting; mr != nil {
		for tier, tc := range []*policy.TierConfig{mr.Tier0, mr.Tier1, mr.Tier2} {
			if tc != nil {
				v.ModelRouting = append(v.ModelRouting, TierRoute{Tier: tier, Primary: tc.Primary, Fallback: tc.Fallback, FallbackChain: tc.FallbackChain, Location: tc.Location})
			}
		}
	}
	if r := pol.Retries; r != nil {
		v.Retry = &Retry{MaxAttempts: r.MaxAttempts, InitialBackoff: r.InitialBackoff, MaxBackoff: r.MaxBackoff}
	}
}

// limitsView copies cost, session and rate limits, tools, data and audit settings.
func limitsView(p *policy.Policy, v *UseCaseConfig) {
	pol := p.Policies
	if cl := pol.CostLimits; cl != nil {
		v.CostPerRequest, v.CostDaily, v.CostMonthly = cl.PerRequest, cl.Daily, cl.Monthly
		v.BudgetWebhook = strings.TrimSpace(cl.BudgetAlertWebhook) != ""
	}
	if sl := pol.SessionLimits; sl != nil {
		v.SessionMaxCost = sl.MaxCost
	}
	if rl := pol.RateLimits; rl != nil {
		v.RequestsPerMinute, v.ConcurrentExecutions = rl.RequestsPerMinute, rl.ConcurrentExecutions
	}
	if c := p.Capabilities; c != nil {
		v.AllowedTools, v.ForbiddenTools, v.ToolPolicyAction = c.AllowedTools, c.ForbiddenTools, c.ToolPolicyAction
	}
	if dc := pol.DataClassification; dc != nil {
		v.InputScan, v.OutputScan, v.RedactPII, v.BlockOnPII = dc.InputScan, dc.OutputScan, dc.RedactPII, dc.BlockOnPII
	}
	if a := p.Audit; a != nil {
		v.AuditLogLevel, v.AuditRetentionDays = a.LogLevel, a.RetentionDays
		v.AuditIncludePrompts, v.AuditIncludeResponses = a.IncludePrompts, a.IncludeResponses
	}
}

func proxyView(ctx context.Context, path string, now time.Time) ProxyConfigView {
	out := ProxyConfigView{SourcePath: path}
	if path == "" {
		out.Availability = Availability{State: StateUnknown, Source: SourceNone, Note: "no MCP proxy config is configured for this console (talon ui serve --proxy-config)"}
		return out
	}
	cfg, err := mcp.LoadProxyConfig(ctx, path)
	if err != nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceConfigFiles, AsOf: now, Error: err.Error()}
		return out
	}
	px := cfg.Proxy
	out.Name, out.Vendor, out.Region = cfg.Agent.Name, px.Upstream.Vendor, px.Upstream.Region
	out.Endpoint = endpointOnly(px.Upstream.URL)
	if px.Upstream.Auth != nil {
		out.AuthSecretName = px.Upstream.Auth.SecretName
	}
	for _, t := range px.AllowedTools {
		out.AllowedTools = append(out.AllowedTools, t.Name)
	}
	out.ForbiddenTools = px.ForbiddenTools
	out.RequestsPerMinute = px.RateLimits.RequestsPerMinute
	out.Availability = Availability{State: StateOK, Source: SourceConfigFiles, AsOf: now, Note: configNote}
	return out
}

// endpointOnly reduces a configured URL to scheme://host[:port]: user-info,
// path, query and fragment can carry credentials or tokens and are dropped.
func endpointOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(not a URL)"
	}
	return u.Scheme + "://" + u.Host
}

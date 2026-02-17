package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// ---------------------------------------------------------------------------
// Proxy policy configuration types
// ---------------------------------------------------------------------------

// ProxyPolicyConfig represents a .talon.yaml for MCP proxy mode.
type ProxyPolicyConfig struct {
	Agent       ProxyAgentConfig  `yaml:"agent" json:"agent"`
	Proxy       ProxyConfig       `yaml:"proxy" json:"proxy"`
	PIIHandling PIIHandlingConfig `yaml:"pii_handling,omitempty" json:"pii_handling,omitempty"`
	Compliance  ComplianceConfig  `yaml:"compliance,omitempty" json:"compliance,omitempty"`
}

// ProxyAgentConfig holds the agent identity for proxy configs.
type ProxyAgentConfig struct {
	Name        string `yaml:"name" json:"name"`
	Type        string `yaml:"type" json:"type"` // must be "mcp_proxy"
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Version     string `yaml:"version,omitempty" json:"version,omitempty"`
}

// ProxyConfig defines the MCP proxy behaviour.
type ProxyConfig struct {
	Mode           string             `yaml:"mode,omitempty" json:"mode,omitempty"` // intercept | passthrough | shadow
	Upstream       UpstreamConfig     `yaml:"upstream" json:"upstream"`
	AllowedTools   []ToolMapping      `yaml:"allowed_tools" json:"allowed_tools"`
	ForbiddenTools []string           `yaml:"forbidden_tools,omitempty" json:"forbidden_tools,omitempty"`
	RateLimits     ProxyRateLimitConfig `yaml:"rate_limits,omitempty" json:"rate_limits,omitempty"`
}

// UpstreamConfig identifies the upstream vendor endpoint.
type UpstreamConfig struct {
	Vendor string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	URL    string `yaml:"url" json:"url"`
}

// ToolMapping maps a Talon-facing tool name to the vendor's upstream name.
type ToolMapping struct {
	Name         string `yaml:"name" json:"name"`
	UpstreamName string `yaml:"upstream_name,omitempty" json:"upstream_name,omitempty"`
}

// PIIHandlingConfig defines PII redaction rules for proxy mode.
type PIIHandlingConfig struct {
	RedactionRules []RedactionRule `yaml:"redaction_rules,omitempty" json:"redaction_rules,omitempty"`
}

// RedactionRule specifies how a PII field should be redacted.
type RedactionRule struct {
	Field    string   `yaml:"field" json:"field"`
	Method   string   `yaml:"method" json:"method"` // hash | mask_middle | redact_full | mask
	Patterns []string `yaml:"patterns,omitempty" json:"patterns,omitempty"`
}

// ProxyRateLimitConfig constrains proxy request throughput.
type ProxyRateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute,omitempty" json:"requests_per_minute,omitempty"`
}

// ProxyInput is the runtime input provided when evaluating proxy policies.
type ProxyInput struct {
	ToolName       string                 `json:"tool_name"`
	Vendor         string                 `json:"vendor,omitempty"`
	DetectedPII    []string               `json:"detected_pii,omitempty"`
	UpstreamRegion string                 `json:"upstream_region"`
	RequestCount   int                    `json:"request_count,omitempty"`
	Arguments      map[string]interface{} `json:"arguments,omitempty"`
	Approved       bool                   `json:"approved,omitempty"`
}

// ---------------------------------------------------------------------------
// Proxy engine
// ---------------------------------------------------------------------------

// proxyPolicies defines the Rego files and query paths for proxy evaluation.
var proxyPolicies = []regoPolicy{
	{file: "rego/proxy_tool_access.rego", query: "data.talon.proxy.tool_access.deny"},
	{file: "rego/proxy_rate_limits.rego", query: "data.talon.proxy.rate_limits.deny"},
	{file: "rego/proxy_pii_redaction.rego", query: "data.talon.proxy.pii_redaction.deny"},
	{file: "rego/proxy_compliance.rego", query: "data.talon.proxy.compliance.deny"},
}

// ProxyEngine evaluates proxy-specific governance policies using embedded OPA.
type ProxyEngine struct {
	config   *ProxyPolicyConfig
	prepared map[string]rego.PreparedEvalQuery
}

// NewProxyEngine creates a proxy policy engine with precompiled Rego policies.
// The ProxyPolicyConfig is converted to OPA data under the "proxy" root key.
func NewProxyEngine(ctx context.Context, cfg *ProxyPolicyConfig) (*ProxyEngine, error) {
	ctx, span := tracer.Start(ctx, "policy.proxy_engine.new")
	defer span.End()

	proxyData, err := proxyConfigToOPAData(cfg)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("converting proxy config to OPA data: %w", err)
	}

	prepared := make(map[string]rego.PreparedEvalQuery, len(proxyPolicies))

	for _, rp := range proxyPolicies {
		content, err := embeddedPolicies.ReadFile(rp.file)
		if err != nil {
			return nil, fmt.Errorf("reading embedded proxy policy %s: %w", rp.file, err)
		}

		store := inmem.NewFromObject(map[string]interface{}{
			"proxy": proxyData,
		})

		r := rego.New(
			rego.Query(rp.query),
			rego.Module(rp.file, string(content)),
			rego.Store(store),
		)

		preparedQuery, err := r.PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("preparing proxy Rego policy %s: %w", rp.file, err)
		}

		prepared[rp.file] = preparedQuery
	}

	span.SetAttributes(attribute.Int("policy.proxy.prepared_count", len(prepared)))

	return &ProxyEngine{
		config:   cfg,
		prepared: prepared,
	}, nil
}

// EvaluateProxyToolAccess checks whether a proxy tool call is allowed.
func (pe *ProxyEngine) EvaluateProxyToolAccess(ctx context.Context, input *ProxyInput) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.proxy.evaluate_tool_access",
		trace.WithAttributes(
			attribute.String("tool.name", input.ToolName),
			attribute.String("vendor", input.Vendor),
		))
	defer span.End()

	return pe.evaluate(ctx, "rego/proxy_tool_access.rego", proxyInputToMap(input))
}

// EvaluateProxyRateLimit checks whether the vendor rate limit is exceeded.
func (pe *ProxyEngine) EvaluateProxyRateLimit(ctx context.Context, input *ProxyInput) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.proxy.evaluate_rate_limit",
		trace.WithAttributes(
			attribute.String("vendor", input.Vendor),
			attribute.Int("request_count", input.RequestCount),
		))
	defer span.End()

	return pe.evaluate(ctx, "rego/proxy_rate_limits.rego", proxyInputToMap(input))
}

// EvaluateProxyPII checks whether all detected PII fields have valid redaction rules.
func (pe *ProxyEngine) EvaluateProxyPII(ctx context.Context, input *ProxyInput) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.proxy.evaluate_pii",
		trace.WithAttributes(
			attribute.Int("detected_pii_count", len(input.DetectedPII)),
		))
	defer span.End()

	return pe.evaluate(ctx, "rego/proxy_pii_redaction.rego", proxyInputToMap(input))
}

// EvaluateProxyCompliance checks GDPR / NIS2 / EU AI Act compliance requirements.
func (pe *ProxyEngine) EvaluateProxyCompliance(ctx context.Context, input *ProxyInput) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "policy.proxy.evaluate_compliance",
		trace.WithAttributes(
			attribute.String("upstream_region", input.UpstreamRegion),
		))
	defer span.End()

	return pe.evaluate(ctx, "rego/proxy_compliance.rego", proxyInputToMap(input))
}

// evaluate runs a single proxy Rego policy and returns a Decision.
// It delegates to the shared evaluateDenyReasons helper in engine.go.
func (pe *ProxyEngine) evaluate(ctx context.Context, file string, input map[string]interface{}) (*Decision, error) {
	decision := &Decision{
		Allowed: true,
		Action:  "allow",
	}

	reasons, err := evaluateDenyReasons(ctx, pe.prepared, file, input)
	if err != nil {
		return nil, err
	}
	decision.Reasons = append(decision.Reasons, reasons...)

	if len(decision.Reasons) > 0 {
		decision.Allowed = false
		decision.Action = "deny"
	}

	return decision, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// proxyInputToMap converts a ProxyInput to map[string]interface{} for OPA.
func proxyInputToMap(input *ProxyInput) map[string]interface{} {
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return map[string]interface{}{}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &m); err != nil {
		return map[string]interface{}{}
	}
	return m
}

// proxyConfigToOPAData flattens a ProxyPolicyConfig into the OPA data
// structure expected by the proxy Rego policies (under the "proxy" root).
//
// OPA data layout:
//
//	{
//	  "allowed_tools":  ["tool1", "tool2"],
//	  "forbidden_tools": ["pattern1"],
//	  "rate_limits":    {"requests_per_minute": 100},
//	  "pii_rules":      [{"field": "email", "method": "hash"}],
//	  "compliance":     {"data_residency": "eu-only", "frameworks": ["gdpr"]}
//	}
func proxyConfigToOPAData(cfg *ProxyPolicyConfig) (map[string]interface{}, error) {
	// Build allowed_tools as a flat list of tool names.
	allowedTools := make([]interface{}, 0, len(cfg.Proxy.AllowedTools))
	for _, t := range cfg.Proxy.AllowedTools {
		allowedTools = append(allowedTools, t.Name)
	}

	// Build forbidden_tools.
	forbiddenTools := make([]interface{}, 0, len(cfg.Proxy.ForbiddenTools))
	for _, f := range cfg.Proxy.ForbiddenTools {
		forbiddenTools = append(forbiddenTools, f)
	}

	// Build rate limits.
	rateLimits := map[string]interface{}{}
	if cfg.Proxy.RateLimits.RequestsPerMinute > 0 {
		rateLimits["requests_per_minute"] = cfg.Proxy.RateLimits.RequestsPerMinute
	}

	// Build PII rules.
	piiRules := make([]interface{}, 0, len(cfg.PIIHandling.RedactionRules))
	for _, r := range cfg.PIIHandling.RedactionRules {
		piiRules = append(piiRules, map[string]interface{}{
			"field":  r.Field,
			"method": r.Method,
		})
	}

	// Build compliance data.
	complianceData := map[string]interface{}{}
	if cfg.Compliance.DataResidency != "" {
		complianceData["data_residency"] = cfg.Compliance.DataResidency
	}
	if len(cfg.Compliance.Frameworks) > 0 {
		frameworks := make([]interface{}, 0, len(cfg.Compliance.Frameworks))
		for _, f := range cfg.Compliance.Frameworks {
			frameworks = append(frameworks, f)
		}
		complianceData["frameworks"] = frameworks
	}

	data := map[string]interface{}{
		"allowed_tools":  allowedTools,
		"forbidden_tools": forbiddenTools,
		"rate_limits":    rateLimits,
		"pii_rules":     piiRules,
		"compliance":    complianceData,
	}

	return data, nil
}

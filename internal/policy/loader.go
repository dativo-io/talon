package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/policy")

// ResolvePathUnderBase resolves path relative to baseDir and returns an absolute path
// that is guaranteed to be under baseDir. Prevents path traversal when path is user-controlled.
// If path is absolute, it must still be under baseDir. Use this when you need the safe path
// for other uses (e.g. passing to loadRoutingAndCostLimits) in addition to LoadPolicy.
func ResolvePathUnderBase(baseDir, path string) (string, error) {
	dirAbs, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return "", fmt.Errorf("policy base directory: %w", err)
	}
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(dirAbs, path)
	}
	full = filepath.Clean(full)
	pathAbs, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("policy path: %w", err)
	}
	rel, err := filepath.Rel(dirAbs, pathAbs)
	if err != nil {
		return "", fmt.Errorf("policy path outside base directory")
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("policy path outside base directory")
	}
	return pathAbs, nil
}

// LoadPolicy loads and validates a .talon.yaml file.
// baseDir is the directory path is resolved against; the resolved path must stay under baseDir.
// If baseDir is empty, the current working directory is used.
// If strict is true, additional business-rule validation is applied.
func LoadPolicy(ctx context.Context, path string, strict bool, baseDir string) (*Policy, error) {
	_, span := tracer.Start(ctx, "policy.load")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.path", path),
		attribute.Bool("policy.strict", strict),
	)

	if baseDir == "" {
		var err error
		baseDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("policy base directory: %w", err)
		}
	}
	safePath, err := ResolvePathUnderBase(baseDir, path)
	if err != nil {
		return nil, fmt.Errorf("policy path: %w", err)
	}

	content, err := os.ReadFile(safePath)
	if err != nil {
		return nil, fmt.Errorf("reading policy file %s: %w", safePath, err)
	}

	if err := ValidateSchema(content, strict); err != nil {
		return nil, fmt.Errorf("schema validation: %w", err)
	}

	var pol Policy
	if err := yaml.Unmarshal(content, &pol); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	pol.ComputeHash(content)
	applyDefaults(&pol)

	// Validate routing configuration for sovereignty misconfigurations
	if pol.Policies.ModelRouting != nil {
		warnings, err := ValidateRouting(pol.Policies.ModelRouting)
		if err != nil {
			return nil, fmt.Errorf("routing validation: %w", err)
		}
		for _, w := range warnings {
			log.Debug().
				Str("tier", w.Tier).
				Str("agent", pol.Agent.Name).
				Msg(w.Message)
			span.AddEvent("routing_warning", trace.WithAttributes(
				attribute.String("tier", w.Tier),
				attribute.String("warning", w.Message),
			))
		}
	}

	span.SetAttributes(
		attribute.String("policy.agent_name", pol.Agent.Name),
		attribute.String("policy.version_tag", pol.VersionTag),
	)

	return &pol, nil
}

// applyDefaults fills in sensible defaults for optional fields.
func applyDefaults(p *Policy) {
	// Model tier: default to 1 when capabilities are defined
	if p.Agent.ModelTier == 0 && p.Capabilities != nil {
		p.Agent.ModelTier = 1
	}

	// Audit defaults (7-year retention for GDPR)
	if p.Audit == nil {
		p.Audit = &AuditConfig{
			LogLevel:      "detailed",
			RetentionDays: 2555,
		}
	}

	// Memory defaults when enabled
	if p.Memory != nil && p.Memory.Enabled {
		if p.Memory.MaxEntries == 0 {
			p.Memory.MaxEntries = 100
		}
		if p.Memory.MaxEntrySizeKB == 0 {
			p.Memory.MaxEntrySizeKB = 10
		}
		if p.Memory.RetentionDays == 0 {
			p.Memory.RetentionDays = 90
		}
		if p.Memory.ReviewMode == "" {
			p.Memory.ReviewMode = "auto"
		}
	}

	// Attachment handling defaults
	if p.AttachmentHandling == nil {
		p.AttachmentHandling = &AttachmentHandlingConfig{
			Mode: "permissive",
			Sandboxing: &SandboxingConfig{
				WrapContent: true,
			},
		}
	}
}

// LoadProxyPolicy loads and validates a .talon.yaml file for proxy mode.
// baseDir is the directory path is resolved against; the resolved path must stay under baseDir.
// If baseDir is empty, the current working directory is used.
// It checks that agent.type is "mcp_proxy", that an upstream URL is set,
// and that at least one allowed_tool is defined.
func LoadProxyPolicy(path string, baseDir string) (*ProxyPolicyConfig, error) {
	if baseDir == "" {
		var err error
		baseDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("proxy policy base directory: %w", err)
		}
	}
	safePath, err := ResolvePathUnderBase(baseDir, path)
	if err != nil {
		return nil, fmt.Errorf("proxy policy path: %w", err)
	}
	data, err := os.ReadFile(safePath)
	if err != nil {
		return nil, fmt.Errorf("reading proxy policy file %s: %w", safePath, err)
	}

	var config ProxyPolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing proxy policy YAML: %w", err)
	}

	if config.Agent.Type != "mcp_proxy" {
		return nil, fmt.Errorf("agent.type must be 'mcp_proxy' for proxy configs, got %q", config.Agent.Type)
	}

	if config.Proxy.Upstream.URL == "" {
		return nil, fmt.Errorf("proxy.upstream.url is required")
	}

	if len(config.Proxy.AllowedTools) == 0 {
		return nil, fmt.Errorf("proxy.allowed_tools must have at least one entry")
	}

	// Default proxy mode to "intercept" when unset.
	if config.Proxy.Mode == "" {
		config.Proxy.Mode = "intercept"
	}

	return &config, nil
}

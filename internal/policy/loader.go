package policy

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel/attribute"
	"gopkg.in/yaml.v3"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/policy")

// LoadPolicy loads and validates a .talon.yaml file.
// If strict is true, additional business-rule validation is applied.
func LoadPolicy(ctx context.Context, path string, strict bool) (*Policy, error) {
	ctx, span := tracer.Start(ctx, "policy.load")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.path", path),
		attribute.Bool("policy.strict", strict),
	)

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file %s: %w", path, err)
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

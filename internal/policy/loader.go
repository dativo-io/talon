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
	if err := rejectLegacyPostureKeys(content); err != nil {
		return nil, err
	}

	var pol Policy
	if err := yaml.Unmarshal(content, &pol); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Detect unknown/misspelled keys: a strict re-decode that fails means the
	// file contains keys the loader silently ignores. Warn (don't fail) so
	// existing configs keep working while typos become visible.
	if unknownErr := detectUnknownFields(content); unknownErr != nil {
		log.Warn().
			Str("policy_path", safePath).
			Str("detail", unknownErr.Error()).
			Msg("policy contains unknown keys that Talon ignores — check for typos or misplaced sections")
		span.AddEvent("policy_unknown_fields", trace.WithAttributes(
			attribute.String("detail", unknownErr.Error()),
		))
	}

	applyDefaults(&pol)
	if err := pol.ComputeCanonicalIdentity(); err != nil {
		return nil, fmt.Errorf("computing policy identity: %w", err)
	}

	// Operating-record rules (#382): closed criticality vocabulary + length
	// bounds. A config without a use_case block is untouched.
	if err := ValidateUseCase(pol.Agent.UseCase); err != nil {
		return nil, fmt.Errorf("use_case validation: %w", err)
	}

	// Retry override bounds (#139): fail the file at load, mirroring the
	// gateway's org-baseline validation.
	if err := ValidateRetries(pol.Policies.Retries); err != nil {
		return nil, fmt.Errorf("retries validation: %w", err)
	}

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

// ValidateNoUnknownFields fails when the agent policy at path contains keys
// the loader would silently ignore (#266 review round 4). Gateway startup
// calls this so a typo like `montly:` (dropping a budget), `allowed_provider:`
// (dropping a provider restriction), or `tool_policy_acton:` fails LOUDLY
// instead of silently removing a security control. Native-only `talon run`
// keeps the advisory warning to avoid breaking pre-cutover local files.
func ValidateNoUnknownFields(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		// No file to scan (e.g. an in-memory/synthetic policy): the loader
		// path already validated any real file, so there is nothing to check.
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading policy file %s: %w", path, err)
	}
	if err := detectUnknownFields(content); err != nil {
		return fmt.Errorf("agent policy %s contains unknown keys (typo or misplaced section — every key must be recognized for a gateway agent, #266): %w", path, err)
	}
	return nil
}

// detectUnknownFields re-decodes the YAML with strict field matching and
// returns the decode error when the document contains keys that do not exist
// on the Policy struct (typos, wrong nesting). Returns nil when all keys are
// known.
func detectUnknownFields(content []byte) error {
	dec := yaml.NewDecoder(strings.NewReader(string(content)))
	dec.KnownFields(true)
	var probe Policy
	if err := dec.Decode(&probe); err != nil {
		return err
	}
	return nil
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

// LegacyPostureRemovedHint is the shared migration text for every removed
// live-posture selector (#442): gateway.mode, proxy.mode, audit.observation_only
// and tool_policies.*.schema_validation. Live policy is always enforced; the
// only policy-checking paths that never contact a provider are the non-live
// ones named here.
const LegacyPostureRemovedHint = "live policy is always enforced; there is no shadow, log_only, passthrough or enforce posture to select (breaking change, #442). Delete the key. To check configuration without live traffic use 'talon doctor' (infrastructure config), 'talon validate' (agent policies) and 'talon run --dry-run' (native policy evaluation, no provider call); a side-effect-free policy-impact preview is tracked in #459"

// rejectLegacyPostureKeys fails closed on agent configuration that still
// selects a removed live-enforcement posture. It runs on EVERY load path
// (including the ones where unknown keys are merely warned about) so an old
// file can never be silently treated as enforced.
func rejectLegacyPostureKeys(content []byte) error {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return nil // the typed unmarshal reports the real parse error
	}
	if audit, ok := raw["audit"].(map[string]interface{}); ok {
		if v, present := audit["observation_only"]; present {
			return fmt.Errorf("agent policy uses removed key \"audit.observation_only\" (value %v) — a policy denial is always enforced for native runs; %s", v, LegacyPostureRemovedHint)
		}
	}
	if tps, ok := raw["tool_policies"].(map[string]interface{}); ok {
		for name, tp := range tps {
			m, ok := tp.(map[string]interface{})
			if !ok {
				continue
			}
			if v, present := m["schema_validation"]; present {
				return fmt.Errorf("agent policy uses removed key \"tool_policies.%s.schema_validation\" (value %v) — tool argument schema validation is always enforced when a tool declares an input schema; %s", name, v, LegacyPostureRemovedHint)
			}
		}
	}
	return nil
}

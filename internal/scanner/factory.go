package scanner

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/classifier/adapter/llm"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/sovereignty"
)

// Build returns the process-wide scanner engine for the given operator
// config. With no scanner block (or type regex) it builds the policy-aware
// built-in regex scanner — byte-identical to the pre-adapter default. For
// external engines it validates endpoint locality (air-gap), wraps the
// transport with the sovereignty egress guard when active, and runs the
// eager health probe: a configured-but-unreachable engine refuses to start
// rather than silently degrading (fail-closed).
//
// pol and engine may be nil (e.g. `talon plan` has no enrichment engine);
// the regex path then uses the embedded default recognizers.
func Build(ctx context.Context, cfg *config.Config, pol *policy.Policy, engine *policy.Engine) (classifier.Facade, error) {
	var sc *config.ScannerConfig
	if cfg != nil {
		sc = cfg.Scanner
	}
	if !sc.IsExternal() {
		return buildRegex(ctx, pol, engine)
	}

	switch sc.EngineType() {
	case config.ScannerTypePresidio, config.ScannerTypeHTTP:
		return buildHTTP(ctx, cfg, sc)
	case config.ScannerTypeLLM:
		return buildLLM(ctx, cfg, sc, pol)
	default:
		return nil, fmt.Errorf("scanner.type %q is not supported", sc.EngineType())
	}
}

func buildRegex(ctx context.Context, pol *policy.Policy, engine *policy.Engine) (classifier.Facade, error) {
	if pol == nil {
		s, err := classifier.NewScanner()
		if err != nil {
			return nil, fmt.Errorf("initializing built-in PII scanner: %w", err)
		}
		return s, nil
	}
	s, err := policy.NewPIIScannerForPolicyWithEnrichment(ctx, pol, "", engine)
	if err != nil {
		return nil, fmt.Errorf("initializing policy-aware PII scanner: %w", err)
	}
	return s, nil
}

func buildHTTP(ctx context.Context, cfg *config.Config, sc *config.ScannerConfig) (classifier.Facade, error) {
	airGap := cfg.Sovereignty.AirGapEnabled()
	if err := ValidateEndpointLocality(sc.Endpoint, airGap); err != nil {
		return nil, err
	}

	var transport http.RoundTripper
	if airGap {
		// The adapter client is its own egress path; in air-gap mode it gets
		// the same transport-level allowlist guard as the gateway upstream.
		transport = sovereignty.NewEgressGuard(append([]string{sc.Endpoint}, cfg.Sovereignty.AllowedEgressHosts...))
	}

	a, err := adapter.New(adapter.Config{
		Type:                  sc.EngineType(),
		Endpoint:              sc.Endpoint,
		Name:                  sc.Name,
		EngineVersion:         sc.EngineVersion,
		Language:              sc.EffectiveLanguage(),
		Timeout:               sc.ParsedTimeout(),
		MinScore:              sc.EffectiveMinScore(),
		DefaultOffsetEncoding: sc.OffsetEncoding,
		Entities:              sc.Entities,
		Transport:             transport,
	})
	if err != nil {
		return nil, fmt.Errorf("initializing external scanner adapter: %w", err)
	}

	return finishExternal(ctx, a, sc, sc.EngineVersion)
}

// buildLLM assembles the OpenAI-compatible NER engine (e.g. Ollama). The
// entity set the prompt hunts for is derived from the effective policy so the
// model targets exactly what the policy governs.
func buildLLM(ctx context.Context, cfg *config.Config, sc *config.ScannerConfig, pol *policy.Policy) (classifier.Facade, error) {
	airGap := cfg.Sovereignty.AirGapEnabled()
	if err := ValidateEndpointLocality(sc.Endpoint, airGap); err != nil {
		return nil, err
	}

	var transport http.RoundTripper
	if airGap {
		transport = sovereignty.NewEgressGuard(append([]string{sc.Endpoint}, cfg.Sovereignty.AllowedEgressHosts...))
	}

	// scanner.entities, when set, is the explicit entity list the prompt
	// hunts for — the operator's lever for shrinking the NER prompt (prompt
	// evaluation dominates scan latency on CPU hosts). Otherwise the list is
	// derived from the effective policy.
	entityTypes := sc.Entities
	if len(entityTypes) == 0 {
		var scanOpts []classifier.ScannerOption
		if pol != nil {
			var err error
			scanOpts, err = policy.PIIScannerOptions(pol.Policies.DataClassification, "")
			if err != nil {
				return nil, fmt.Errorf("deriving scanner options from policy: %w", err)
			}
		}
		var err error
		entityTypes, err = classifier.SupportedEntityTypes(scanOpts...)
		if err != nil {
			return nil, fmt.Errorf("deriving entity types for llm scanner: %w", err)
		}
	}

	a, err := llm.New(llm.Config{
		Endpoint:    sc.Endpoint,
		Model:       sc.LLM.Model,
		Confidence:  sc.LLM.EffectiveConfidence(),
		Timeout:     sc.ParsedTimeout(),
		EntityTypes: entityTypes,
		Name:        sc.Name,
		Transport:   transport,
	})
	if err != nil {
		return nil, fmt.Errorf("initializing llm scanner adapter: %w", err)
	}
	return finishExternal(ctx, a, sc, llm.PromptVersion)
}

// externalEngine is the common surface of every external adapter.
type externalEngine interface {
	classifier.Facade
	HealthCheck(ctx context.Context) error
}

// finishExternal runs the startup probe and logs engine activation.
func finishExternal(ctx context.Context, a externalEngine, sc *config.ScannerConfig, version string) (classifier.Facade, error) {
	if sc.HealthCheckEnabled() {
		if err := probeHealth(ctx, a, sc); err != nil {
			return nil, err
		}
	} else {
		log.Warn().Str("engine", a.Detector()).Msg("scanner health check disabled; a dead engine will surface as fail-closed blocks on first scan")
	}

	log.Info().
		Str("engine", a.Detector()).
		Str("type", sc.EngineType()).
		Str("version", version).
		Dur("timeout", sc.ParsedTimeout()).
		Msg("external PII scanner engine active (replaces built-in regex scanner; fail-closed on errors)")
	return a, nil
}

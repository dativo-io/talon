package scanner

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/adapter"
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
		return nil, fmt.Errorf("scanner.type llm is not implemented yet (see docs/reference/external-scanners.md)")
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
		Str("version", sc.EngineVersion).
		Dur("timeout", sc.ParsedTimeout()).
		Msg("external PII scanner engine active (replaces built-in regex scanner; fail-closed on errors)")
	return a, nil
}

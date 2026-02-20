package llm

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/policy"
)

// CostContext holds cost totals and scope for graceful degradation decisions.
type CostContext struct {
	DailyTotal   float64
	MonthlyTotal float64
	AgentName    string
	TenantID     string
}

// Router selects the appropriate LLM provider and model based on
// data classification tier and policy configuration.
type Router struct {
	providers  map[string]Provider
	routing    *policy.ModelRoutingConfig
	costLimits *policy.CostLimitsConfig
}

// NewRouter creates an LLM router with the given providers and routing config.
// costLimits may be nil; when set, GracefulRoute can downgrade to fallback_model when budget threshold is reached.
func NewRouter(routing *policy.ModelRoutingConfig, providers map[string]Provider, costLimits *policy.CostLimitsConfig) *Router {
	return &Router{
		providers:  providers,
		routing:    routing,
		costLimits: costLimits,
	}
}

// Route selects a provider and model based on the data classification tier.
// Tier 0 = public data (any provider), Tier 1 = internal (EU preferred),
// Tier 2 = confidential (EU-only / Bedrock).
func (r *Router) Route(ctx context.Context, tier int) (Provider, string, error) {
	_, span := tracer.Start(ctx, "llm.route",
		trace.WithAttributes(
			attribute.Int("data.tier", tier),
		))
	defer span.End()

	tierConfig, err := r.getTierConfig(tier)
	if err != nil {
		span.RecordError(err)
		return nil, "", err
	}

	if strings.TrimSpace(tierConfig.Primary) == "" {
		err := fmt.Errorf("tier %d: %w", tier, ErrNoPrimaryModel)
		span.RecordError(err)
		return nil, "", err
	}

	model := tierConfig.Primary
	providerName, err := inferProvider(model)
	if err != nil {
		span.RecordError(err)
		return nil, "", err
	}

	// Enforce bedrock_only: override inferred provider and reject non-bedrock fallbacks.
	// This prevents confidential data from being routed outside the sovereignty boundary.
	if tierConfig.BedrockOnly {
		providerName = "bedrock"
	}

	provider, ok := r.providers[providerName]
	if !ok {
		// Try fallback model if available
		if tierConfig.Fallback != "" {
			fallbackProvider, fbErr := inferProvider(tierConfig.Fallback)
			if fbErr != nil {
				span.RecordError(fbErr)
				return nil, "", fbErr
			}
			if tierConfig.BedrockOnly {
				fallbackProvider = "bedrock"
			}
			provider, ok = r.providers[fallbackProvider]
			if ok {
				model = tierConfig.Fallback
				providerName = fallbackProvider
			}
		}
		if !ok {
			err := fmt.Errorf("provider %s: %w", providerName, ErrProviderNotAvailable)
			span.RecordError(err)
			return nil, "", err
		}
	}

	span.SetAttributes(
		attribute.String("gen_ai.request.model", model),
		attribute.String("llm.provider", providerName),
	)

	return provider, model, nil
}

// GracefulRoute selects provider and model like Route, but may downgrade to a fallback model
// when cost degradation is enabled and the daily budget usage meets the threshold.
// Returns (provider, model, degraded, originalModel, error). When degraded is true, originalModel
// is the primary model that would have been used; model is the fallback actually used.
func (r *Router) GracefulRoute(ctx context.Context, tier int, costCtx *CostContext) (provider Provider, model string, degraded bool, originalModel string, err error) {
	ctx, span := tracer.Start(ctx, "llm.graceful_route",
		trace.WithAttributes(attribute.Int("data.tier", tier)))
	defer span.End()

	provider, model, err = r.Route(ctx, tier)
	if err != nil {
		span.RecordError(err)
		return nil, "", false, "", err
	}

	if costCtx == nil || r.costLimits == nil || r.costLimits.Degradation == nil || !r.costLimits.Degradation.Enabled {
		return provider, model, false, "", nil
	}
	if r.costLimits.Daily <= 0 {
		return provider, model, false, "", nil
	}

	budgetUsedPct := (costCtx.DailyTotal / r.costLimits.Daily) * 100
	if budgetUsedPct < r.costLimits.Degradation.ThresholdPercent {
		return provider, model, false, "", nil
	}

	fallbackModel := strings.TrimSpace(r.costLimits.Degradation.FallbackModel)
	if fallbackModel == "" {
		return provider, model, false, "", nil
	}

	fallbackProviderName, err := InferProvider(fallbackModel)
	if err != nil {
		span.RecordError(err)
		return provider, model, false, "", nil
	}

	// Enforce tier's bedrock_only: do not degrade to a non-Bedrock provider when the tier
	// requires EU/Bedrock-only (data sovereignty). Route() enforces this for primary and
	// tier fallback; we must not bypass it for cost-degradation fallback.
	if tierConfig, tierErr := r.getTierConfig(tier); tierErr == nil && tierConfig.BedrockOnly && fallbackProviderName != "bedrock" {
		span.SetAttributes(
			attribute.Bool("cost.degradation_skipped_bedrock_only", true),
			attribute.String("cost.fallback_model_rejected", fallbackModel),
		)
		return provider, model, false, "", nil
	}

	fallbackProvider, ok := r.providers[fallbackProviderName]
	if !ok {
		return provider, model, false, "", nil
	}

	span.SetAttributes(
		attribute.Bool("cost.degraded", true),
		attribute.String("cost.original_model", model),
		attribute.String("cost.fallback_model", fallbackModel),
		attribute.Float64("cost.budget_used_pct", budgetUsedPct),
	)
	return fallbackProvider, fallbackModel, true, model, nil
}

// PreRunEstimate returns an estimated cost in EUR for a small request (300 input + 300 output tokens)
// for the primary model of the given tier. Used for pre-run policy budget checks when the actual
// token counts are not yet known. Returns a conservative estimate; on error falls back to 0.01.
const (
	preRunEstimateInputTokens  = 300
	preRunEstimateOutputTokens = 300
)

func (r *Router) PreRunEstimate(tier int) (float64, error) {
	tierConfig, err := r.getTierConfig(tier)
	if err != nil {
		return 0.01, err
	}
	model := strings.TrimSpace(tierConfig.Primary)
	if model == "" {
		return 0.01, ErrNoPrimaryModel
	}
	providerName, err := inferProvider(model)
	if err != nil {
		return 0.01, err
	}
	if tierConfig.BedrockOnly {
		providerName = "bedrock"
	}
	provider, ok := r.providers[providerName]
	if !ok {
		return 0.01, ErrProviderNotAvailable
	}
	return provider.EstimateCost(model, preRunEstimateInputTokens, preRunEstimateOutputTokens), nil
}

// InferProvider is the public name for inferProvider for use by callers that need to resolve a model to a provider.
func InferProvider(model string) (string, error) {
	return inferProvider(model)
}

// getTierConfig returns the routing configuration for the given tier.
func (r *Router) getTierConfig(tier int) (*policy.TierConfig, error) {
	if r.routing == nil {
		return nil, fmt.Errorf("tier %d: %w", tier, ErrNoRoutingConfig)
	}

	switch tier {
	case 0:
		if r.routing.Tier0 == nil {
			return nil, fmt.Errorf("tier 0: %w", ErrNoRoutingConfig)
		}
		return r.routing.Tier0, nil
	case 1:
		if r.routing.Tier1 == nil {
			return nil, fmt.Errorf("tier 1: %w", ErrNoRoutingConfig)
		}
		return r.routing.Tier1, nil
	case 2:
		if r.routing.Tier2 == nil {
			return nil, fmt.Errorf("tier 2: %w", ErrNoRoutingConfig)
		}
		return r.routing.Tier2, nil
	default:
		return nil, fmt.Errorf("tier %d: %w", tier, ErrInvalidTier)
	}
}

// inferProvider determines the provider name from the model identifier.
// Returns ErrUnknownModel for unrecognized model prefixes (fail-closed).
// Bedrock vendor-prefixed models (e.g. "meta.llama3-1-70b-instruct-v1:0")
// are checked before bare-name Ollama models to avoid misrouting.
func inferProvider(model string) (string, error) {
	// Check Bedrock vendor-prefixed models first (e.g. "mistral.mistral-large")
	// before bare-name checks (e.g. "mistral:7b" for Ollama).
	for _, prefix := range policy.BedrockModelPrefixes() {
		if strings.HasPrefix(model, prefix) {
			return "bedrock", nil
		}
	}

	switch {
	case strings.HasPrefix(model, "gpt-"):
		return "openai", nil
	case strings.HasPrefix(model, "claude-"):
		return "anthropic", nil
	case strings.HasPrefix(model, "llama"),
		strings.HasPrefix(model, "mistral"),
		strings.HasPrefix(model, "gemma"),
		strings.HasPrefix(model, "phi"):
		return "ollama", nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnknownModel, model)
	}
}

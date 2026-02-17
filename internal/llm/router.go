package llm

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/policy"
)

// Router selects the appropriate LLM provider and model based on
// data classification tier and policy configuration.
type Router struct {
	providers map[string]Provider
	routing   *policy.ModelRoutingConfig
}

// NewRouter creates an LLM router with the given providers and routing config.
func NewRouter(routing *policy.ModelRoutingConfig, providers map[string]Provider) *Router {
	return &Router{
		providers: providers,
		routing:   routing,
	}
}

// Route selects a provider and model based on the data classification tier.
// Tier 0 = public data (any provider), Tier 1 = internal (EU preferred),
// Tier 2 = confidential (EU-only / Bedrock).
func (r *Router) Route(ctx context.Context, tier int) (Provider, string, error) {
	ctx, span := tracer.Start(ctx, "llm.route",
		trace.WithAttributes(
			attribute.Int("data.tier", tier),
		))
	defer span.End()

	tierConfig, err := r.getTierConfig(tier)
	if err != nil {
		span.RecordError(err)
		return nil, "", err
	}

	model := tierConfig.Primary
	providerName := inferProvider(model)

	// Enforce bedrock_only: override inferred provider and reject non-bedrock fallbacks.
	// This prevents confidential data from being routed outside the sovereignty boundary.
	if tierConfig.BedrockOnly {
		providerName = "bedrock"
	}

	provider, ok := r.providers[providerName]
	if !ok {
		// Try fallback model if available
		if tierConfig.Fallback != "" {
			fallbackProvider := inferProvider(tierConfig.Fallback)
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
func inferProvider(model string) string {
	switch {
	case strings.HasPrefix(model, "gpt-"):
		return "openai"
	case strings.HasPrefix(model, "claude-"):
		return "anthropic"
	case strings.HasPrefix(model, "anthropic."):
		return "bedrock"
	case strings.HasPrefix(model, "amazon."):
		return "bedrock"
	case strings.HasPrefix(model, "llama"), strings.HasPrefix(model, "mistral"),
		strings.HasPrefix(model, "gemma"), strings.HasPrefix(model, "phi"):
		return "ollama"
	default:
		return "openai" // Default to OpenAI for unknown model names
	}
}

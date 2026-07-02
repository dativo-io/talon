package otel

import (
	"go.opentelemetry.io/otel/attribute"
)

// GenAI Semantic Conventions for LLM observability
// Based on OpenTelemetry GenAI SIG conventions

const (
	// LLM System attributes
	GenAISystem       = attribute.Key("gen_ai.system")        // e.g., "openai", "anthropic"
	GenAIRequestModel = attribute.Key("gen_ai.request.model") // e.g., "gpt-4o"

	// Request attributes
	GenAIRequestTemperature = attribute.Key("gen_ai.request.temperature")
	GenAIRequestMaxTokens   = attribute.Key("gen_ai.request.max_tokens")
	GenAIRequestTopP        = attribute.Key("gen_ai.request.top_p")

	// Usage attributes
	GenAIUsageInputTokens  = attribute.Key("gen_ai.usage.input_tokens")
	GenAIUsageOutputTokens = attribute.Key("gen_ai.usage.output_tokens")

	// Response attributes
	GenAIResponseFinishReason = attribute.Key("gen_ai.response.finish_reason")
	GenAIResponseID           = attribute.Key("gen_ai.response.id")

	// Talon compliance routing attributes (provider registry + EU sovereignty)
	TalonProviderJurisdiction   = attribute.Key("talon.provider.jurisdiction")
	TalonProviderRegion         = attribute.Key("talon.provider.region")
	TalonRoutingSovereigntyMode = attribute.Key("talon.routing.sovereignty_mode")
	TalonRoutingSelectionReason = attribute.Key("talon.routing.selection_reason")
	TalonDataTier               = attribute.Key("talon.data.tier")
	TalonRoutingRejectedCount   = attribute.Key("talon.routing.rejected_count")

	// Talon provider failover attributes (error-driven fallback chains)
	TalonProviderOriginal       = attribute.Key("talon.provider.original")        // primary provider that failed
	TalonProviderSelected       = attribute.Key("talon.provider.selected")        // provider actually used
	TalonProviderFallbackReason = attribute.Key("talon.provider.fallback_reason") // error class that triggered failover
	TalonFallbackChainPosition  = attribute.Key("talon.fallback.chain_position")  // position of selected candidate (0 = primary)
	TalonFallbackFailedAttempts = attribute.Key("talon.fallback.failed_attempts") // number of failed runtime attempts
	TalonFallbackFailClosed     = attribute.Key("talon.fallback.fail_closed")     // true when no policy-valid candidate existed

	// Talon cost estimation attributes (from pricing table)
	TalonCostEstimatedUSD = attribute.Key("talon.cost.estimated_usd")
	TalonCostPricingKnown = attribute.Key("talon.cost.pricing_known")
	TalonCostInputTokens  = attribute.Key("talon.cost.input_tokens")
	TalonCostOutputTokens = attribute.Key("talon.cost.output_tokens")
)

// LLMRequestAttributes creates standard attributes for LLM requests
func LLMRequestAttributes(system, model string, temperature float64, maxTokens int) []attribute.KeyValue {
	return []attribute.KeyValue{
		GenAISystem.String(system),
		GenAIRequestModel.String(model),
		GenAIRequestTemperature.Float64(temperature),
		GenAIRequestMaxTokens.Int(maxTokens),
	}
}

// LLMUsageAttributes creates attributes for token usage
func LLMUsageAttributes(inputTokens, outputTokens int) []attribute.KeyValue {
	return []attribute.KeyValue{
		GenAIUsageInputTokens.Int(inputTokens),
		GenAIUsageOutputTokens.Int(outputTokens),
	}
}

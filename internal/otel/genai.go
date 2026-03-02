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

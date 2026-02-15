package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLLMRequestAttributes(t *testing.T) {
	tests := []struct {
		name        string
		system      string
		model       string
		temperature float64
		maxTokens   int
		wantLen     int
	}{
		{
			name:        "openai gpt-4o",
			system:      "openai",
			model:       "gpt-4o",
			temperature: 0.7,
			maxTokens:   4096,
			wantLen:     4,
		},
		{
			name:        "anthropic claude",
			system:      "anthropic",
			model:       "claude-3-sonnet",
			temperature: 0.0,
			maxTokens:   1024,
			wantLen:     4,
		},
		{
			name:        "zero values",
			system:      "",
			model:       "",
			temperature: 0.0,
			maxTokens:   0,
			wantLen:     4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := LLMRequestAttributes(tt.system, tt.model, tt.temperature, tt.maxTokens)
			require.Len(t, attrs, tt.wantLen)

			assert.Equal(t, "gen_ai.system", string(attrs[0].Key))
			assert.Equal(t, tt.system, attrs[0].Value.AsString())

			assert.Equal(t, "gen_ai.request.model", string(attrs[1].Key))
			assert.Equal(t, tt.model, attrs[1].Value.AsString())

			assert.Equal(t, "gen_ai.request.temperature", string(attrs[2].Key))
			assert.Equal(t, tt.temperature, attrs[2].Value.AsFloat64())

			assert.Equal(t, "gen_ai.request.max_tokens", string(attrs[3].Key))
			assert.Equal(t, int64(tt.maxTokens), attrs[3].Value.AsInt64())
		})
	}
}

func TestLLMUsageAttributes(t *testing.T) {
	tests := []struct {
		name         string
		inputTokens  int
		outputTokens int
	}{
		{"typical usage", 150, 300},
		{"zero tokens", 0, 0},
		{"large request", 128000, 4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := LLMUsageAttributes(tt.inputTokens, tt.outputTokens)
			require.Len(t, attrs, 2)

			assert.Equal(t, "gen_ai.usage.input_tokens", string(attrs[0].Key))
			assert.Equal(t, int64(tt.inputTokens), attrs[0].Value.AsInt64())

			assert.Equal(t, "gen_ai.usage.output_tokens", string(attrs[1].Key))
			assert.Equal(t, int64(tt.outputTokens), attrs[1].Value.AsInt64())
		})
	}
}

func TestGenAIAttributeKeys(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		wantName string
	}{
		{"system", string(GenAISystem), "gen_ai.system"},
		{"request model", string(GenAIRequestModel), "gen_ai.request.model"},
		{"request temperature", string(GenAIRequestTemperature), "gen_ai.request.temperature"},
		{"request max tokens", string(GenAIRequestMaxTokens), "gen_ai.request.max_tokens"},
		{"request top p", string(GenAIRequestTopP), "gen_ai.request.top_p"},
		{"usage input tokens", string(GenAIUsageInputTokens), "gen_ai.usage.input_tokens"},
		{"usage output tokens", string(GenAIUsageOutputTokens), "gen_ai.usage.output_tokens"},
		{"response finish reason", string(GenAIResponseFinishReason), "gen_ai.response.finish_reason"},
		{"response id", string(GenAIResponseID), "gen_ai.response.id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantName, tt.key)
		})
	}
}

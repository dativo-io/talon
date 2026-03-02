package llm

// Regression tests for PR #7 review findings.
// These tests document known bugs that were fixed in PROMPT_03_FIX.
// They guard against reintroduction of these bugs in future changes.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

// BUG-8: inferProvider() returned "openai" for unknown model names.
// This silently routed confidential data to a US-based provider when
// operators misconfigured a model name in .talon.yaml.
// For a compliance tool, fail-closed is the only correct posture.
//
// Original code: `default: return "openai"` in inferProvider().
// Fix: return ErrUnknownModel for unrecognised model names.
func TestBug8_InferProviderSilentlyDefaultsToOpenAI(t *testing.T) {
	unknownModels := []string{
		"grok-2",
		"gemini-pro",
		"custom-enterprise-model-v3",
		"",
		"UNKNOWN",
		"my-fine-tuned-model",
	}

	for _, model := range unknownModels {
		t.Run(model, func(t *testing.T) {
			provider, err := inferProvider(model)

			assert.Error(t, err,
				"BUG-8: unknown model %q must return an error, not silently default to OpenAI", model)
			assert.ErrorIs(t, err, ErrUnknownModel,
				"BUG-8: error must be ErrUnknownModel for unknown model %q", model)
			assert.Empty(t, provider,
				"BUG-8: provider must be empty string when model is unknown")
		})
	}
}

// BUG-8b: Known models must still infer correctly after the signature change.
func TestBug8b_KnownModelsStillInferCorrectly(t *testing.T) {
	tests := []struct {
		model    string
		wantProv string
	}{
		{"gpt-4o", "openai"},
		{"gpt-4o-mini", "openai"},
		{"claude-sonnet-4-5-20250929", "anthropic"},
		{"claude-haiku-4-5-20251001", "anthropic"},
		{"anthropic.claude-3-sonnet-20240229-v1:0", "bedrock"},
		{"amazon.titan-text-premier-v1:0", "bedrock"},
		{"llama3.1:70b", "ollama"},
		{"mistral:7b", "ollama"},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			provider, err := inferProvider(tt.model)
			require.NoError(t, err,
				"BUG-8b: known model %q must not return an error", tt.model)
			assert.Equal(t, tt.wantProv, provider,
				"BUG-8b: known model %q must infer to provider %q", tt.model, tt.wantProv)
		})
	}
}

// BUG-8c: Route() must propagate ErrUnknownModel when the configured model is unknown.
func TestBug8c_RouteReturnsErrorForUnknownModel(t *testing.T) {
	providers := map[string]Provider{
		"openai": &mockProvider{name: "openai"},
	}

	routing := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{
			Primary: "grok-2-ultra-secret",
		},
	}
	router := NewRouter(routing, providers, nil)

	_, _, _, err := router.Route(context.Background(), 0, nil)
	assert.Error(t, err,
		"BUG-8c: Route must return error when model is unknown")
	assert.ErrorIs(t, err, ErrUnknownModel,
		"BUG-8c: error must wrap ErrUnknownModel")
}

// BUG-9, BUG-9b, BUG-9c: Ollama HTTP status checks are tested in internal/llm/providers/ollama/provider_test.go
// (TestOllamaGenerate_Non2xx and related) to avoid import cycles.

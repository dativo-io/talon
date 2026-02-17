package llm

// Regression tests for PR #7 review findings.
// These tests document known bugs that were fixed in PROMPT_03_FIX.
// They guard against reintroduction of these bugs in future changes.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	router := NewRouter(routing, providers)

	_, _, err := router.Route(context.Background(), 0)
	assert.Error(t, err,
		"BUG-8c: Route must return error when model is unknown")
	assert.ErrorIs(t, err, ErrUnknownModel,
		"BUG-8c: error must wrap ErrUnknownModel")
}

// BUG-9: OllamaProvider.Generate() did not check HTTP status before decoding.
// A non-200 response (e.g. 404 "model not found", 500 "internal error")
// caused json.Decoder to attempt to parse the error body as an ollamaResponse.
// This returned no error and an empty Content string — a silent failure.
//
// Anthropic and OpenAI both checked status. Ollama was missed.
// Fix: add `if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf(...) }`
// immediately after p.httpClient.Do().
func TestBug9_OllamaDoesNotCheckHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"model 'nonexistent' not found, try pulling it first"}`))
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)

	resp, err := provider.Generate(context.Background(), &Request{
		Model:    "nonexistent-model",
		Messages: []Message{{Role: "user", Content: "Hello"}},
	})

	// BROKEN BEHAVIOUR: err is nil, resp.Content is ""
	// CORRECT BEHAVIOUR: err is non-nil containing the status code and body
	assert.Error(t, err,
		"BUG-9: Ollama 500 response must return an error, not silently succeed with empty content")
	assert.Nil(t, resp,
		"BUG-9: response must be nil when HTTP error occurs")

	if err != nil {
		assert.Contains(t, err.Error(), "500",
			"BUG-9: error message must include the HTTP status code")
	}
}

// BUG-9b: Ollama 404 (model not pulled) must also return an error.
func TestBug9b_OllamaDoesNotCheck404Status(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"model not found"}`))
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)
	_, err := provider.Generate(context.Background(), &Request{
		Model:    "llama-not-pulled",
		Messages: []Message{{Role: "user", Content: "Hello"}},
	})

	assert.Error(t, err, "BUG-9b: Ollama 404 must return an error")
}

// BUG-9c: Ollama 200 must still work correctly after the status check is added.
func TestBug9c_Ollama200StillWorks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message": map[string]string{
				"role":    "assistant",
				"content": "Hello from Ollama",
			},
		})
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)
	resp, err := provider.Generate(context.Background(), &Request{
		Model:    "llama3.1:8b",
		Messages: []Message{{Role: "user", Content: "Hello"}},
	})

	require.NoError(t, err, "BUG-9c: Ollama 200 must not return an error")
	assert.Equal(t, "Hello from Ollama", resp.Content)
}

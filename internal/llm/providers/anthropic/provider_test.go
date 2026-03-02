package anthropic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/pricing"
)

func newAnthropicTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *AnthropicProvider) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	prov := &AnthropicProvider{
		apiKey:     "test-anthropic-key",
		httpClient: ts.Client(),
		baseURL:    ts.URL,
	}
	return ts, prov
}

func TestAnthropicGenerate_Success(t *testing.T) {
	_, provider := newAnthropicTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-anthropic-key", r.Header.Get("x-api-key"))
		var reqBody anthropicRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))
		assert.Equal(t, "claude-sonnet-4-20250514", reqBody.Model)

		resp := anthropicResponse{
			ID: "msg_test123",
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{{Type: "text", Text: "Hello from Claude!"}},
			StopReason: "end_turn",
			Usage: struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			}{15, 5},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	resp, err := provider.Generate(context.Background(), &llm.Request{
		Model: "claude-sonnet-4-20250514", Messages: []llm.Message{{Role: "user", Content: "Hello Claude"}},
		Temperature: 0.7, MaxTokens: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, "Hello from Claude!", resp.Content)
	assert.Equal(t, "end_turn", resp.FinishReason)
	assert.Equal(t, 15, resp.InputTokens)
	assert.Equal(t, 5, resp.OutputTokens)
}

func TestAnthropicGenerate_AuthError(t *testing.T) {
	_, provider := newAnthropicTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := provider.Generate(context.Background(), &llm.Request{
		Model: "claude-3", Messages: []llm.Message{{Role: "user", Content: "Hi"}}, MaxTokens: 10,
	})
	require.Error(t, err)
	var pe *llm.ProviderError
	assert.ErrorAs(t, err, &pe)
	assert.Equal(t, "auth_failed", pe.Code)
}

func TestAnthropicMetadata(t *testing.T) {
	prov := &AnthropicProvider{apiKey: "x", baseURL: "https://api.anthropic.com"}
	meta := prov.Metadata()
	assert.Equal(t, "anthropic", meta.ID)
	assert.Equal(t, "US", meta.Jurisdiction)
	assert.Equal(t, 20, meta.Wizard.Order)
}

func TestAnthropicValidateConfig(t *testing.T) {
	p1 := &AnthropicProvider{apiKey: ""}
	require.Error(t, p1.ValidateConfig())
	p2 := &AnthropicProvider{apiKey: "sk-ant-x"}
	require.NoError(t, p2.ValidateConfig())
}

func TestAnthropicWithHTTPClient(t *testing.T) {
	prov := &AnthropicProvider{apiKey: "x", httpClient: &http.Client{}}
	p2 := prov.WithHTTPClient(&http.Client{})
	assert.NotNil(t, p2)
}

func TestAnthropicCostEstimation(t *testing.T) {
	pt, err := pricing.Load("../../../../pricing/models.yaml")
	if err != nil {
		t.Skipf("pricing file not found: %v", err)
	}
	prov := &AnthropicProvider{pricing: pt}
	cost := prov.EstimateCost("claude-sonnet-4-20250514", 1000, 500)
	assert.Greater(t, cost, 0.0)
}

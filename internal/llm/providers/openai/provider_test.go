package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	openaisdk "github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/llm"
)

func newOpenAITestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *OpenAIProvider) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	prov, err := NewOpenAIProviderFromConfig("test-api-key", ts.URL+"/v1")
	require.NoError(t, err)
	withClient := prov.WithHTTPClient(ts.Client())
	return ts, withClient.(*OpenAIProvider)
}

func TestOpenAIGenerate_Success(t *testing.T) {
	_, provider := newOpenAITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))
		resp := openaisdk.ChatCompletionResponse{
			ID: "chatcmpl-test123", Model: "gpt-4o",
			Choices: []openaisdk.ChatCompletionChoice{{
				Message:      openaisdk.ChatCompletionMessage{Role: "assistant", Content: "Hello! How can I help you?"},
				FinishReason: openaisdk.FinishReasonStop,
			}},
			Usage: openaisdk.Usage{PromptTokens: 10, CompletionTokens: 8},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	req := &llm.Request{
		Model: "gpt-4o", Messages: []llm.Message{{Role: "user", Content: "Hello"}},
		Temperature: 0.7, MaxTokens: 100,
	}
	resp, err := provider.Generate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "Hello! How can I help you?", resp.Content)
	assert.Equal(t, "stop", resp.FinishReason)
	assert.Equal(t, 10, resp.InputTokens)
	assert.Equal(t, 8, resp.OutputTokens)
	assert.Equal(t, "gpt-4o", resp.Model)
}

func TestOpenAIGenerate_APIError(t *testing.T) {
	_, provider := newOpenAITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{"message": "Invalid API key", "type": "invalid_request_error"},
		})
	})

	_, err := provider.Generate(context.Background(), &llm.Request{
		Model: "gpt-4o", Messages: []llm.Message{{Role: "user", Content: "Hello"}}, MaxTokens: 100,
	})
	require.Error(t, err)
	var pe *llm.ProviderError
	if assert.ErrorAs(t, err, &pe) {
		assert.Equal(t, "auth_failed", pe.Code)
	}
}

func TestOpenAIGenerate_RateLimit(t *testing.T) {
	_, provider := newOpenAITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": {"message": "rate limit exceeded"}}`))
	})

	_, err := provider.Generate(context.Background(), &llm.Request{
		Model: "gpt-4o", Messages: []llm.Message{{Role: "user", Content: "Hi"}}, MaxTokens: 10,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate_limit")
}

func TestOpenAIStream_Success(t *testing.T) {
	_, provider := newOpenAITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
	})

	ch := make(chan llm.StreamChunk, 4)
	err := provider.Stream(context.Background(), &llm.Request{
		Model: "gpt-4o", Messages: []llm.Message{{Role: "user", Content: "Hi"}}, MaxTokens: 10,
	}, ch)
	require.NoError(t, err)
	var chunks []llm.StreamChunk
	for c := range ch {
		chunks = append(chunks, c)
	}
	require.GreaterOrEqual(t, len(chunks), 1)
	assert.Equal(t, "Hi", chunks[0].Content)
}

func TestOpenAIMetadata(t *testing.T) {
	prov, _ := NewOpenAIProviderFromConfig("key", "")
	meta := prov.Metadata()
	assert.Equal(t, "openai", meta.ID)
	assert.Equal(t, "OpenAI", meta.DisplayName)
	assert.Equal(t, "US", meta.Jurisdiction)
	assert.True(t, meta.DPAAvailable)
	assert.True(t, meta.GDPRCompliant)
	assert.Equal(t, 10, meta.Wizard.Order)
	assert.Equal(t, "Direct API — US jurisdiction", meta.Wizard.Suffix)
}

func TestOpenAIValidateConfig(t *testing.T) {
	prov, _ := NewOpenAIProviderFromConfig("", "")
	err := prov.ValidateConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")

	prov2, _ := NewOpenAIProviderFromConfig("sk-x", "")
	err = prov2.ValidateConfig()
	require.NoError(t, err)
}

func TestOpenAIHealthCheck(t *testing.T) {
	prov, _ := NewOpenAIProviderFromConfig("", "")
	err := prov.HealthCheck(context.Background())
	assert.Error(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[]}`))
	}))
	defer ts.Close()
	prov2, _ := NewOpenAIProviderFromConfig("key", ts.URL+"/v1")
	prov2 = prov2.WithHTTPClient(ts.Client()).(*OpenAIProvider)
	err = prov2.HealthCheck(context.Background())
	require.NoError(t, err)
}

func TestOpenAIWithHTTPClient(t *testing.T) {
	prov, _ := NewOpenAIProviderFromConfig("key", "")
	p2 := prov.WithHTTPClient(&http.Client{})
	assert.NotNil(t, p2)
	assert.Equal(t, "openai", p2.Name())
}

func TestOpenAICostEstimation(t *testing.T) {
	provider, _ := NewOpenAIProviderFromConfig("dummy", "")
	tests := []struct {
		name         string
		model        string
		inputTokens  int
		outputTokens int
		wantPositive bool
	}{
		{"known model gpt-4o", "gpt-4o", 1000, 500, true},
		{"known model gpt-4o-mini", "gpt-4o-mini", 1000, 500, true},
		{"unknown model defaults", "gpt-new-model", 1000, 500, true},
		{"zero tokens", "gpt-4o", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := provider.EstimateCost(tt.model, tt.inputTokens, tt.outputTokens)
			if tt.wantPositive {
				assert.Greater(t, cost, 0.0)
			} else {
				assert.Equal(t, 0.0, cost)
			}
		})
	}
}

func TestOpenAIGenerate_WithToolCalls(t *testing.T) {
	_, provider := newOpenAITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		resp := openaisdk.ChatCompletionResponse{
			ID: "chatcmpl-toolcall", Model: "gpt-4o",
			Choices: []openaisdk.ChatCompletionChoice{{
				Message: openaisdk.ChatCompletionMessage{
					Role: "assistant", ToolCalls: []openaisdk.ToolCall{
						{ID: "call_abc", Type: openaisdk.ToolTypeFunction, Function: openaisdk.FunctionCall{Name: "get_weather", Arguments: `{"location":"Berlin"}`}},
					},
				},
				FinishReason: openaisdk.FinishReasonToolCalls,
			}},
			Usage: openaisdk.Usage{PromptTokens: 10, CompletionTokens: 20},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	resp, err := provider.Generate(context.Background(), &llm.Request{
		Model: "gpt-4o", Messages: []llm.Message{{Role: "user", Content: "What's the weather?"}}, MaxTokens: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, "tool_calls", resp.FinishReason)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "call_abc", resp.ToolCalls[0].ID)
	assert.Equal(t, "get_weather", resp.ToolCalls[0].Name)
}

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    string
	}{
		{"scheme+host gets /v1", "https://api.openai.com", "https://api.openai.com/v1"},
		{"already /v1 unchanged", "https://my-proxy.com/v1", "https://my-proxy.com/v1"},
		{"empty becomes /v1", "", "/v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeBaseURL(tt.baseURL)
			assert.Equal(t, tt.want, got)
		})
	}
}

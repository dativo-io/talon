package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	openai "github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newOpenAITestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *OpenAIProvider) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	config := openai.DefaultConfig("test-api-key")
	config.BaseURL = ts.URL + "/v1"
	client := openai.NewClientWithConfig(config)
	provider := newOpenAIProviderWithClient(client)
	return ts, provider
}

func TestOpenAIGenerate_Success(t *testing.T) {
	_, provider := newOpenAITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		resp := openai.ChatCompletionResponse{
			ID:    "chatcmpl-test123",
			Model: "gpt-4o",
			Choices: []openai.ChatCompletionChoice{
				{
					Message: openai.ChatCompletionMessage{
						Role:    "assistant",
						Content: "Hello! How can I help you?",
					},
					FinishReason: openai.FinishReasonStop,
				},
			},
			Usage: openai.Usage{
				PromptTokens:     10,
				CompletionTokens: 8,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	req := &Request{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: "Hello"},
		},
		Temperature: 0.7,
		MaxTokens:   100,
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
			"error": map[string]interface{}{
				"message": "Invalid API key",
				"type":    "invalid_request_error",
			},
		})
	})

	req := &Request{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: "Hello"},
		},
		MaxTokens: 100,
	}

	_, err := provider.Generate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "openai api call")
}

func TestOpenAICostEstimation(t *testing.T) {
	provider := NewOpenAIProvider("dummy")

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
		resp := openai.ChatCompletionResponse{
			ID:    "chatcmpl-toolcall",
			Model: "gpt-4o",
			Choices: []openai.ChatCompletionChoice{
				{
					Message: openai.ChatCompletionMessage{
						Role:      "assistant",
						Content:   "",
						ToolCalls: []openai.ToolCall{{ID: "call_abc", Type: openai.ToolTypeFunction, Function: openai.FunctionCall{Name: "get_weather", Arguments: `{"location":"Berlin"}`}}},
					},
					FinishReason: openai.FinishReasonToolCalls,
				},
			},
			Usage: openai.Usage{PromptTokens: 10, CompletionTokens: 20},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	req := &Request{
		Model:     "gpt-4o",
		Messages:  []Message{{Role: "user", Content: "What's the weather?"}},
		MaxTokens: 100,
	}
	resp, err := provider.Generate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "tool_calls", resp.FinishReason)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "call_abc", resp.ToolCalls[0].ID)
	assert.Equal(t, "get_weather", resp.ToolCalls[0].Name)
	assert.Equal(t, map[string]interface{}{"location": "Berlin"}, resp.ToolCalls[0].Arguments)
}

func TestOpenAIGenerate_WithToolsInRequest(t *testing.T) {
	var receivedBody map[string]interface{}
	_, provider := newOpenAITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&receivedBody))
		resp := openai.ChatCompletionResponse{
			ID:      "chatcmpl-ok",
			Model:   "gpt-4o",
			Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Role: "assistant", Content: "Done."}, FinishReason: openai.FinishReasonStop}},
			Usage:   openai.Usage{PromptTokens: 20, CompletionTokens: 5},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	req := &Request{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: "Hello"},
			{Role: "assistant", Content: "", ToolCalls: []ToolCall{{ID: "call_1", Name: "echo", Arguments: map[string]interface{}{"x": "1"}}}},
			{Role: "tool", Content: `{"result":"ok"}`, ToolCallID: "call_1"},
		},
		Tools:     []Tool{{Name: "echo", Description: "Echo", Parameters: map[string]interface{}{"type": "object"}}},
		MaxTokens: 100,
	}
	_, err := provider.Generate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, receivedBody)
	tools, _ := receivedBody["tools"].([]interface{})
	require.NotEmpty(t, tools)
	msgs, _ := receivedBody["messages"].([]interface{})
	require.Len(t, msgs, 3)
	// Second message should have tool_calls; third should have tool_call_id
	msg1, _ := msgs[1].(map[string]interface{})
	assert.NotNil(t, msg1["tool_calls"])
	msg2, _ := msgs[2].(map[string]interface{})
	assert.Equal(t, "call_1", msg2["tool_call_id"])
}

func TestNormalizeOpenAIBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    string
	}{
		{"scheme+host gets /v1", "https://api.openai.com", "https://api.openai.com/v1"},
		{"scheme+host+port", "http://localhost:8080", "http://localhost:8080/v1"},
		{"already /v1 unchanged", "https://my-proxy.com/v1", "https://my-proxy.com/v1"},
		{"already /v1/ trimmed then unchanged", "https://my-proxy.com/v1/", "https://my-proxy.com/v1"},
		{"trailing slash no v1", "https://proxy.com/", "https://proxy.com/v1"},
		{"empty becomes /v1", "", "/v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeOpenAIBaseURL(tt.baseURL)
			assert.Equal(t, tt.want, got, "OPENAI_BASE_URL convention: no double /v1/v1")
		})
	}
}

package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAnthropicTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *AnthropicProvider) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	provider := &AnthropicProvider{
		apiKey:     "test-anthropic-key",
		httpClient: ts.Client(),
		baseURL:    ts.URL,
	}
	return ts, provider
}

func TestAnthropicGenerate_Success(t *testing.T) {
	_, provider := newAnthropicTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify Anthropic-specific headers
		assert.Equal(t, "test-anthropic-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body structure
		var reqBody anthropicRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)
		assert.Equal(t, "claude-sonnet-4-20250514", reqBody.Model)
		assert.Equal(t, 100, reqBody.MaxTokens)

		resp := anthropicResponse{
			ID: "msg_test123",
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{
				{Type: "text", Text: "Hello from Claude!"},
			},
			StopReason: "end_turn",
			Usage: struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			}{
				InputTokens:  15,
				OutputTokens: 5,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	req := &Request{
		Model: "claude-sonnet-4-20250514",
		Messages: []Message{
			{Role: "user", Content: "Hello Claude"},
		},
		Temperature: 0.7,
		MaxTokens:   100,
	}

	resp, err := provider.Generate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "Hello from Claude!", resp.Content)
	assert.Equal(t, "end_turn", resp.FinishReason)
	assert.Equal(t, 15, resp.InputTokens)
	assert.Equal(t, 5, resp.OutputTokens)
	assert.Equal(t, "claude-sonnet-4-20250514", resp.Model)
}

func TestAnthropicGenerate_SystemPromptExtraction(t *testing.T) {
	_, provider := newAnthropicTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var reqBody anthropicRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)

		// System message should be extracted to top-level field, not in messages array
		assert.Equal(t, "You are a helpful assistant.", reqBody.System)
		for _, msg := range reqBody.Messages {
			assert.NotEqual(t, "system", msg.Role, "system messages must not appear in messages array")
		}
		assert.Len(t, reqBody.Messages, 1)
		assert.Equal(t, "user", reqBody.Messages[0].Role)

		resp := anthropicResponse{
			ID: "msg_test456",
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{
				{Type: "text", Text: "OK"},
			},
			StopReason: "end_turn",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	req := &Request{
		Model: "claude-sonnet-4-20250514",
		Messages: []Message{
			{Role: "system", Content: "You are a helpful assistant."},
			{Role: "user", Content: "Hello"},
		},
		MaxTokens: 100,
	}

	resp, err := provider.Generate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "OK", resp.Content)
}

func TestAnthropicGenerate_MultipleContentBlocks(t *testing.T) {
	_, provider := newAnthropicTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Simulate response with multiple text blocks and a leading non-text block
		// (e.g. tool_use); only text blocks should be concatenated.
		resp := anthropicResponse{
			ID: "msg_multi",
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{
				{Type: "tool_use", Text: ""}, // non-text first
				{Type: "text", Text: "First part. "},
				{Type: "text", Text: "Second part. "},
				{Type: "text", Text: "Third part."},
			},
			StopReason: "end_turn",
			Usage: struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			}{
				InputTokens:  10,
				OutputTokens: 12,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	req := &Request{
		Model:     "claude-sonnet-4-20250514",
		Messages:  []Message{{Role: "user", Content: "Hi"}},
		MaxTokens: 100,
	}

	resp, err := provider.Generate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "First part. Second part. Third part.", resp.Content,
		"multiple text blocks must be concatenated; non-text blocks must be skipped")
}

func TestAnthropicGenerate_APIError(t *testing.T) {
	_, provider := newAnthropicTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"Rate limit exceeded"}}`))
	})

	req := &Request{
		Model: "claude-sonnet-4-20250514",
		Messages: []Message{
			{Role: "user", Content: "Hello"},
		},
		MaxTokens: 100,
	}

	_, err := provider.Generate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "anthropic api error 429")
}

func TestAnthropicCostEstimation(t *testing.T) {
	provider := NewAnthropicProvider("dummy")

	tests := []struct {
		name         string
		model        string
		inputTokens  int
		outputTokens int
		wantPositive bool
	}{
		{"known model claude-sonnet", "claude-sonnet-4-20250514", 1000, 500, true},
		{"known model claude-opus", "claude-opus-4-5-20251101", 1000, 500, true},
		{"unknown model defaults", "claude-new-model", 1000, 500, true},
		{"zero tokens", "claude-sonnet-4-20250514", 0, 0, false},
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

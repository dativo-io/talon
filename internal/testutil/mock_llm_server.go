package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// OpenAICompatibleResponse is the minimal chat completions response for tests.
type OpenAICompatibleResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// NewOpenAICompatibleServer starts an httptest.Server that responds to
// POST /v1/chat/completions with a minimal valid OpenAI-style JSON response.
// Content is the assistant message body; inputTokens/outputTokens set usage.
// Caller must call server.Close() or register t.Cleanup(server.Close).
func NewOpenAICompatibleServer(content string, inputTokens, outputTokens int) *httptest.Server {
	if content == "" {
		content = "mock response"
	}
	if inputTokens == 0 {
		inputTokens = 10
	}
	if outputTokens == 0 {
		outputTokens = 20
	}
	resp := OpenAICompatibleResponse{
		ID:     "chatcmpl-test",
		Object: "chat.completion",
		Model:  "gpt-4o",
		Choices: []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		}{
			{
				Message: struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				}{Role: "assistant", Content: content},
				FinishReason: "stop",
			},
		},
		Usage: struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		}{
			PromptTokens:     inputTokens,
			CompletionTokens: outputTokens,
			TotalTokens:      inputTokens + outputTokens,
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/v1/chat/completions/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(handler)
}

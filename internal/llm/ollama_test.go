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

func TestOllamaGenerate(t *testing.T) {
	ctx := context.Background()

	t.Run("successful response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/chat", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var reqBody ollamaRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))
			assert.Equal(t, "llama3.1:70b", reqBody.Model)
			assert.False(t, reqBody.Stream)
			assert.Len(t, reqBody.Messages, 1)
			assert.Equal(t, "user", reqBody.Messages[0].Role)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ollamaResponse{
				Message: struct {
					Content string `json:"content"`
				}{Content: "Hello from Ollama!"},
			})
		}))
		defer server.Close()

		provider := NewOllamaProvider(server.URL)
		resp, err := provider.Generate(ctx, &Request{
			Model:    "llama3.1:70b",
			Messages: []Message{{Role: "user", Content: "Hi"}},
		})

		require.NoError(t, err)
		assert.Equal(t, "Hello from Ollama!", resp.Content)
		assert.Equal(t, "stop", resp.FinishReason)
		assert.Equal(t, "llama3.1:70b", resp.Model)
	})

	t.Run("non-2xx status returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"model 'nonexistent' not found"}`))
		}))
		defer server.Close()

		provider := NewOllamaProvider(server.URL)
		resp, err := provider.Generate(ctx, &Request{
			Model:    "nonexistent",
			Messages: []Message{{Role: "user", Content: "Hi"}},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ollama api error 404")
		assert.Contains(t, err.Error(), "model 'nonexistent' not found")
	})

	t.Run("500 internal server error returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		}))
		defer server.Close()

		provider := NewOllamaProvider(server.URL)
		resp, err := provider.Generate(ctx, &Request{
			Model:    "llama3.1:70b",
			Messages: []Message{{Role: "user", Content: "Hi"}},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ollama api error 500")
	})

	t.Run("invalid JSON in 200 response returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{invalid json`))
		}))
		defer server.Close()

		provider := NewOllamaProvider(server.URL)
		resp, err := provider.Generate(ctx, &Request{
			Model:    "llama3.1:70b",
			Messages: []Message{{Role: "user", Content: "Hi"}},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding ollama response")
	})

	t.Run("empty content in valid response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ollamaResponse{})
		}))
		defer server.Close()

		provider := NewOllamaProvider(server.URL)
		resp, err := provider.Generate(ctx, &Request{
			Model:    "llama3.1:70b",
			Messages: []Message{{Role: "user", Content: "Hi"}},
		})

		require.NoError(t, err)
		assert.Equal(t, "", resp.Content, "empty content from a 200 is valid")
	})

	t.Run("connection refused returns error", func(t *testing.T) {
		provider := NewOllamaProvider("http://127.0.0.1:1")
		resp, err := provider.Generate(ctx, &Request{
			Model:    "llama3.1:70b",
			Messages: []Message{{Role: "user", Content: "Hi"}},
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ollama api call")
	})

	t.Run("token estimation from content length", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ollamaResponse{
				Message: struct {
					Content string `json:"content"`
				}{Content: "This is a twenty char"},
			})
		}))
		defer server.Close()

		provider := NewOllamaProvider(server.URL)
		resp, err := provider.Generate(ctx, &Request{
			Model:    "llama3.1:70b",
			Messages: []Message{{Role: "user", Content: "Hello, world!"}},
		})

		require.NoError(t, err)
		assert.Equal(t, len("Hello, world!")/4, resp.InputTokens)
		assert.Equal(t, len("This is a twenty char")/4, resp.OutputTokens)
	})

	t.Run("system and user messages forwarded", func(t *testing.T) {
		var capturedMessages []ollamaMessage
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody ollamaRequest
			json.NewDecoder(r.Body).Decode(&reqBody)
			capturedMessages = reqBody.Messages

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ollamaResponse{
				Message: struct {
					Content string `json:"content"`
				}{Content: "ok"},
			})
		}))
		defer server.Close()

		provider := NewOllamaProvider(server.URL)
		_, err := provider.Generate(ctx, &Request{
			Model: "llama3.1:70b",
			Messages: []Message{
				{Role: "system", Content: "You are helpful."},
				{Role: "user", Content: "Hello"},
			},
		})

		require.NoError(t, err)
		require.Len(t, capturedMessages, 2)
		assert.Equal(t, "system", capturedMessages[0].Role)
		assert.Equal(t, "You are helpful.", capturedMessages[0].Content)
		assert.Equal(t, "user", capturedMessages[1].Role)
		assert.Equal(t, "Hello", capturedMessages[1].Content)
	})
}

func TestNewOllamaProvider(t *testing.T) {
	t.Run("default base URL", func(t *testing.T) {
		p := NewOllamaProvider("")
		assert.Equal(t, "http://localhost:11434", p.baseURL)
	})

	t.Run("custom base URL", func(t *testing.T) {
		p := NewOllamaProvider("http://ollama:11434")
		assert.Equal(t, "http://ollama:11434", p.baseURL)
	})
}

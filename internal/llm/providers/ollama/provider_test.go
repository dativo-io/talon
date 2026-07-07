package ollama

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/llm"
)

func TestOllamaGenerate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/chat", r.URL.Path)
		var reqBody ollamaRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))
		assert.Equal(t, "llama3.1:70b", reqBody.Model)
		assert.False(t, reqBody.Stream)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ollamaResponse{
			Message: struct {
				Content string `json:"content"`
			}{Content: "Hello from Ollama!"},
		})
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)
	resp, err := provider.Generate(context.Background(), &llm.Request{
		Model: "llama3.1:70b", Messages: []llm.Message{{Role: "user", Content: "Hi"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "Hello from Ollama!", resp.Content)
	assert.Equal(t, "stop", resp.FinishReason)
	assert.Equal(t, "llama3.1:70b", resp.Model)
}

// The runner sets MaxTokens to bound generation; Ollama honors it only via
// options.num_predict. Without this, a slow local model generates unbounded
// and blows past the caller's call timeout (seen live on a small CPU host).
func TestOllamaGenerate_MaxTokensBecomesNumPredict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody ollamaRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))
		require.NotNil(t, reqBody.Options, "MaxTokens must produce an options block")
		assert.Equal(t, 128, reqBody.Options.NumPredict)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ollamaResponse{Message: struct {
			Content string `json:"content"`
		}{Content: "ok"}})
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)
	_, err := provider.Generate(context.Background(), &llm.Request{
		Model: "llama3.2:1b", Messages: []llm.Message{{Role: "user", Content: "Hi"}}, MaxTokens: 128,
	})
	require.NoError(t, err)
}

// No MaxTokens → no options block (backward compatible).
func TestOllamaGenerate_NoMaxTokens_NoOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody ollamaRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))
		assert.Nil(t, reqBody.Options)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ollamaResponse{Message: struct {
			Content string `json:"content"`
		}{Content: "ok"}})
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)
	_, err := provider.Generate(context.Background(), &llm.Request{
		Model: "llama3.2:1b", Messages: []llm.Message{{Role: "user", Content: "Hi"}},
	})
	require.NoError(t, err)
}

func TestOllamaGenerate_Non2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"model not found"}`))
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)
	_, err := provider.Generate(context.Background(), &llm.Request{
		Model: "nonexistent", Messages: []llm.Message{{Role: "user", Content: "Hi"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestOllamaHealthCheck_ConnectionRefused(t *testing.T) {
	provider := NewOllamaProvider("http://127.0.0.1:1")
	err := provider.HealthCheck(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ollama not reachable")
	assert.Contains(t, err.Error(), "ollama serve")
}

func TestOllamaHealthCheck_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/tags", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"models":[]}`))
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)
	err := provider.HealthCheck(context.Background())
	require.NoError(t, err)
}

func TestOllamaMetadata(t *testing.T) {
	prov := NewOllamaProvider("")
	meta := prov.Metadata()
	assert.Equal(t, "ollama", meta.ID)
	assert.Equal(t, "LOCAL", meta.Jurisdiction)
	assert.True(t, meta.Wizard.SuggestEUStrict)
	assert.Equal(t, 60, meta.Wizard.Order)
}

func TestOllamaValidateConfig(t *testing.T) {
	prov := NewOllamaProvider("http://localhost:11434")
	require.NoError(t, prov.ValidateConfig())
}

func TestOllamaWithHTTPClient(t *testing.T) {
	prov := NewOllamaProvider("http://x")
	p2 := prov.WithHTTPClient(&http.Client{})
	assert.NotNil(t, p2)
}

func TestOllamaCostEstimation(t *testing.T) {
	prov := NewOllamaProvider("")
	assert.Equal(t, 0.0, prov.EstimateCost("llama3", 100, 50))
}

// TestOllamaStream_ClosesChannelOnError ensures Stream closes ch on error paths
// so callers ranging over ch do not block forever (goroutine leak).
func TestOllamaStream_ClosesChannelOnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	provider := NewOllamaProvider(server.URL)
	ch := make(chan llm.StreamChunk, 4)
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	err := provider.Stream(context.Background(), &llm.Request{
		Model: "llama3", Messages: []llm.Message{{Role: "user", Content: "Hi"}},
	}, ch)
	require.Error(t, err)
	<-done // would block forever if ch were not closed
}

package mistral

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

func TestMistralMetadata(t *testing.T) {
	p := &MistralProvider{}
	meta := p.Metadata()
	assert.Equal(t, "mistral", meta.ID)
	assert.Equal(t, "EU", meta.Jurisdiction)
	assert.Equal(t, 50, meta.Wizard.Order)
}

func TestMistralGenerate_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "Hi"}, "finish_reason": "stop"},
			},
			"usage": map[string]int{"prompt_tokens": 5, "completion_tokens": 2},
		})
	}))
	defer ts.Close()
	p := &MistralProvider{apiKey: "key", baseURL: ts.URL, httpClient: ts.Client()}
	resp, err := p.Generate(context.Background(), &llm.Request{
		Model: "mistral-small", Messages: []llm.Message{{Role: "user", Content: "Hi"}}, MaxTokens: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, "Hi", resp.Content)
}

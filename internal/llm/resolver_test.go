package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProviderWithKey_OpenAI(t *testing.T) {
	p := NewProviderWithKey("openai", "sk-test")
	require.NotNil(t, p)
	assert.Equal(t, "openai", p.Name())
}

func TestNewProviderWithKey_Anthropic(t *testing.T) {
	p := NewProviderWithKey("anthropic", "ant-test")
	require.NotNil(t, p)
	assert.Equal(t, "anthropic", p.Name())
}

func TestNewProviderWithKey_Ollama_ReturnsNil(t *testing.T) {
	p := NewProviderWithKey("ollama", "")
	assert.Nil(t, p)
}

func TestNewProviderWithKey_Bedrock_ReturnsNil(t *testing.T) {
	p := NewProviderWithKey("bedrock", "")
	assert.Nil(t, p)
}

func TestNewProviderWithKey_Unknown_ReturnsNil(t *testing.T) {
	p := NewProviderWithKey("unknown-provider", "key")
	assert.Nil(t, p)
}

func TestProviderUsesAPIKey(t *testing.T) {
	tests := []struct {
		provider string
		want     bool
	}{
		{"openai", true},
		{"anthropic", true},
		{"ollama", false},
		{"bedrock", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			assert.Equal(t, tt.want, ProviderUsesAPIKey(tt.provider))
		})
	}
}

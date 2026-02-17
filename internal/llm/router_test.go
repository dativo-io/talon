package llm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

// mockProvider implements Provider for testing without actual API calls.
type mockProvider struct {
	name string
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Generate(ctx context.Context, req *Request) (*Response, error) {
	return &Response{
		Content:      "mock response",
		FinishReason: "stop",
		InputTokens:  10,
		OutputTokens: 5,
		Model:        req.Model,
	}, nil
}
func (m *mockProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	return 0.001
}

func TestRouterRoute(t *testing.T) {
	providers := map[string]Provider{
		"openai":    &mockProvider{name: "openai"},
		"anthropic": &mockProvider{name: "anthropic"},
		"bedrock":   &mockProvider{name: "bedrock"},
		"ollama":    &mockProvider{name: "ollama"},
	}

	routing := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{
			Primary:  "gpt-4o-mini",
			Location: "global",
		},
		Tier1: &policy.TierConfig{
			Primary:  "claude-sonnet-4-20250514",
			Fallback: "gpt-4o",
			Location: "eu",
		},
		Tier2: &policy.TierConfig{
			Primary:     "anthropic.claude-3-sonnet-20240229-v1:0",
			Location:    "eu-central-1",
			BedrockOnly: true,
		},
	}

	router := NewRouter(routing, providers)
	ctx := context.Background()

	t.Run("tier 0 routes to OpenAI", func(t *testing.T) {
		provider, model, err := router.Route(ctx, 0)
		require.NoError(t, err)
		assert.Equal(t, "openai", provider.Name())
		assert.Equal(t, "gpt-4o-mini", model)
	})

	t.Run("tier 1 routes to Anthropic", func(t *testing.T) {
		provider, model, err := router.Route(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, "anthropic", provider.Name())
		assert.Equal(t, "claude-sonnet-4-20250514", model)
	})

	t.Run("tier 2 routes to Bedrock", func(t *testing.T) {
		provider, model, err := router.Route(ctx, 2)
		require.NoError(t, err)
		assert.Equal(t, "bedrock", provider.Name())
		assert.Equal(t, "anthropic.claude-3-sonnet-20240229-v1:0", model)
	})

	t.Run("invalid tier returns error", func(t *testing.T) {
		_, _, err := router.Route(ctx, 5)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTier)
	})
}

func TestRouterFallback(t *testing.T) {
	// Only openai available, not anthropic
	providers := map[string]Provider{
		"openai": &mockProvider{name: "openai"},
	}

	routing := &policy.ModelRoutingConfig{
		Tier1: &policy.TierConfig{
			Primary:  "claude-sonnet-4-20250514",
			Fallback: "gpt-4o",
			Location: "eu",
		},
	}

	router := NewRouter(routing, providers)
	ctx := context.Background()

	t.Run("falls back to openai when anthropic unavailable", func(t *testing.T) {
		provider, model, err := router.Route(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, "openai", provider.Name())
		assert.Equal(t, "gpt-4o", model)
	})
}

func TestRouterNoProvider(t *testing.T) {
	providers := map[string]Provider{
		"ollama": &mockProvider{name: "ollama"},
	}

	routing := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{
			Primary: "gpt-4o",
		},
	}

	router := NewRouter(routing, providers)
	ctx := context.Background()

	t.Run("returns error when no provider available", func(t *testing.T) {
		_, _, err := router.Route(ctx, 0)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderNotAvailable)
	})
}

func TestRouterNilRouting(t *testing.T) {
	router := NewRouter(nil, map[string]Provider{})
	ctx := context.Background()

	_, _, err := router.Route(ctx, 0)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoRoutingConfig)
}

func TestRouterMissingTierConfig(t *testing.T) {
	routing := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4o"},
		// Tier1 and Tier2 not configured
	}

	router := NewRouter(routing, map[string]Provider{
		"openai": &mockProvider{name: "openai"},
	})
	ctx := context.Background()

	t.Run("tier 0 works", func(t *testing.T) {
		_, _, err := router.Route(ctx, 0)
		require.NoError(t, err)
	})

	t.Run("tier 1 returns error", func(t *testing.T) {
		_, _, err := router.Route(ctx, 1)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoRoutingConfig)
	})

	t.Run("tier 2 returns error", func(t *testing.T) {
		_, _, err := router.Route(ctx, 2)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoRoutingConfig)
	})
}

func TestInferProvider(t *testing.T) {
	tests := []struct {
		model    string
		wantProv string
	}{
		{"gpt-4o", "openai"},
		{"gpt-4o-mini", "openai"},
		{"gpt-3.5-turbo", "openai"},
		{"claude-sonnet-4-20250514", "anthropic"},
		{"claude-haiku-3-5-20241022", "anthropic"},
		{"anthropic.claude-3-sonnet-20240229-v1:0", "bedrock"},
		{"amazon.titan-text-premier-v1:0", "bedrock"},
		{"llama3.1:70b", "ollama"},
		{"mistral:7b", "ollama"},
		{"gemma:2b", "ollama"},
		{"phi3:mini", "ollama"},
		{"unknown-model", "openai"}, // default
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			got := inferProvider(tt.model)
			assert.Equal(t, tt.wantProv, got)
		})
	}
}

func TestProviderCostEstimation(t *testing.T) {
	t.Run("openai cost", func(t *testing.T) {
		p := &OpenAIProvider{}
		cost := p.EstimateCost("gpt-4o", 1000, 500)
		assert.Greater(t, cost, 0.0)
	})

	t.Run("anthropic cost", func(t *testing.T) {
		p := &AnthropicProvider{}
		cost := p.EstimateCost("claude-sonnet-4-20250514", 1000, 500)
		assert.Greater(t, cost, 0.0)
	})

	t.Run("ollama cost is zero", func(t *testing.T) {
		p := &OllamaProvider{}
		cost := p.EstimateCost("llama3.1:70b", 1000, 500)
		assert.Equal(t, 0.0, cost)
	})

	t.Run("bedrock cost", func(t *testing.T) {
		p := &BedrockProvider{region: "eu-central-1"}
		cost := p.EstimateCost("anthropic.claude-3-sonnet-20240229-v1:0", 1000, 500)
		assert.Greater(t, cost, 0.0)
	})

	t.Run("unknown model uses default pricing", func(t *testing.T) {
		p := &OpenAIProvider{}
		cost := p.EstimateCost("unknown-model", 1000, 500)
		assert.Greater(t, cost, 0.0, "should use default gpt-4o pricing")
	})
}

func TestProviderNames(t *testing.T) {
	assert.Equal(t, "openai", (&OpenAIProvider{}).Name())
	assert.Equal(t, "anthropic", (&AnthropicProvider{}).Name())
	assert.Equal(t, "ollama", (&OllamaProvider{}).Name())
	assert.Equal(t, "bedrock", (&BedrockProvider{}).Name())
}

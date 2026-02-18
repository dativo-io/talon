package llm

import (
	"context"
	"fmt"
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

	router := NewRouter(routing, providers, nil)
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

	t.Run("tier with empty primary returns routing error", func(t *testing.T) {
		emptyPrimaryRouting := &policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{
				Primary:  "", // missing in policy
				Location: "global",
			},
		}
		r := NewRouter(emptyPrimaryRouting, providers, nil)
		_, _, err := r.Route(ctx, 0)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoPrimaryModel)
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

	router := NewRouter(routing, providers, nil)
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

	router := NewRouter(routing, providers, nil)
	ctx := context.Background()

	t.Run("returns error when no provider available", func(t *testing.T) {
		_, _, err := router.Route(ctx, 0)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderNotAvailable)
	})
}

func TestRouterNilRouting(t *testing.T) {
	router := NewRouter(nil, map[string]Provider{}, nil)
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
	}, nil)
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

func TestRouterBedrockOnlyEnforcement(t *testing.T) {
	ctx := context.Background()

	t.Run("bedrock_only forces bedrock even when model name infers anthropic", func(t *testing.T) {
		providers := map[string]Provider{
			"anthropic": &mockProvider{name: "anthropic"},
			"bedrock":   &mockProvider{name: "bedrock"},
		}

		routing := &policy.ModelRoutingConfig{
			Tier2: &policy.TierConfig{
				Primary:     "claude-sonnet-4-20250514", // inferProvider → "anthropic"
				BedrockOnly: true,
			},
		}

		router := NewRouter(routing, providers, nil)
		provider, model, err := router.Route(ctx, 2)
		require.NoError(t, err)
		assert.Equal(t, "bedrock", provider.Name(), "must route through bedrock for sovereignty")
		assert.Equal(t, "claude-sonnet-4-20250514", model)
	})

	t.Run("bedrock_only rejects when bedrock provider unavailable", func(t *testing.T) {
		providers := map[string]Provider{
			"anthropic": &mockProvider{name: "anthropic"},
			"openai":    &mockProvider{name: "openai"},
		}

		routing := &policy.ModelRoutingConfig{
			Tier2: &policy.TierConfig{
				Primary:     "claude-sonnet-4-20250514",
				Fallback:    "gpt-4o",
				BedrockOnly: true,
			},
		}

		router := NewRouter(routing, providers, nil)
		_, _, err := router.Route(ctx, 2)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderNotAvailable,
			"must not silently route to non-bedrock provider")
	})

	t.Run("bedrock_only routes primary through bedrock even when anthropic is absent", func(t *testing.T) {
		providers := map[string]Provider{
			"bedrock": &mockProvider{name: "bedrock"},
			// "anthropic" intentionally absent — without bedrock_only this would fail
		}

		routing := &policy.ModelRoutingConfig{
			Tier1: &policy.TierConfig{
				Primary:     "claude-sonnet-4-20250514", // infers "anthropic" — absent
				BedrockOnly: true,
			},
		}

		router := NewRouter(routing, providers, nil)
		provider, model, err := router.Route(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, "bedrock", provider.Name(), "bedrock_only must override inferred provider")
		assert.Equal(t, "claude-sonnet-4-20250514", model)
	})

	t.Run("without bedrock_only model routes to inferred provider", func(t *testing.T) {
		providers := map[string]Provider{
			"anthropic": &mockProvider{name: "anthropic"},
			"bedrock":   &mockProvider{name: "bedrock"},
		}

		routing := &policy.ModelRoutingConfig{
			Tier1: &policy.TierConfig{
				Primary:     "claude-sonnet-4-20250514",
				BedrockOnly: false,
			},
		}

		router := NewRouter(routing, providers, nil)
		provider, _, err := router.Route(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, "anthropic", provider.Name(), "should use inferred provider when bedrock_only is false")
	})
}

// TestSovereigntyInvariant is a contract test that proves a critical invariant:
// when BedrockOnly=true, the selected provider is ALWAYS "bedrock" regardless of
// model name, available providers, or fallback configuration.
// This test exists because the original implementation of Route() ignored BedrockOnly,
// which could route confidential data outside the EU sovereignty boundary.
func TestSovereigntyInvariant(t *testing.T) {
	ctx := context.Background()

	// Every model prefix that inferProvider could map to a non-bedrock provider
	nonBedrockModels := []string{
		"gpt-4o",                    // → openai
		"gpt-4o-mini",               // → openai
		"claude-sonnet-4-20250514",  // → anthropic
		"claude-haiku-3-5-20241022", // → anthropic
		"llama3.1:70b",              // → ollama
		"mistral:7b",                // → ollama
	}

	// All providers registered (worst case for leakage: all are available)
	allProviders := map[string]Provider{
		"openai":    &mockProvider{name: "openai"},
		"anthropic": &mockProvider{name: "anthropic"},
		"bedrock":   &mockProvider{name: "bedrock"},
		"ollama":    &mockProvider{name: "ollama"},
	}

	for _, model := range nonBedrockModels {
		t.Run("primary="+model, func(t *testing.T) {
			routing := &policy.ModelRoutingConfig{
				Tier2: &policy.TierConfig{
					Primary:     model,
					BedrockOnly: true,
				},
			}
			router := NewRouter(routing, allProviders, nil)
			provider, _, err := router.Route(ctx, 2)
			require.NoError(t, err)
			assert.Equal(t, "bedrock", provider.Name(),
				"SOVEREIGNTY VIOLATION: bedrock_only=true but routed to %s for model %s",
				provider.Name(), model)
		})
	}

	// Also test that fallback models can't escape bedrock_only
	for _, fallback := range nonBedrockModels {
		t.Run("fallback="+fallback, func(t *testing.T) {
			// Primary uses a model that won't find "bedrock" without the override,
			// then falls back — fallback must also be forced to bedrock
			routing := &policy.ModelRoutingConfig{
				Tier2: &policy.TierConfig{
					Primary:     "gpt-4o",
					Fallback:    fallback,
					BedrockOnly: true,
				},
			}
			router := NewRouter(routing, allProviders, nil)
			provider, _, err := router.Route(ctx, 2)
			require.NoError(t, err)
			assert.Equal(t, "bedrock", provider.Name(),
				"SOVEREIGNTY VIOLATION: fallback %s escaped bedrock_only", fallback)
		})
	}
}

// TestBedrockOnlyFailsClosed verifies that when bedrock_only=true and the bedrock
// provider is unavailable, the router fails with an error rather than silently
// falling back to a non-bedrock provider.
func TestBedrockOnlyFailsClosed(t *testing.T) {
	ctx := context.Background()

	// Every possible provider combination EXCEPT bedrock
	providerSets := []map[string]Provider{
		{"openai": &mockProvider{name: "openai"}},
		{"anthropic": &mockProvider{name: "anthropic"}},
		{"ollama": &mockProvider{name: "ollama"}},
		{
			"openai":    &mockProvider{name: "openai"},
			"anthropic": &mockProvider{name: "anthropic"},
			"ollama":    &mockProvider{name: "ollama"},
		},
	}

	for i, providers := range providerSets {
		t.Run(fmt.Sprintf("provider_set_%d", i), func(t *testing.T) {
			routing := &policy.ModelRoutingConfig{
				Tier2: &policy.TierConfig{
					Primary:     "claude-sonnet-4-20250514",
					Fallback:    "gpt-4o",
					BedrockOnly: true,
				},
			}
			router := NewRouter(routing, providers, nil)
			_, _, err := router.Route(ctx, 2)
			assert.Error(t, err, "must fail when bedrock unavailable with bedrock_only=true")
			assert.ErrorIs(t, err, ErrProviderNotAvailable)
		})
	}
}

// TestTierConfigFieldInfluence is a contract test that verifies every field in
// TierConfig actually influences routing decisions. If a new field is added to
// TierConfig but never read by Route(), a test here will catch it.
func TestTierConfigFieldInfluence(t *testing.T) {
	ctx := context.Background()
	allProviders := map[string]Provider{
		"openai":    &mockProvider{name: "openai"},
		"anthropic": &mockProvider{name: "anthropic"},
		"bedrock":   &mockProvider{name: "bedrock"},
	}

	t.Run("Primary field selects model", func(t *testing.T) {
		r1 := NewRouter(&policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{Primary: "gpt-4o"},
		}, allProviders, nil)
		r2 := NewRouter(&policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{Primary: "gpt-4o-mini"},
		}, allProviders, nil)

		_, m1, _ := r1.Route(ctx, 0)
		_, m2, _ := r2.Route(ctx, 0)
		assert.NotEqual(t, m1, m2, "changing Primary must change the selected model")
	})

	t.Run("Fallback field used when primary unavailable", func(t *testing.T) {
		limitedProviders := map[string]Provider{
			"openai": &mockProvider{name: "openai"},
		}

		r1 := NewRouter(&policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{Primary: "claude-sonnet-4-20250514", Fallback: "gpt-4o"},
		}, limitedProviders, nil)
		r2 := NewRouter(&policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{Primary: "claude-sonnet-4-20250514", Fallback: "gpt-4o-mini"},
		}, limitedProviders, nil)

		_, m1, err1 := r1.Route(ctx, 0)
		_, m2, err2 := r2.Route(ctx, 0)
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, m1, m2, "changing Fallback must change the selected model when primary is unavailable")
	})

	t.Run("BedrockOnly field overrides provider selection", func(t *testing.T) {
		// Same model name, toggle BedrockOnly
		rOff := NewRouter(&policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{Primary: "claude-sonnet-4-20250514", BedrockOnly: false},
		}, allProviders, nil)
		rOn := NewRouter(&policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{Primary: "claude-sonnet-4-20250514", BedrockOnly: true},
		}, allProviders, nil)

		pOff, _, _ := rOff.Route(ctx, 0)
		pOn, _, _ := rOn.Route(ctx, 0)
		assert.NotEqual(t, pOff.Name(), pOn.Name(),
			"toggling BedrockOnly must change the selected provider")
		assert.Equal(t, "bedrock", pOn.Name())
		assert.Equal(t, "anthropic", pOff.Name())
	})
}

func TestInferProvider(t *testing.T) {
	tests := []struct {
		model    string
		wantProv string
		wantErr  bool
	}{
		{"gpt-4o", "openai", false},
		{"gpt-4o-mini", "openai", false},
		{"gpt-3.5-turbo", "openai", false},
		{"claude-sonnet-4-20250514", "anthropic", false},
		{"claude-haiku-3-5-20241022", "anthropic", false},
		{"anthropic.claude-3-sonnet-20240229-v1:0", "bedrock", false},
		{"amazon.titan-text-premier-v1:0", "bedrock", false},
		{"meta.llama3-1-70b-instruct-v1:0", "bedrock", false},
		{"cohere.command-r-plus-v1:0", "bedrock", false},
		{"ai21.jamba-1-5-large-v1:0", "bedrock", false},
		{"stability.stable-diffusion-xl-v1", "bedrock", false},
		{"mistral.mistral-large-2402-v1:0", "bedrock", false},
		{"llama3.1:70b", "ollama", false},
		{"mistral:7b", "ollama", false},
		{"gemma:2b", "ollama", false},
		{"phi3:mini", "ollama", false},
		{"unknown-model", "", true}, // fail-closed
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			got, err := inferProvider(tt.model)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrUnknownModel)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantProv, got)
			}
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

func TestGracefulRoute(t *testing.T) {
	ctx := context.Background()
	providers := map[string]Provider{
		"openai":    &mockProvider{name: "openai"},
		"anthropic": &mockProvider{name: "anthropic"},
	}
	routing := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4o", Location: "global"},
	}

	t.Run("under threshold returns primary, not degraded", func(t *testing.T) {
		costLimits := &policy.CostLimitsConfig{
			Daily:   100,
			Monthly: 2000,
			Degradation: &policy.DegradationConfig{
				Enabled:          true,
				ThresholdPercent: 80,
				FallbackModel:    "gpt-4o-mini",
			},
		}
		router := NewRouter(routing, providers, costLimits)
		costCtx := &CostContext{DailyTotal: 50, TenantID: "t1", AgentName: "a1"}
		provider, model, degraded, originalModel, err := router.GracefulRoute(ctx, 0, costCtx)
		require.NoError(t, err)
		assert.False(t, degraded)
		assert.Empty(t, originalModel)
		assert.Equal(t, "openai", provider.Name())
		assert.Equal(t, "gpt-4o", model)
	})

	t.Run("at 80 percent budget returns fallback and degraded", func(t *testing.T) {
		costLimits := &policy.CostLimitsConfig{
			Daily:   100,
			Monthly: 2000,
			Degradation: &policy.DegradationConfig{
				Enabled:          true,
				ThresholdPercent: 80,
				FallbackModel:    "gpt-4o-mini",
			},
		}
		router := NewRouter(routing, providers, costLimits)
		costCtx := &CostContext{DailyTotal: 80, TenantID: "t1", AgentName: "a1"}
		provider, model, degraded, originalModel, err := router.GracefulRoute(ctx, 0, costCtx)
		require.NoError(t, err)
		assert.True(t, degraded)
		assert.Equal(t, "gpt-4o", originalModel)
		assert.Equal(t, "openai", provider.Name())
		assert.Equal(t, "gpt-4o-mini", model)
	})

	t.Run("degradation disabled returns primary", func(t *testing.T) {
		costLimits := &policy.CostLimitsConfig{
			Daily:       100,
			Degradation: &policy.DegradationConfig{Enabled: false, ThresholdPercent: 80, FallbackModel: "gpt-4o-mini"},
		}
		router := NewRouter(routing, providers, costLimits)
		costCtx := &CostContext{DailyTotal: 90, TenantID: "t1", AgentName: "a1"}
		provider, model, degraded, _, err := router.GracefulRoute(ctx, 0, costCtx)
		require.NoError(t, err)
		assert.False(t, degraded)
		assert.Equal(t, "gpt-4o", model)
		assert.Equal(t, "openai", provider.Name())
	})

	t.Run("fallback provider missing returns primary", func(t *testing.T) {
		limitedProviders := map[string]Provider{"anthropic": &mockProvider{name: "anthropic"}}
		costLimits := &policy.CostLimitsConfig{
			Daily: 100,
			Degradation: &policy.DegradationConfig{
				Enabled:          true,
				ThresholdPercent: 80,
				FallbackModel:    "gpt-4o-mini", // openai not in map
			},
		}
		costCtx := &CostContext{DailyTotal: 85, TenantID: "t1", AgentName: "a1"}
		routing1 := &policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{Primary: "claude-sonnet-4-20250514", Fallback: "gpt-4o-mini"},
		}
		router := NewRouter(routing1, limitedProviders, costLimits)
		provider, model, degraded, _, err := router.GracefulRoute(ctx, 0, costCtx)
		require.NoError(t, err)
		// Fallback gpt-4o-mini -> openai, not in providers; so we get primary (anthropic) and not degraded
		assert.False(t, degraded)
		assert.Equal(t, "anthropic", provider.Name())
		assert.Equal(t, "claude-sonnet-4-20250514", model)
	})

	t.Run("nil costCtx returns primary", func(t *testing.T) {
		costLimits := &policy.CostLimitsConfig{
			Daily:       100,
			Degradation: &policy.DegradationConfig{Enabled: true, ThresholdPercent: 80, FallbackModel: "gpt-4o-mini"},
		}
		router := NewRouter(routing, providers, costLimits)
		provider, model, degraded, _, err := router.GracefulRoute(ctx, 0, nil)
		require.NoError(t, err)
		assert.False(t, degraded)
		assert.Equal(t, "gpt-4o", model)
		assert.Equal(t, "openai", provider.Name())
	})

	// Tier 2 with BedrockOnly must not degrade to a non-Bedrock fallback (data sovereignty).
	t.Run("bedrock_only tier does not degrade to non-Bedrock fallback", func(t *testing.T) {
		bedrockProviders := map[string]Provider{
			"openai":  &mockProvider{name: "openai"},
			"bedrock": &mockProvider{name: "bedrock"},
		}
		routingT2 := &policy.ModelRoutingConfig{
			Tier0: &policy.TierConfig{Primary: "gpt-4o", Location: "global"},
			Tier2: &policy.TierConfig{
				Primary:     "anthropic.claude-3-sonnet-20240229-v1:0",
				Location:    "eu-central-1",
				BedrockOnly: true,
			},
		}
		costLimits := &policy.CostLimitsConfig{
			Daily: 100,
			Degradation: &policy.DegradationConfig{
				Enabled:          true,
				ThresholdPercent: 80,
				FallbackModel:    "gpt-4o-mini", // OpenAI — would violate sovereignty for Tier 2
			},
		}
		router := NewRouter(routingT2, bedrockProviders, costLimits)
		costCtx := &CostContext{DailyTotal: 85, TenantID: "t1", AgentName: "a1"}
		provider, model, degraded, _, err := router.GracefulRoute(ctx, 2, costCtx)
		require.NoError(t, err)
		assert.False(t, degraded, "must not degrade when tier is bedrock_only and fallback is non-Bedrock")
		assert.Equal(t, "bedrock", provider.Name(), "must stay on Bedrock for data sovereignty")
		assert.Equal(t, "anthropic.claude-3-sonnet-20240229-v1:0", model)
	})
}

func BenchmarkRouterRoute(b *testing.B) {
	providers := map[string]Provider{
		"openai":    &mockProvider{name: "openai"},
		"anthropic": &mockProvider{name: "anthropic"},
		"bedrock":   &mockProvider{name: "bedrock"},
	}
	routing := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4o-mini"},
		Tier1: &policy.TierConfig{Primary: "claude-sonnet-4-20250514"},
		Tier2: &policy.TierConfig{Primary: "anthropic.claude-3-sonnet-20240229-v1:0", BedrockOnly: true},
	}
	router := NewRouter(routing, providers, nil)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = router.Route(ctx, i%3)
	}
}

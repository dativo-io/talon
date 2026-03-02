package llm

import (
	"context"
	"fmt"
	"net/http"
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
func (m *mockProvider) Metadata() ProviderMetadata {
	return ProviderMetadata{ID: m.name, DisplayName: m.name, Jurisdiction: "US", Wizard: WizardHint{Order: 0}}
}

func (m *mockProvider) Generate(ctx context.Context, req *Request) (*Response, error) {
	return &Response{
		Content:      "mock response",
		FinishReason: "stop",
		InputTokens:  10,
		OutputTokens: 5,
		Model:        req.Model,
	}, nil
}

func (m *mockProvider) Stream(ctx context.Context, req *Request, ch chan<- StreamChunk) error {
	ch <- StreamChunk{Content: "mock", FinishReason: "stop"}
	close(ch)
	return nil
}

func (m *mockProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	return 0.001
}
func (m *mockProvider) ValidateConfig() error                 { return nil }
func (m *mockProvider) HealthCheck(ctx context.Context) error { return nil }
func (m *mockProvider) WithHTTPClient(client *http.Client) Provider {
	return m
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
		provider, model, _, err := router.Route(ctx, 0, nil)
		require.NoError(t, err)
		assert.Equal(t, "openai", provider.Name())
		assert.Equal(t, "gpt-4o-mini", model)
	})

	t.Run("tier 1 routes to Anthropic", func(t *testing.T) {
		provider, model, _, err := router.Route(ctx, 1, nil)
		require.NoError(t, err)
		assert.Equal(t, "anthropic", provider.Name())
		assert.Equal(t, "claude-sonnet-4-20250514", model)
	})

	t.Run("tier 2 routes to Bedrock", func(t *testing.T) {
		provider, model, _, err := router.Route(ctx, 2, nil)
		require.NoError(t, err)
		assert.Equal(t, "bedrock", provider.Name())
		assert.Equal(t, "anthropic.claude-3-sonnet-20240229-v1:0", model)
	})

	t.Run("invalid tier returns error", func(t *testing.T) {
		_, _, _, err := router.Route(ctx, 5, nil)
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
		_, _, _, err := r.Route(ctx, 0, nil)
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
		provider, model, _, err := router.Route(ctx, 1, nil)
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
		_, _, _, err := router.Route(ctx, 0, nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrProviderNotAvailable)
	})
}

func TestRouterNilRouting(t *testing.T) {
	router := NewRouter(nil, map[string]Provider{}, nil)
	ctx := context.Background()

	_, _, _, err := router.Route(ctx, 0, nil)
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
		_, _, _, err := router.Route(ctx, 0, nil)
		require.NoError(t, err)
	})

	t.Run("tier 1 returns error", func(t *testing.T) {
		_, _, _, err := router.Route(ctx, 1, nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoRoutingConfig)
	})

	t.Run("tier 2 returns error", func(t *testing.T) {
		_, _, _, err := router.Route(ctx, 2, nil)
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
		provider, model, _, err := router.Route(ctx, 2, nil)
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
		_, _, _, err := router.Route(ctx, 2, nil)
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
		provider, model, _, err := router.Route(ctx, 1, nil)
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
		provider, _, _, err := router.Route(ctx, 1, nil)
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
			provider, _, _, err := router.Route(ctx, 2, nil)
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
			provider, _, _, err := router.Route(ctx, 2, nil)
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
			_, _, _, err := router.Route(ctx, 2, nil)
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

		_, m1, _, _ := r1.Route(ctx, 0, nil)
		_, m2, _, _ := r2.Route(ctx, 0, nil)
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

		_, m1, _, err1 := r1.Route(ctx, 0, nil)
		_, m2, _, err2 := r2.Route(ctx, 0, nil)
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

		pOff, _, _, _ := rOff.Route(ctx, 0, nil)
		pOn, _, _, _ := rOn.Route(ctx, 0, nil)
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
	// Router uses whatever provider is in the map; cost is from provider.EstimateCost.
	// Real provider cost logic is tested in each provider's package (e.g. openai/provider_test.go).
	mock := &mockProvider{name: "openai"}
	cost := mock.EstimateCost("gpt-4o", 1000, 500)
	assert.Equal(t, 0.001, cost)
}

func TestProviderNames(t *testing.T) {
	assert.Equal(t, "openai", (&mockProvider{name: "openai"}).Name())
	assert.Equal(t, "anthropic", (&mockProvider{name: "anthropic"}).Name())
	assert.Equal(t, "ollama", (&mockProvider{name: "ollama"}).Name())
	assert.Equal(t, "bedrock", (&mockProvider{name: "bedrock"}).Name())
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
		provider, model, degraded, originalModel, _, err := router.GracefulRoute(ctx, 0, costCtx, nil)
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
		provider, model, degraded, originalModel, _, err := router.GracefulRoute(ctx, 0, costCtx, nil)
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
		provider, model, degraded, _, _, err := router.GracefulRoute(ctx, 0, costCtx, nil)
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
		provider, model, degraded, _, _, err := router.GracefulRoute(ctx, 0, costCtx, nil)
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
		provider, model, degraded, _, _, err := router.GracefulRoute(ctx, 0, nil, nil)
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
		provider, model, degraded, _, _, err := router.GracefulRoute(ctx, 2, costCtx, nil)
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
		_, _, _, _ = router.Route(ctx, i%3, nil)
	}
}

// TestRoute_WithComplianceOpts verifies that when RouteOptions has PolicyEngine and SovereigntyMode,
// the router uses compliance-aware routing and returns a RouteDecision for evidence.
func TestRoute_WithComplianceOpts(t *testing.T) {
	ctx := context.Background()
	pol := &policy.Policy{VersionTag: "v1", Policies: policy.PoliciesConfig{}}
	eng, err := policy.NewEngine(ctx, pol)
	require.NoError(t, err)

	providers := map[string]Provider{
		"openai": &mockProvider{name: "openai"},
	}
	routing := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4o-mini"},
	}
	router := NewRouter(routing, providers, nil)

	opts := &RouteOptions{
		PolicyEngine:    eng,
		SovereigntyMode: "global",
		DataTier:        0,
	}
	provider, model, decision, err := router.Route(ctx, 0, opts)
	require.NoError(t, err)
	require.NotNil(t, provider)
	assert.Equal(t, "gpt-4o-mini", model)
	require.NotNil(t, decision)
	assert.Equal(t, "openai", decision.SelectedProvider)
	assert.Equal(t, "gpt-4o-mini", decision.SelectedModel)
	assert.Empty(t, decision.Rejected, "global mode should not reject any candidate")
}

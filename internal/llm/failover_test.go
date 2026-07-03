package llm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/failover"
	"github.com/dativo-io/talon/internal/policy"
)

func TestClassifyGenerateError(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantClass     string
		wantTransient bool
	}{
		{name: "nil", err: nil, wantClass: failover.ClassNone, wantTransient: false},
		{name: "provider rate_limit", err: &ProviderError{Code: "rate_limit", Provider: "openai"}, wantClass: failover.ClassRateLimited, wantTransient: true},
		{name: "provider server_error", err: &ProviderError{Code: "server_error", Provider: "openai"}, wantClass: failover.ClassUpstream5xx, wantTransient: true},
		{name: "provider auth_failed permanent", err: &ProviderError{Code: "auth_failed", Provider: "openai"}, wantClass: failover.ClassAuth, wantTransient: false},
		{name: "provider model_not_found permanent", err: &ProviderError{Code: "model_not_found", Provider: "openai"}, wantClass: failover.ClassClient, wantTransient: false},
		{name: "wrapped provider error", err: fmt.Errorf("calling LLM: %w", &ProviderError{Code: "server_error"}), wantClass: failover.ClassUpstream5xx, wantTransient: true},
		{name: "context canceled never transient", err: context.Canceled, wantClass: failover.ClassCanceled, wantTransient: false},
		{name: "deadline exceeded transient", err: context.DeadlineExceeded, wantClass: failover.ClassTimeout, wantTransient: true},
		{name: "connection error transient", err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}, wantClass: failover.ClassConnection, wantTransient: true},
		{name: "unknown error is permanent (fail closed)", err: errors.New("json decode failed"), wantClass: failover.ClassNone, wantTransient: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyGenerateError(tt.err)
			assert.Equal(t, tt.wantClass, got.Class)
			assert.Equal(t, tt.wantTransient, got.Transient)
		})
	}
}

// stubRoutingEvaluator allows/denies candidates by provider jurisdiction:
// EU and LOCAL allowed, everything else rejected (mimics eu_strict routing.rego).
type stubRoutingEvaluator struct{}

func (stubRoutingEvaluator) EvaluateRouting(_ context.Context, in *policy.RoutingInput) (*policy.Decision, error) {
	if in.ProviderJurisdiction == "EU" || in.ProviderJurisdiction == "LOCAL" {
		return &policy.Decision{Allowed: true}, nil
	}
	return &policy.Decision{Allowed: false, Reasons: []string{"sovereignty: provider " + in.ProviderID + " not allowed"}}, nil
}

// jurisdictionProvider is a mockProvider with a configurable jurisdiction.
type jurisdictionProvider struct {
	mockProvider
	jurisdiction string
}

func (p *jurisdictionProvider) Metadata() ProviderMetadata {
	return ProviderMetadata{ID: p.name, DisplayName: p.name, Jurisdiction: p.jurisdiction}
}

func TestResolveCandidates_FallbackChain(t *testing.T) {
	providers := map[string]Provider{
		"openai":    &jurisdictionProvider{mockProvider: mockProvider{name: "openai"}, jurisdiction: "US"},
		"anthropic": &jurisdictionProvider{mockProvider: mockProvider{name: "anthropic"}, jurisdiction: "US"},
		"ollama":    &jurisdictionProvider{mockProvider: mockProvider{name: "ollama"}, jurisdiction: "LOCAL"},
	}
	routing := &policy.ModelRoutingConfig{
		Tier1: &policy.TierConfig{
			Primary:       "gpt-4o",
			FallbackChain: []string{"claude-sonnet-4-20250514", "llama3:70b", "not-a-known-model"},
		},
	}
	router := NewRouter(routing, providers, nil)
	ctx := context.Background()

	t.Run("no compliance: full chain in order, unknown model rejected", func(t *testing.T) {
		resolved, rejected, err := router.ResolveCandidates(ctx, 1, nil)
		require.NoError(t, err)
		require.Len(t, resolved, 3)
		assert.Equal(t, "openai", resolved[0].ProviderName)
		assert.Equal(t, 0, resolved[0].ChainPosition)
		assert.Equal(t, "anthropic", resolved[1].ProviderName)
		assert.Equal(t, "claude-sonnet-4-20250514", resolved[1].Model)
		assert.Equal(t, 1, resolved[1].ChainPosition)
		assert.Equal(t, "ollama", resolved[2].ProviderName)
		assert.Contains(t, resolved[1].RuleID, "fallback_chain[0]")
		require.Len(t, rejected, 1)
		assert.Equal(t, "not-a-known-model", rejected[0].ProviderID)
	})

	t.Run("compliance mode filters sovereignty-rejected candidates", func(t *testing.T) {
		opts := &RouteOptions{PolicyEngine: stubRoutingEvaluator{}, SovereigntyMode: "eu_strict", DataTier: 1}
		resolved, rejected, err := router.ResolveCandidates(ctx, 1, opts)
		require.NoError(t, err)
		// openai (US) and anthropic (US) rejected; only ollama (LOCAL) remains.
		require.Len(t, resolved, 1)
		assert.Equal(t, "ollama", resolved[0].ProviderName)
		assert.GreaterOrEqual(t, len(rejected), 3) // 2 US candidates + unknown model
	})

	t.Run("legacy fallback used only when chain is empty", func(t *testing.T) {
		legacyRouting := &policy.ModelRoutingConfig{
			Tier1: &policy.TierConfig{Primary: "gpt-4o", Fallback: "claude-sonnet-4-20250514"},
		}
		legacyRouter := NewRouter(legacyRouting, providers, nil)
		resolved, _, err := legacyRouter.ResolveCandidates(ctx, 1, nil)
		require.NoError(t, err)
		require.Len(t, resolved, 2)
		assert.Equal(t, "anthropic", resolved[1].ProviderName)
		assert.Contains(t, resolved[1].RuleID, "tier_1.fallback")
	})

	t.Run("chain supersedes legacy fallback", func(t *testing.T) {
		bothRouting := &policy.ModelRoutingConfig{
			Tier1: &policy.TierConfig{Primary: "gpt-4o", Fallback: "claude-sonnet-4-20250514", FallbackChain: []string{"llama3:70b"}},
		}
		bothRouter := NewRouter(bothRouting, providers, nil)
		resolved, _, err := bothRouter.ResolveCandidates(ctx, 1, nil)
		require.NoError(t, err)
		require.Len(t, resolved, 2)
		assert.Equal(t, "ollama", resolved[1].ProviderName)
	})

	t.Run("duplicate chain entries deduplicated", func(t *testing.T) {
		dupRouting := &policy.ModelRoutingConfig{
			Tier1: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"gpt-4o", "llama3:70b", "llama3:70b"}},
		}
		dupRouter := NewRouter(dupRouting, providers, nil)
		resolved, _, err := dupRouter.ResolveCandidates(ctx, 1, nil)
		require.NoError(t, err)
		require.Len(t, resolved, 2)
	})
}

func TestRouteWithCompliance_UsesChainCandidates(t *testing.T) {
	providers := map[string]Provider{
		"openai": &jurisdictionProvider{mockProvider: mockProvider{name: "openai"}, jurisdiction: "US"},
		"ollama": &jurisdictionProvider{mockProvider: mockProvider{name: "ollama"}, jurisdiction: "LOCAL"},
	}
	routing := &policy.ModelRoutingConfig{
		Tier2: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3:70b"}},
	}
	router := NewRouter(routing, providers, nil)
	opts := &RouteOptions{PolicyEngine: stubRoutingEvaluator{}, SovereigntyMode: "eu_strict", DataTier: 2}
	provider, model, decision, err := router.Route(context.Background(), 2, opts)
	require.NoError(t, err)
	assert.Equal(t, "ollama", provider.Name())
	assert.Equal(t, "llama3:70b", model)
	require.NotNil(t, decision)
	assert.Equal(t, "ollama", decision.SelectedProvider)
	assert.NotEmpty(t, decision.Rejected)
}

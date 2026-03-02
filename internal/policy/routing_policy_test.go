package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateRouting_EUStrictBlocksCN(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{VersionTag: "v1", Policies: PoliciesConfig{}}
	eng, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	dec, err := eng.EvaluateRouting(ctx, &RoutingInput{
		SovereigntyMode:      "eu_strict",
		ProviderID:           "qwen",
		ProviderJurisdiction: "CN",
	})
	require.NoError(t, err)
	assert.False(t, dec.Allowed)
	assert.Contains(t, dec.Reasons, "provider jurisdiction CN not allowed in eu_strict")
}

func TestEvaluateRouting_EUStrictBlocksUS(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{VersionTag: "v1", Policies: PoliciesConfig{}}
	eng, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	dec, err := eng.EvaluateRouting(ctx, &RoutingInput{
		SovereigntyMode:      "eu_strict",
		ProviderID:           "openai",
		ProviderJurisdiction: "US",
	})
	require.NoError(t, err)
	assert.False(t, dec.Allowed)
	assert.NotEmpty(t, dec.Reasons)
}

func TestEvaluateRouting_EUStrictAllowsEU(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{VersionTag: "v1", Policies: PoliciesConfig{}}
	eng, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	dec, err := eng.EvaluateRouting(ctx, &RoutingInput{
		SovereigntyMode:      "eu_strict",
		ProviderID:           "mistral",
		ProviderJurisdiction: "EU",
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
	assert.Empty(t, dec.Reasons)
}

func TestEvaluateRouting_EUStrictAllowsLOCAL(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{VersionTag: "v1", Policies: PoliciesConfig{}}
	eng, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	dec, err := eng.EvaluateRouting(ctx, &RoutingInput{
		SovereigntyMode:      "eu_strict",
		ProviderID:           "ollama",
		ProviderJurisdiction: "LOCAL",
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestEvaluateRouting_EUStrictBlocksAzureUSRegion(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{VersionTag: "v1", Policies: PoliciesConfig{}}
	eng, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	// Use actual Azure OpenAI metadata: Jurisdiction "EU" but user can select US region (eastus).
	// eu_strict must deny non-EU region regardless of provider jurisdiction.
	dec, err := eng.EvaluateRouting(ctx, &RoutingInput{
		SovereigntyMode:      "eu_strict",
		ProviderID:           "azure-openai",
		ProviderJurisdiction: "EU",
		ProviderRegion:       "eastus",
	})
	require.NoError(t, err)
	assert.False(t, dec.Allowed)
	assert.NotEmpty(t, dec.Reasons)
}

func TestEvaluateRouting_EUStrictAllowsAzureEURegion(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{VersionTag: "v1", Policies: PoliciesConfig{}}
	eng, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	dec, err := eng.EvaluateRouting(ctx, &RoutingInput{
		SovereigntyMode:      "eu_strict",
		ProviderID:           "azure-openai",
		ProviderJurisdiction: "EU",
		ProviderRegion:       "westeurope",
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestEvaluateRouting_GlobalAllowsAll(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{VersionTag: "v1", Policies: PoliciesConfig{}}
	eng, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	dec, err := eng.EvaluateRouting(ctx, &RoutingInput{
		SovereigntyMode:      "global",
		ProviderID:           "qwen",
		ProviderJurisdiction: "CN",
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestEvaluateRouting_ConfidentialTierRequiresLocal(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{VersionTag: "v1", Policies: PoliciesConfig{}}
	eng, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	dec, err := eng.EvaluateRouting(ctx, &RoutingInput{
		DataTier:             2,
		RequireEURouting:     true,
		ProviderID:           "mistral",
		ProviderJurisdiction: "EU",
	})
	require.NoError(t, err)
	assert.False(t, dec.Allowed)
	assert.NotEmpty(t, dec.Reasons)
}

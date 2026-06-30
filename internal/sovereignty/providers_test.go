package sovereignty

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	_ "github.com/dativo-io/talon/internal/llm/providers"
)

func TestAllowsProvider(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		provider string
		want     bool
	}{
		{"eu_strict allows ollama (LOCAL)", config.DataSovereigntyEUStrict, "ollama", true},
		{"eu_strict allows mistral (EU)", config.DataSovereigntyEUStrict, "mistral", true},
		// Bedrock is US-jurisdiction and region-aware: with no configured region
		// it is excluded (fail closed) even though it offers EU regions.
		{"eu_strict excludes bedrock without region", config.DataSovereigntyEUStrict, "bedrock", false},
		{"eu_strict rejects openai (US)", config.DataSovereigntyEUStrict, "openai", false},
		{"eu_strict rejects anthropic (US)", config.DataSovereigntyEUStrict, "anthropic", false},
		{"eu_strict rejects unknown provider (fail closed)", config.DataSovereigntyEUStrict, "made-up", false},
		{"eu_preferred allows openai", config.DataSovereigntyEUPreferred, "openai", true},
		{"global allows openai", config.DataSovereigntyGlobal, "openai", true},
		{"empty mode allows openai", "", "openai", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, AllowsProvider(tt.mode, tt.provider))
		})
	}
}

func TestAllowsProviderRegion(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		provider string
		region   string
		want     bool
	}{
		// Bedrock (US jurisdiction, region-aware).
		{"bedrock eu-central-1 allowed", config.DataSovereigntyEUStrict, "bedrock", "eu-central-1", true},
		{"bedrock us-east-1 excluded", config.DataSovereigntyEUStrict, "bedrock", "us-east-1", false},
		{"bedrock no region excluded", config.DataSovereigntyEUStrict, "bedrock", "", false},
		// Vertex (US jurisdiction, region-aware).
		{"vertex europe-west1 allowed", config.DataSovereigntyEUStrict, "vertex", "europe-west1", true},
		{"vertex us-central1 excluded", config.DataSovereigntyEUStrict, "vertex", "us-central1", false},
		// Azure OpenAI (EU jurisdiction, but region-aware: a US region excludes).
		{"azure westeurope allowed", config.DataSovereigntyEUStrict, "azure-openai", "westeurope", true},
		{"azure eastus excluded", config.DataSovereigntyEUStrict, "azure-openai", "eastus", false},
		{"azure no region trusts EU jurisdiction", config.DataSovereigntyEUStrict, "azure-openai", "", true},
		// Non-region providers ignore the region argument.
		{"openai region ignored, still US", config.DataSovereigntyEUStrict, "openai", "eu-central-1", false},
		{"ollama LOCAL always allowed", config.DataSovereigntyEUStrict, "ollama", "us-east-1", true},
		// Non-strict modes allow everything regardless of region.
		{"global bedrock us-east-1 allowed", config.DataSovereigntyGlobal, "bedrock", "us-east-1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, AllowsProviderRegion(tt.mode, tt.provider, tt.region))
		})
	}
}

func TestEvaluateSovereignty_EUStrictExcludesGatewayUSProvider(t *testing.T) {
	clearProviderKeys(t)
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", Region: "US"},
		},
	}
	eval := EvaluateSovereignty(op, gw)
	require.Len(t, eval.Excluded, 1)
	assert.Equal(t, "openai", eval.Excluded[0].Provider)
	assert.Equal(t, ExclusionScopeGateway, eval.Excluded[0].Scope)
	assert.False(t, eval.HasRoutableProvider)
}

func TestEvaluateSovereignty_EUStrictAllowsEUAndLocal(t *testing.T) {
	clearProviderKeys(t)
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"mistral":  {Enabled: true, BaseURL: "https://api.mistral.ai", Region: "EU"},
			"ollama":   {Enabled: true, BaseURL: "http://127.0.0.1:11434", Region: "LOCAL"},
			"disabled": {Enabled: false, BaseURL: "https://api.openai.com", Region: "US"},
		},
	}
	eval := EvaluateSovereignty(op, gw)
	assert.Empty(t, eval.Excluded)
	assert.True(t, eval.HasRoutableProvider)
	assert.ElementsMatch(t, []string{"mistral", "ollama"}, eval.CompliantGatewayProviders)
}

func TestEvaluateSovereignty_EUStrictMixedProviders(t *testing.T) {
	clearProviderKeys(t)
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", Region: "US"},
			"ollama": {Enabled: true, BaseURL: "http://127.0.0.1:11434", Region: "LOCAL"},
		},
	}
	eval := EvaluateSovereignty(op, gw)
	require.Len(t, eval.Excluded, 1)
	assert.Equal(t, "openai", eval.Excluded[0].Provider)
	assert.True(t, eval.HasRoutableProvider)
}

func TestEvaluateSovereignty_EUStrictExcludesKeyedOpenAI(t *testing.T) {
	clearProviderKeys(t)
	t.Setenv("OPENAI_API_KEY", "sk-test")
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	eval := EvaluateSovereignty(op, nil)
	require.Len(t, eval.Excluded, 1)
	assert.Equal(t, "openai", eval.Excluded[0].Provider)
	assert.Equal(t, ExclusionScopeEnv, eval.Excluded[0].Scope)
	assert.True(t, eval.HasRoutableProvider, "native run still has implicit ollama")
}

func TestEvaluateSovereignty_EUStrictExcludesLLMProvidersBlock(t *testing.T) {
	clearProviderKeys(t)
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
		LLM: &config.LLMConfig{
			Providers: map[string]config.LLMProviderConfig{"openai": {Enabled: true}},
		},
	}
	eval := EvaluateSovereignty(op, nil)
	require.Len(t, eval.Excluded, 1)
	assert.Contains(t, eval.Excluded[0].Reason, "llm.providers")
}

func TestEvaluateSovereignty_GlobalAllowsAll(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyGlobal},
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", Region: "US"},
		},
	}
	eval := EvaluateSovereignty(op, gw)
	assert.Empty(t, eval.Excluded)
	assert.True(t, eval.HasRoutableProvider)
}

func TestEvaluateSovereignty_NoSovereigntyBlockIsNoop(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	op := &config.Config{}
	eval := EvaluateSovereignty(op, nil)
	assert.Empty(t, eval.Excluded)
	assert.True(t, eval.HasRoutableProvider)
}

func clearProviderKeys(t *testing.T) {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_REGION", "")
}

// TestEvaluateSovereignty_EUStrictBedrockRegionAware is the regression for the
// "Bedrock metadata has EU regions so any region is allowed" bug: under
// eu_strict the *configured* AWS_REGION decides routability.
func TestEvaluateSovereignty_EUStrictBedrockRegionAware(t *testing.T) {
	clearProviderKeys(t)
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}

	t.Run("us region excluded", func(t *testing.T) {
		t.Setenv("AWS_REGION", "us-east-1")
		eval := EvaluateSovereignty(op, nil)
		require.Len(t, eval.Excluded, 1)
		assert.Equal(t, "bedrock", eval.Excluded[0].Provider)
		assert.Equal(t, ExclusionScopeEnv, eval.Excluded[0].Scope)
		assert.Contains(t, eval.Excluded[0].Reason, "us-east-1")
	})

	t.Run("eu region compliant", func(t *testing.T) {
		t.Setenv("AWS_REGION", "eu-central-1")
		eval := EvaluateSovereignty(op, nil)
		assert.Empty(t, eval.Excluded)
		assert.True(t, eval.HasCompliantOperatorProvider)
	})
}

// TestEvaluateSovereignty_EUStrictLLMProvidersRegionAware verifies an
// llm.providers entry for a region-aware provider is gated on its configured
// region, not just its type.
func TestEvaluateSovereignty_EUStrictLLMProvidersRegionAware(t *testing.T) {
	clearProviderKeys(t)

	t.Run("bedrock us region in llm.providers excluded", func(t *testing.T) {
		op := &config.Config{
			Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
			LLM: &config.LLMConfig{
				Providers: map[string]config.LLMProviderConfig{
					"aws": {Type: "bedrock", Enabled: true, Config: map[string]interface{}{"region": "us-east-1"}},
				},
			},
		}
		excluded, compliant := evaluateOperatorProviders(op, config.DataSovereigntyEUStrict)
		require.Len(t, excluded, 1)
		assert.Equal(t, "bedrock", excluded[0].Provider)
		assert.False(t, compliant)
	})

	t.Run("bedrock eu region in llm.providers compliant", func(t *testing.T) {
		op := &config.Config{
			Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
			LLM: &config.LLMConfig{
				Providers: map[string]config.LLMProviderConfig{
					"aws": {Type: "bedrock", Enabled: true, Config: map[string]interface{}{"region": "eu-west-1"}},
				},
			},
		}
		excluded, compliant := evaluateOperatorProviders(op, config.DataSovereigntyEUStrict)
		assert.Empty(t, excluded)
		assert.True(t, compliant)
	})
}

// TestEvaluateOperatorProviders_UsesProviderTypeNotAlias is the regression for
// the "provider gate uses map key" bug: the gate must classify llm.providers
// entries by their Type field, not by the (operator-chosen) map alias.
func TestEvaluateOperatorProviders_UsesProviderTypeNotAlias(t *testing.T) {
	clearProviderKeys(t)

	t.Run("excludes by type not alias", func(t *testing.T) {
		op := &config.Config{
			Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
			LLM: &config.LLMConfig{
				Providers: map[string]config.LLMProviderConfig{
					"my-eu-llm": {Type: "openai", Enabled: true},
				},
			},
		}
		excluded, compliant := evaluateOperatorProviders(op, config.DataSovereigntyEUStrict)
		require.Len(t, excluded, 1)
		assert.Equal(t, "openai", excluded[0].Provider)
		assert.False(t, compliant)
	})

	t.Run("allows by type not alias", func(t *testing.T) {
		op := &config.Config{
			Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
			LLM: &config.LLMConfig{
				Providers: map[string]config.LLMProviderConfig{
					"openai": {Type: "mistral", Enabled: true},
				},
			},
		}
		excluded, compliant := evaluateOperatorProviders(op, config.DataSovereigntyEUStrict)
		assert.Empty(t, excluded)
		assert.True(t, compliant)
	})
}

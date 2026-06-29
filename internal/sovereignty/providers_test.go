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
		{"eu_strict allows bedrock (US + EU regions)", config.DataSovereigntyEUStrict, "bedrock", true},
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

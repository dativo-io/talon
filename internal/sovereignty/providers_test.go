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

func TestValidateSovereignty_EUStrictRejectsGatewayUSProvider(t *testing.T) {
	clearProviderKeys(t)
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", Region: "US"},
		},
	}
	err := ValidateSovereignty(op, gw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "openai")
	assert.Contains(t, err.Error(), "eu_strict")
}

func TestValidateSovereignty_EUStrictAllowsEUAndLocal(t *testing.T) {
	clearProviderKeys(t)
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"mistral":  {Enabled: true, BaseURL: "https://api.mistral.ai", Region: "EU"},
			"ollama":   {Enabled: true, BaseURL: "http://127.0.0.1:11434", Region: "LOCAL"},
			"disabled": {Enabled: false, BaseURL: "https://api.openai.com", Region: "US"}, // ignored: not enabled
		},
	}
	require.NoError(t, ValidateSovereignty(op, gw))
}

func TestValidateSovereignty_EUStrictRejectsKeyedOpenAI(t *testing.T) {
	clearProviderKeys(t)
	t.Setenv("OPENAI_API_KEY", "sk-test")
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	err := ValidateSovereignty(op, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OPENAI_API_KEY")
}

func TestValidateSovereignty_EUStrictRejectsLLMProvidersBlock(t *testing.T) {
	clearProviderKeys(t)
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
		LLM: &config.LLMConfig{
			Providers: map[string]config.LLMProviderConfig{"openai": {Enabled: true}},
		},
	}
	err := ValidateSovereignty(op, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "llm.providers")
}

func TestValidateSovereignty_GlobalAllowsAll(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyGlobal},
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", Region: "US"},
		},
	}
	require.NoError(t, ValidateSovereignty(op, gw))
}

func TestValidateSovereignty_NoSovereigntyBlockIsNoop(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	op := &config.Config{}
	require.NoError(t, ValidateSovereignty(op, nil))
}

// TestValidateOperatorProviders_UsesProviderTypeNotAlias is the regression for
// the "provider gate uses map key" bug: the gate must classify llm.providers
// entries by their Type field, not by the (operator-chosen) map alias.
func TestValidateOperatorProviders_UsesProviderTypeNotAlias(t *testing.T) {
	clearProviderKeys(t)

	// Alias looks EU-friendly but the real type is openai (US) → must be rejected.
	t.Run("rejects by type not alias", func(t *testing.T) {
		op := &config.Config{
			Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
			LLM: &config.LLMConfig{
				Providers: map[string]config.LLMProviderConfig{
					"my-eu-llm": {Type: "openai", Enabled: true},
				},
			},
		}
		err := validateOperatorProviders(op, config.DataSovereigntyEUStrict)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "openai")
	})

	// Alias looks like a US provider but the real type is mistral (EU) → allowed.
	t.Run("allows by type not alias", func(t *testing.T) {
		op := &config.Config{
			Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
			LLM: &config.LLMConfig{
				Providers: map[string]config.LLMProviderConfig{
					"openai": {Type: "mistral", Enabled: true},
				},
			},
		}
		require.NoError(t, validateOperatorProviders(op, config.DataSovereigntyEUStrict))
	})
}

// clearProviderKeys ensures operator-keyed provider env vars are unset so the
// fail-closed gate is exercised deterministically regardless of the dev shell.
func clearProviderKeys(t *testing.T) {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
}

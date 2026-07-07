package pricing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidFile(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	require.NotNil(t, table)
	assert.Equal(t, "1", table.Version)
	require.Contains(t, table.Providers, "openai")
	openai := table.Providers["openai"]
	require.Contains(t, openai.Models, "gpt-4o")
	gpt4o := openai.Models["gpt-4o"]
	assert.Equal(t, 2.50, gpt4o.InputPer1M)
	assert.Equal(t, 10.00, gpt4o.OutputPer1M)

	cost, known := table.Estimate("openai", "gpt-4o", 1_000_000, 500_000)
	assert.True(t, known)
	assert.InDelta(t, 2.50+5.00, cost, 0.001)
}

func TestLoad_Inherit(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	require.Contains(t, table.Providers, "azure-openai")
	azure := table.Providers["azure-openai"]
	assert.Empty(t, azure.Inherit, "inherit should be resolved")
	require.Contains(t, azure.Models, "gpt-4o", "azure-openai should inherit openai models")
	assert.Equal(t, 2.50, azure.Models["gpt-4o"].InputPer1M)

	cost, known := table.Estimate("azure-openai", "gpt-4o-mini", 1000, 1000)
	assert.True(t, known)
	assert.InDelta(t, (0.15+0.60)/1000, cost, 0.0001)
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/pricing/models.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading pricing file")

	// When file is missing, LoadOrDefault falls back to embedded default (so cost estimation still works)
	table := LoadOrDefault("/nonexistent/pricing/models.yaml")
	require.NotNil(t, table)
	require.NotNil(t, table.Providers)
	assert.NotEmpty(t, table.Providers, "embedded default should contain providers")
	require.Contains(t, table.Providers, "openai")
	cost, known := table.Estimate("openai", "gpt-4o", 1000, 1000)
	assert.True(t, known, "embedded default should provide openai/gpt-4o pricing")
	assert.InDelta(t, (2.50+10.00)/1000, cost, 0.0001)
}

func TestLoadOrDefault_EmbeddedDefaultParses(t *testing.T) {
	// When file is missing, embedded default must provide usable pricing so cost estimation works out of the box
	table := LoadOrDefault("/nonexistent/pricing/models.yaml")
	require.NotNil(t, table)
	cost, known := table.Estimate("anthropic", "claude-sonnet-4-20250514", 1_000_000, 0)
	assert.True(t, known)
	assert.InDelta(t, 3.00, cost, 0.001)
}

func TestLoad_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("invalid: [[["), 0o644))
	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing pricing YAML")
}

func TestLoad_NegativePrice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "neg.yaml")
	content := `
version: "1"
providers:
  openai:
    models:
      gpt-4o:
        input_per_1m: -1.0
        output_per_1m: 10.0
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "negative price")
}

func TestEstimate_KnownModel(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	cost, known := table.Estimate("anthropic", "claude-sonnet-4-20250514", 2_000_000, 500_000)
	assert.True(t, known)
	// 2*3 + 0.5*15 = 6 + 7.5 = 13.5
	assert.InDelta(t, 13.5, cost, 0.001)
}

func TestEstimate_UnknownModel(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	cost, known := table.Estimate("openai", "nonexistent-model-xyz", 1000, 1000)
	assert.False(t, known)
	assert.Equal(t, 0.0, cost)
}

func TestEstimate_APIModelIDSuffixNormalization(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	// API-returned model IDs like gpt-4o-2024-08-06 should match pricing key gpt-4o
	exact, knownExact := table.Estimate("openai", "gpt-4o", 1_000_000, 500_000)
	normalized, knownNorm := table.Estimate("openai", "gpt-4o-2024-08-06", 1_000_000, 500_000)
	assert.True(t, knownExact)
	assert.True(t, knownNorm, "gpt-4o-2024-08-06 should match gpt-4o via suffix strip")
	assert.InDelta(t, exact, normalized, 0.001)
}

func TestEstimate_UnknownProvider(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	cost, known := table.Estimate("unknown-provider", "gpt-4o", 1000, 1000)
	assert.False(t, known)
	assert.Equal(t, 0.0, cost)
}

func TestEstimate_OllamaZeroCost(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	// Ollama has models: {} so any model lookup is unknown... Actually the prompt says
	// "Ollama models return 0.0 and known=true (free, not unknown)". So for ollama we need
	// to treat empty models as "known with zero cost". Let me re-read the prompt.
	// "TestEstimate_OllamaZeroCost — Ollama models return 0.0 and known=true (free, not unknown)."
	// So when provider is ollama and we look up a model, we should return (0, true)? But our
	// table has ollama: models: {}. So Estimate("ollama", "llama3", ...) would not find "llama3"
	// in models and return (0, false). So to get known=true we need either to have a wildcard
	// or to treat "provider exists with empty models" as "any model is free". The prompt says
	// "Ollama models return 0.0 and known=true". So for provider ollama, we should return
	// (0, true) for any model. That means we need special case: if provider exists and has
	// models: {} (empty map), then treat any model as known with cost 0.
	// I'll add that to the Estimate logic.
	cost, known := table.Estimate("ollama", "llama3", 1000, 1000)
	// With empty models, we currently return (0, false). Prompt wants (0, true).
	// So: if provider exists and Models is empty, return (0, true).
	assert.True(t, known, "ollama with empty models should be known (free)")
	assert.Equal(t, 0.0, cost)
}

func TestModelCount(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	assert.Greater(t, table.ModelCount("openai"), 0)
	assert.Greater(t, table.ModelCount("anthropic"), 0)
	assert.Equal(t, 0, table.ModelCount("ollama"), "ollama has models: {}")
	assert.Equal(t, 0, table.ModelCount("nonexistent-provider"))
}

func TestEstimate_ZeroTokens(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	cost, known := table.Estimate("openai", "gpt-4o", 0, 0)
	assert.True(t, known)
	assert.Equal(t, 0.0, cost)
}

func TestEstimate_ExactOneMillionTokens(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	// 1M input at 2.50/1M + 1M output at 10.00/1M = 2.50 + 10.00 = 12.50
	cost, known := table.Estimate("openai", "gpt-4o", 1_000_000, 1_000_000)
	assert.True(t, known)
	assert.InDelta(t, 12.50, cost, 0.001)
}

func TestEstimateCached_AnthropicExplicitRates(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	// claude-sonnet-5: input 3.00, output 15.00, cache_read 0.3, cache_write 3.75 per 1M.
	// 1M input + 1M cacheRead + 1M cacheWrite + 1M output.
	cost, known, fallback := table.EstimateCached("anthropic", "claude-sonnet-5", 1_000_000, 1_000_000, 1_000_000, 1_000_000)
	require.True(t, known)
	assert.False(t, fallback, "explicit cache rates present → no fallback")
	assert.InDelta(t, 3.00+0.3+3.75+15.00, cost, 0.001)
}

func TestEstimateCached_OpenAIReadDiscountNoWrite(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	// gpt-5.5: input 5.00, output 30.00, cache_read 0.5, no cache_write.
	cost, known, fallback := table.EstimateCached("openai", "gpt-5.5", 1_000_000, 1_000_000, 0, 1_000_000)
	require.True(t, known)
	assert.False(t, fallback)
	assert.InDelta(t, 5.00+0.5+30.00, cost, 0.001)
}

func TestEstimateCached_FallbackToInputRate(t *testing.T) {
	// A model with only input/output rates → cache tokens priced at input rate,
	// fallback flagged (fail-conservative: never below the input rate).
	table, err := loadFromData([]byte(`version: "1"
providers:
  openai:
    models:
      cheap:
        input_per_1m: 10.0
        output_per_1m: 20.0`))
	require.NoError(t, err)
	cost, known, fallback := table.EstimateCached("openai", "cheap", 0, 1_000_000, 0, 0)
	require.True(t, known)
	assert.True(t, fallback, "absent cache rate → fallback to input rate")
	assert.InDelta(t, 10.0, cost, 0.001, "cache read priced at input rate, not lower")
}

func TestEstimateCached_UnknownModel(t *testing.T) {
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	cost, known, fallback := table.EstimateCached("openai", "no-such-model", 100, 100, 0, 100)
	assert.False(t, known)
	assert.False(t, fallback)
	assert.Equal(t, 0.0, cost)
}

// Currency (#216): the table declares the ISO-4217 unit of its prices; every
// cost Talon computes and displays uses it. Default is USD — the unit the
// shipped tables were always denominated in.
func TestCurrency_DefaultAndDeclared(t *testing.T) {
	// Shipped tables declare USD explicitly.
	table, err := Load("../../pricing/models.yaml")
	require.NoError(t, err)
	assert.Equal(t, "USD", table.CurrencyCode())

	// Absent currency → USD (pre-field tables were USD).
	legacy, err := loadFromData([]byte("version: \"1\"\nproviders: {}\n"))
	require.NoError(t, err)
	assert.Equal(t, "USD", legacy.CurrencyCode())

	// Declared currency is normalized (trimmed, uppercased).
	eur, err := loadFromData([]byte("version: \"1\"\ncurrency: \" eur \"\nproviders: {}\n"))
	require.NoError(t, err)
	assert.Equal(t, "EUR", eur.CurrencyCode())

	// Nil table is safe and defaults.
	var nilTable *PricingTable
	assert.Equal(t, "USD", nilTable.CurrencyCode())
}

func TestCurrency_InvalidCodeRejected(t *testing.T) {
	for _, bad := range []string{"EURO", "E", "12A", "US-D"} {
		_, err := loadFromData([]byte("version: \"1\"\ncurrency: \"" + bad + "\"\nproviders: {}\n"))
		require.Error(t, err, "currency %q must be rejected", bad)
		assert.Contains(t, err.Error(), "invalid currency")
	}
}

func TestFormatAmount(t *testing.T) {
	assert.Equal(t, "$1.23", FormatAmount("USD", "1.23"))
	assert.Equal(t, "$1.23", FormatAmount("", "1.23"), "empty code renders as USD (pre-field records)")
	assert.Equal(t, "€1.23", FormatAmount("EUR", "1.23"))
	assert.Equal(t, "CHF 1.23", FormatAmount("CHF", "1.23"))
	assert.Equal(t, "€0.42", FormatAmount("eur", "0.42"), "case-insensitive")
}

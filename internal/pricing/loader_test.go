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

	empty := LoadOrDefault("/nonexistent/pricing/models.yaml")
	require.NotNil(t, empty)
	assert.NotNil(t, empty.Providers)
	assert.Empty(t, empty.Providers)
	cost, known := empty.Estimate("openai", "gpt-4o", 1000, 1000)
	assert.False(t, known)
	assert.Equal(t, 0.0, cost)
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

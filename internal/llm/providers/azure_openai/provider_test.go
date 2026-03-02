package azure_openai

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/llm"
)

func TestAzureOpenAIMetadata(t *testing.T) {
	p := &AzureOpenAIProvider{}
	meta := p.Metadata()
	assert.Equal(t, "azure-openai", meta.ID)
	assert.Equal(t, "EU", meta.Jurisdiction)
	assert.True(t, meta.Wizard.SuggestEUStrict)
	assert.Len(t, meta.EURegions, 4)
	assert.Len(t, meta.Wizard.AvailableRegions, 5)
}

func TestAzureOpenAIValidateConfig(t *testing.T) {
	p := &AzureOpenAIProvider{}
	require.Error(t, p.ValidateConfig())
	p2, _ := NewAzureOpenAIProvider("key", "res", "dep", "", "westeurope")
	require.NoError(t, p2.ValidateConfig())
}

func TestAzureOpenAIGenerate_NotConfigured(t *testing.T) {
	p := &AzureOpenAIProvider{}
	_, err := p.Generate(context.Background(), &llm.Request{Model: "gpt-4o", Messages: []llm.Message{{Role: "user", Content: "Hi"}}, MaxTokens: 10})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

package bedrock

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/llm"
)

func TestBedrockMetadata(t *testing.T) {
	prov := &BedrockProvider{region: "eu-central-1"}
	meta := prov.Metadata()
	assert.Equal(t, "bedrock", meta.ID)
	assert.Equal(t, "US", meta.Jurisdiction)
	assert.True(t, meta.Wizard.SuggestEUStrict)
	assert.Equal(t, 40, meta.Wizard.Order)
	assert.Len(t, meta.EURegions, 3)
	assert.True(t, meta.Wizard.RequiresRegion)
	assert.Len(t, meta.Wizard.AvailableRegions, 4)
}

func TestBedrockValidateConfig(t *testing.T) {
	prov := &BedrockProvider{region: ""}
	err := prov.ValidateConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "region")

	prov2 := &BedrockProvider{region: "eu-west-1"}
	err = prov2.ValidateConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credentials")
}

func TestBedrockCostEstimation(t *testing.T) {
	prov := &BedrockProvider{}
	cost := prov.EstimateCost("anthropic.claude-3-sonnet-20240229-v1:0", 1000, 500)
	assert.Greater(t, cost, 0.0)
	costUnknown := prov.EstimateCost("unknown-model", 100, 50)
	assert.Greater(t, costUnknown, 0.0)
}

func TestBedrockWithHTTPClient(t *testing.T) {
	prov := &BedrockProvider{region: "eu-central-1"}
	p2 := prov.WithHTTPClient(nil)
	assert.NotNil(t, p2)
}

func TestBedrockGenerate_NoClient(t *testing.T) {
	prov := &BedrockProvider{region: "eu-central-1"}
	_, err := prov.Generate(context.Background(), &llm.Request{
		Model:     "anthropic.claude-3-haiku-20240307-v1:0",
		Messages:  []llm.Message{{Role: "user", Content: "Hi"}},
		MaxTokens: 10,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client not initialized")
}

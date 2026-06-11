package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	_ "github.com/dativo-io/talon/internal/llm/providers/openai" // register provider metadata for region resolution
)

func TestBuildRunDataFlow_PromptOnlyNoPII(t *testing.T) {
	df := buildRunDataFlow(runFlowInputs{
		TenantID:       "acme",
		InvocationType: "manual",
		Provider:       "openai",
		Model:          "gpt-4o-mini",
		InputTier:      0,
		Detector:       "talon-regex",
	})
	require.NotNil(t, df, "every run that egresses must record a flow")
	require.Len(t, df.Items, 1)
	item := df.Items[0]
	assert.Equal(t, evidence.FlowSourcePrompt, item.Source)
	assert.Equal(t, evidence.FlowDispositionForwarded, item.Disposition)
	assert.Equal(t, evidence.FlowDestLLMProvider, item.Destination.Kind)
	assert.Equal(t, "openai", item.Destination.Name)
	assert.Equal(t, "US", item.Destination.Region, "region from registered provider metadata")
	assert.Empty(t, item.EntityTypes)
}

func TestBuildRunDataFlow_InputRedactedOutputPII(t *testing.T) {
	df := buildRunDataFlow(runFlowInputs{
		TenantID:         "acme",
		InvocationType:   "scheduled",
		Provider:         "openai",
		Model:            "gpt-4o-mini",
		InputTier:        2,
		InputPIITypes:    []string{"iban", "email"},
		InputPIIRedacted: true,
		OutputTier:       1,
		OutputPIITypes:   []string{"email"},
		OutputRedacted:   true,
	})
	require.Len(t, df.Items, 2)
	prompt, response := df.Items[0], df.Items[1]
	assert.Equal(t, evidence.FlowDispositionRedacted, prompt.Disposition)
	assert.Equal(t, []string{"email", "iban"}, prompt.EntityTypes, "sorted, deduped")
	assert.Equal(t, evidence.FlowSourceResponse, response.Source)
	assert.Equal(t, evidence.FlowDispositionRedacted, response.Disposition)
	assert.Equal(t, evidence.FlowDestClient, response.Destination.Kind)
	assert.Equal(t, "scheduled", response.Destination.Name)
}

func TestBuildRunDataFlow_OutputBlocked(t *testing.T) {
	df := buildRunDataFlow(runFlowInputs{
		TenantID:       "acme",
		InvocationType: "manual",
		Provider:       "openai",
		Model:          "gpt-4o-mini",
		OutputTier:     2,
		OutputPIITypes: []string{"iban"},
		OutputBlocked:  true,
	})
	require.Len(t, df.Items, 2)
	assert.Equal(t, evidence.FlowDispositionBlocked, df.Items[1].Disposition)
}

func TestBuildRunDataFlow_CacheHit(t *testing.T) {
	df := buildRunDataFlow(runFlowInputs{
		TenantID:       "acme",
		InvocationType: "manual",
		CacheHit:       true,
		CacheEntryID:   "cache_123",
	})
	require.Len(t, df.Items, 1)
	dest := df.Items[0].Destination
	assert.Equal(t, evidence.FlowDestCache, dest.Kind)
	assert.Equal(t, "cache_123", dest.Name)
	assert.Empty(t, dest.Region, "nothing egresses on a cache hit")
}

func TestProviderFlowRegion_Unregistered(t *testing.T) {
	assert.Equal(t, evidence.FlowRegionUnknown, providerFlowRegion("no-such-provider"))
}

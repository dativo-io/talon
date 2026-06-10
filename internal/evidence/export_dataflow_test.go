package evidence

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToExportRecord_DataFlowSummary(t *testing.T) {
	ev := &Evidence{
		ID:        "gw_flow",
		Timestamp: time.Now(),
		TenantID:  "acme",
		AgentID:   "support-bot",
		DataFlow: &DataFlow{
			Detector: "talon-regex",
			Items: []DataFlowItem{
				{
					Source:      FlowSourcePrompt,
					Tier:        2,
					EntityTypes: []string{"email", "iban"},
					Disposition: FlowDispositionForwarded,
					Destination: FlowDestination{Kind: FlowDestLLMProvider, Name: "openai", Region: "US"},
				},
				{
					Source:      FlowSourceResponse,
					Tier:        1,
					EntityTypes: []string{"email"},
					Disposition: FlowDispositionRedacted,
					Destination: FlowDestination{Kind: FlowDestClient, Name: "openclaw-main", Region: ""},
				},
				{
					// duplicate destination: must dedupe
					Source:      FlowSourceAttachment,
					Tier:        1,
					EntityTypes: []string{"phone"},
					Disposition: FlowDispositionForwarded,
					Destination: FlowDestination{Kind: FlowDestLLMProvider, Name: "openai", Region: "US"},
				},
			},
		},
	}

	rec := ToExportRecord(ev)
	assert.Equal(t, []string{"client:openclaw-main", "llm_provider:openai"}, rec.FlowDestinations)
	assert.Equal(t, []string{"US"}, rec.FlowRegions, "empty regions must be skipped, duplicates deduped")
	assert.Equal(t, []string{"email", "iban", "phone"}, rec.FlowEntityTypes)

	assert.Equal(t, "client:openclaw-main,llm_provider:openai", rec.FlowDestinationsCSV())
	assert.Equal(t, "US", rec.FlowRegionsCSV())
	assert.Equal(t, "email,iban,phone", rec.FlowEntityTypesCSV())
}

func TestToExportRecord_NoDataFlow(t *testing.T) {
	ev := &Evidence{ID: "gw_legacy", Timestamp: time.Now(), TenantID: "acme"}
	rec := ToExportRecord(ev)
	assert.Empty(t, rec.FlowDestinations)
	assert.Empty(t, rec.FlowRegions)
	assert.Empty(t, rec.FlowEntityTypes)
	assert.Equal(t, "", rec.FlowDestinationsCSV())
}

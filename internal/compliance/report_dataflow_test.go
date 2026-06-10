package compliance

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func flowEvidence(id string, items []evidence.DataFlowItem) evidence.Evidence {
	return evidence.Evidence{
		ID:        id,
		Timestamp: time.Now(),
		TenantID:  "acme",
		AgentID:   "support-bot",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  "allow",
		},
		DataFlow: &evidence.DataFlow{Detector: "talon-regex", Items: items},
	}
}

func TestBuildReport_AggregatesDataDestinations(t *testing.T) {
	openaiUS := evidence.FlowDestination{Kind: evidence.FlowDestLLMProvider, Name: "openai", Region: "US"}
	vendorEU := evidence.FlowDestination{Kind: evidence.FlowDestMCPTool, Name: "crm", Region: "EU"}

	list := []evidence.Evidence{
		flowEvidence("ev1", []evidence.DataFlowItem{
			{Source: evidence.FlowSourcePrompt, EntityTypes: []string{"email", "iban"}, Destination: openaiUS},
			// second item to the same destination in the same record: counts once
			{Source: evidence.FlowSourceAttachment, EntityTypes: []string{"phone"}, Destination: openaiUS},
		}),
		flowEvidence("ev2", []evidence.DataFlowItem{
			{Source: evidence.FlowSourcePrompt, EntityTypes: []string{"email"}, Destination: openaiUS},
			{Source: evidence.FlowSourceToolArgs, EntityTypes: []string{"national_id"}, Destination: vendorEU},
		}),
		// legacy record without data flow: counted in totals, no destination
		{ID: "ev3", Timestamp: time.Now(), TenantID: "acme", PolicyDecision: evidence.PolicyDecision{Allowed: true}},
	}

	r := BuildReport("", "acme", "", "", "", list)
	assert.Equal(t, 3, r.EvidenceCount)
	require.Len(t, r.DataDestinations, 2)

	// sorted by kind: llm_provider before mcp_tool
	openai := r.DataDestinations[0]
	assert.Equal(t, evidence.FlowDestLLMProvider, openai.Kind)
	assert.Equal(t, "openai", openai.Name)
	assert.Equal(t, "US", openai.Region)
	assert.Equal(t, 2, openai.RecordCount, "same destination in one record must count once")
	assert.Equal(t, []string{"email", "iban", "phone"}, openai.EntityTypes)

	crm := r.DataDestinations[1]
	assert.Equal(t, evidence.FlowDestMCPTool, crm.Kind)
	assert.Equal(t, "crm", crm.Name)
	assert.Equal(t, "EU", crm.Region)
	assert.Equal(t, 1, crm.RecordCount)
	assert.Equal(t, []string{"national_id"}, crm.EntityTypes)
}

func TestBuildReport_NoDataFlowRecords(t *testing.T) {
	list := []evidence.Evidence{
		{ID: "old1", Timestamp: time.Now(), TenantID: "acme", PolicyDecision: evidence.PolicyDecision{Allowed: true}},
	}
	r := BuildReport("", "acme", "", "", "", list)
	assert.Empty(t, r.DataDestinations, "pre-data-flow records must not fabricate destinations")
}

func TestRenderHTML_IncludesDataDestinations(t *testing.T) {
	list := []evidence.Evidence{
		flowEvidence("ev1", []evidence.DataFlowItem{
			{Source: evidence.FlowSourcePrompt, EntityTypes: []string{"email"}, Destination: evidence.FlowDestination{Kind: evidence.FlowDestLLMProvider, Name: "openai", Region: "US"}},
		}),
	}
	r := BuildReport("", "acme", "", "", "", list)
	html, err := RenderHTML(r)
	require.NoError(t, err)
	out := string(html)
	assert.Contains(t, out, "Data Destinations")
	assert.Contains(t, out, "openai")
	assert.True(t, strings.Contains(out, "GDPR Art. 30"), "report must phrase data flow as supporting evidence")
}

func TestRenderHTML_OmitsDataDestinationsWhenEmpty(t *testing.T) {
	r := BuildReport("", "acme", "", "", "", nil)
	html, err := RenderHTML(r)
	require.NoError(t, err)
	assert.NotContains(t, string(html), "Data Destinations")
}

package compliance

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func sovereigntyEvidence() []evidence.Evidence {
	return []evidence.Evidence{
		{
			ID: "sov_aaa", TenantID: "acme", AgentID: "gw", Timestamp: fixedTime,
			PolicyDecision: evidence.PolicyDecision{Allowed: true},
			RoutingDecision: &evidence.RoutingDecision{
				SelectedProvider: "mistral",
				SelectedModel:    "mistral-large",
				RejectedCandidates: []evidence.RejectedCandidate{
					{ProviderID: "openai", Reason: "jurisdiction not allowed"},
				},
			},
			DataFlow: &evidence.DataFlow{Items: []evidence.DataFlowItem{{
				Source: "prompt", Tier: 1,
				Disposition: evidence.FlowDispositionForwarded,
				Destination: evidence.FlowDestination{Kind: "llm_provider", Name: "mistral", Region: "EU"},
			}}},
		},
		{
			ID: "sov_bbb", TenantID: "acme", AgentID: "gw", Timestamp: fixedTime,
			PolicyDecision: evidence.PolicyDecision{Allowed: false},
			EgressDecision: &evidence.EgressDecision{
				Tier: 2, Provider: "openai", Region: "US",
				Decision: "deny", Reason: "egress_tier_destination_disallowed",
			},
		},
	}
}

func TestGenerateSovereigntyPosture_GoldenShape(t *testing.T) {
	cfg := SovereigntyPostureConfig{
		DataSovereigntyMode: "eu_strict",
		DeploymentMode:      "air_gap",
		AirGapEgressGuard:   true,
		AllowedEgressHosts:  []string{"llm.internal.example"},
		GatewayProviders: []SovereigntyGatewayProvider{
			{Name: "ollama", Region: "LOCAL", Enabled: true},
		},
		LLMProviders: []SovereigntyLLMProvider{
			{ID: "mistral", Allowed: true},
			{ID: "openai", Allowed: false, Reason: "jurisdiction not allowed"},
		},
	}
	doc, err := GenerateSovereigntyPosture(context.Background(), cfg, sovereigntyEvidence(), SovereigntyPostureOptions{
		TenantID:        "acme",
		From:            "2026-01-01",
		To:              "2026-06-11",
		SignedExportRef: "evidence.signed.json",
		Now:             fixedTime,
	})
	require.NoError(t, err)

	assert.Equal(t, "Sovereignty Posture Report", doc.Title)
	assert.Equal(t, "sovereignty", doc.Framework)
	assert.Equal(t, 2, doc.Linkage.EvidenceCount)
	assert.Equal(t, "talon audit verify --file evidence.signed.json", doc.Linkage.VerifyCommand)
	require.Len(t, doc.Sections, 5)
	assert.Contains(t, doc.Sections[0].Body, "eu_strict")
	assert.Contains(t, doc.Sections[0].Body, "air_gap")
	assert.NotNil(t, doc.Sections[4].Table)

	// policy denials: 1, egress denials: 1
	denialRows := doc.Sections[4].Table.Rows
	foundPolicy := false
	foundEgress := false
	for _, row := range denialRows {
		if row[0] == "Policy denials (any reason)" && row[1] == "1" {
			foundPolicy = true
		}
		if row[0] == "Egress denials" && row[1] == "1" {
			foundEgress = true
		}
	}
	assert.True(t, foundPolicy)
	assert.True(t, foundEgress)

	out, err := RenderDocumentJSON(doc)
	require.NoError(t, err)
	assert.Contains(t, string(out), "eu_strict")
}

func TestGenerateSovereigntyPosture_HTML(t *testing.T) {
	doc, err := GenerateSovereigntyPosture(context.Background(), SovereigntyPostureConfig{
		DataSovereigntyMode: "eu_strict",
	}, nil, SovereigntyPostureOptions{Now: fixedTime})
	require.NoError(t, err)
	html, err := RenderDocumentHTML(doc)
	require.NoError(t, err)
	assert.Contains(t, string(html), "Sovereignty Posture Report")
}

package compliance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func annexIVEvidence() []evidence.Evidence {
	t1 := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 20, 16, 30, 0, 0, time.UTC)
	return []evidence.Evidence{
		{
			ID: "req_aaa", TenantID: "acme", AgentID: "support-agent", Timestamp: t1,
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Classification: evidence.Classification{PIIDetected: []string{"email"}},
			Execution:      evidence.Execution{ModelUsed: "mistral-large", Cost: 0.01},
			DataFlow: &evidence.DataFlow{Items: []evidence.DataFlowItem{{
				Source: "prompt", Tier: 1,
				Destination: evidence.FlowDestination{Kind: "llm_provider", Name: "mistral-eu", Region: "EU"},
			}}},
			RoutingDecision: &evidence.RoutingDecision{},
		},
		{
			ID: "req_bbb", TenantID: "acme", AgentID: "support-agent", Timestamp: t2,
			PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"budget exceeded", "pii policy"}},
		},
		{
			ID: "req_ccc", TenantID: "acme", AgentID: "support-agent", Timestamp: t2,
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Execution:      evidence.Execution{ModelUsed: "gpt-4o-mini", Degraded: true, OriginalModel: "gpt-4o"},
			PlanReview:     &evidence.PlanReviewEvent{PlanID: "plan_1", EventType: "plan_approved"},
			MemoryWrites:   []evidence.MemoryWrite{{Category: "domain_knowledge"}},
			EgressDecision: &evidence.EgressDecision{Tier: 1, Provider: "openai", Decision: "allow"},
		},
	}
}

func annexIVOpts() AnnexIVOptions {
	return AnnexIVOptions{
		TenantID:        "acme",
		AgentID:         "support-agent",
		From:            "2026-01-01",
		To:              "2026-06-11",
		SignedExportRef: "evidence.signed.json",
		Now:             fixedTime,
	}
}

func TestGenerateAnnexIV_FullDeclarations(t *testing.T) {
	doc, err := GenerateAnnexIV(context.Background(), fullDeclarations(), annexIVEvidence(), annexIVOpts())
	require.NoError(t, err)

	assert.Empty(t, doc.Warnings)
	assert.Equal(t, "eu-ai-act", doc.Framework)
	assert.Equal(t, "Annex IV", doc.Article)
	assert.Equal(t, 3, doc.Linkage.EvidenceCount)
	assert.Contains(t, doc.ClaimNote, "not a completed legal filing")
	require.Len(t, doc.Sections, 6)

	for _, s := range doc.Sections {
		assert.False(t, s.Missing, "no section should be missing: %s", s.Heading)
	}

	general := sectionByHeading(t, doc, "1. General description of the AI system (Annex IV s.1)")
	require.NotNil(t, general.Table)
	cells := map[string]string{}
	for _, row := range general.Table.Rows {
		cells[row[0]] = row[1]
	}
	assert.Equal(t, "LLM assistant for support ticket triage", cells["System description (declared)"])
	assert.Equal(t, "gpt-4o-mini, mistral-large", cells["Models observed in evidence"])
	assert.Equal(t, "mistral-eu", cells["LLM providers observed in evidence"])
}

func TestGenerateAnnexIV_GoldenJSON(t *testing.T) {
	doc, err := GenerateAnnexIV(context.Background(), fullDeclarations(), annexIVEvidence(), annexIVOpts())
	require.NoError(t, err)
	out, err := RenderDocumentJSON(doc)
	require.NoError(t, err)
	checkGolden(t, "annexiv_full.json", out)
}

func TestGenerateAnnexIV_GoldenHTML(t *testing.T) {
	doc, err := GenerateAnnexIV(context.Background(), fullDeclarations(), annexIVEvidence(), annexIVOpts())
	require.NoError(t, err)
	out, err := RenderDocumentHTML(doc)
	require.NoError(t, err)
	checkGolden(t, "annexiv_full.html", out)
}

func TestGenerateAnnexIV_MissingDeclarations(t *testing.T) {
	doc, err := GenerateAnnexIV(context.Background(), Declarations{}, annexIVEvidence(), annexIVOpts())
	require.NoError(t, err, "missing declarations must never fail generation")

	assert.Len(t, doc.Warnings, 3)
	general := sectionByHeading(t, doc, "1. General description of the AI system (Annex IV s.1)")
	assert.True(t, general.Missing)
	assert.Equal(t, MissingDeclarationText, general.Body)

	// Runtime-fact sections still render.
	monitoring := sectionByHeading(t, doc, "3. Monitoring, functioning and control (Annex IV s.3, Art. 14 human oversight)")
	require.NotNil(t, monitoring.Table)
	assert.Contains(t, monitoring.Body, "no oversight declaration set")
}

func TestGenerateAnnexIV_MonitoringCounts(t *testing.T) {
	doc, err := GenerateAnnexIV(context.Background(), fullDeclarations(), annexIVEvidence(), annexIVOpts())
	require.NoError(t, err)

	monitoring := sectionByHeading(t, doc, "3. Monitoring, functioning and control (Annex IV s.3, Art. 14 human oversight)")
	require.NotNil(t, monitoring.Table)
	counts := map[string]string{}
	for _, row := range monitoring.Table.Rows {
		counts[row[0]] = row[1]
	}
	assert.Equal(t, "3", counts["Signed evidence records in scope"])
	assert.Equal(t, "1", counts["Policy denials enforced"])
	assert.Equal(t, "1", counts["Records with PII detected"])
	assert.Equal(t, "1", counts["Plan-review (human oversight) events"])
	assert.Equal(t, "1", counts["Cost-degradation fallbacks"])
	assert.Equal(t, "1", counts["Records with routing decisions (data sovereignty)"])
	assert.Equal(t, "1", counts["Records with egress decisions (destination control)"])
	assert.Contains(t, monitoring.Body, "Support lead reviews flagged tickets daily", "declared oversight included")
}

func TestGenerateAnnexIV_DenialReasonsInRiskSection(t *testing.T) {
	doc, err := GenerateAnnexIV(context.Background(), fullDeclarations(), annexIVEvidence(), annexIVOpts())
	require.NoError(t, err)

	risk := sectionByHeading(t, doc, "5. Risk management system (Annex IV s.5, Art. 9)")
	require.NotNil(t, risk.Table)
	assert.Contains(t, risk.Body, "Denial reasons")
	flat := map[string]string{}
	for _, row := range risk.Table.Rows {
		flat[row[0]] = row[1]
	}
	assert.Equal(t, "1", flat["budget exceeded"])
	assert.Equal(t, "1", flat["pii policy"])
}

func TestGenerateAnnexIV_OperatorItemsAlwaysListed(t *testing.T) {
	doc, err := GenerateAnnexIV(context.Background(), Declarations{}, nil, AnnexIVOptions{Now: fixedTime})
	require.NoError(t, err)

	operator := sectionByHeading(t, doc, "Items to complete outside Talon")
	require.NotNil(t, operator.Table)
	assert.Len(t, operator.Table.Rows, 4)
	assert.Contains(t, operator.Body, "not the model provider")
}

func TestGenerateAnnexIV_EmptyEvidence(t *testing.T) {
	doc, err := GenerateAnnexIV(context.Background(), fullDeclarations(), nil, annexIVOpts())
	require.NoError(t, err)

	assert.Equal(t, 0, doc.Linkage.EvidenceCount)
	postMarket := sectionByHeading(t, doc, "9. Post-market monitoring (Annex IV s.9, Art. 72)")
	assert.NotContains(t, postMarket.Body, "Scope covered", "no scope line without records")
}

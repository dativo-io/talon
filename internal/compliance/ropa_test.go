package compliance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func ropaEvidence() []evidence.Evidence {
	t1 := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 20, 16, 30, 0, 0, time.UTC)
	return []evidence.Evidence{
		{
			ID: "req_aaa", TenantID: "acme", AgentID: "support-agent", Timestamp: t1,
			Classification: evidence.Classification{PIIDetected: []string{"email"}},
			DataFlow: &evidence.DataFlow{Items: []evidence.DataFlowItem{{
				Source: "prompt", Tier: 1, EntityTypes: []string{"email"},
				Disposition: "forwarded",
				Destination: evidence.FlowDestination{Kind: "llm_provider", Name: "mistral-eu", Region: "EU"},
			}}},
		},
		{
			ID: "req_bbb", TenantID: "acme", AgentID: "support-agent", Timestamp: t2,
			Classification: evidence.Classification{PIIDetected: []string{"iban"}},
			DataFlow: &evidence.DataFlow{Items: []evidence.DataFlowItem{{
				Source: "prompt", Tier: 2, EntityTypes: []string{"iban"},
				Disposition: "redacted",
				Destination: evidence.FlowDestination{Kind: "llm_provider", Name: "openai", Region: "US"},
			}}},
		},
		{
			ID: "req_ccc", TenantID: "acme", AgentID: "sales-analyst", Timestamp: t2,
			DataFlow: &evidence.DataFlow{Items: []evidence.DataFlowItem{{
				Source: "prompt", Tier: 0,
				Disposition: "forwarded",
				Destination: evidence.FlowDestination{Kind: "llm_provider", Name: "unregistered", Region: "unknown"},
			}}},
		},
	}
}

func ropaOpts() RoPAOptions {
	return RoPAOptions{
		TenantID:        "acme",
		From:            "2026-01-01",
		To:              "2026-06-11",
		SignedExportRef: "evidence.signed.json",
		Now:             fixedTime,
	}
}

func TestGenerateRoPA_FullDeclarations(t *testing.T) {
	doc, err := GenerateRoPA(context.Background(), fullDeclarations(), ropaEvidence(), ropaOpts())
	require.NoError(t, err)

	assert.Empty(t, doc.Warnings, "complete declarations produce no warnings")
	assert.Equal(t, "gdpr", doc.Framework)
	assert.Equal(t, "Art. 30", doc.Article)
	assert.Equal(t, 3, doc.Linkage.EvidenceCount)
	assert.Equal(t, []string{"req_aaa", "req_bbb", "req_ccc"}, doc.Linkage.SampleEvidenceIDs)
	assert.Equal(t, "talon audit verify --file evidence.signed.json", doc.Linkage.VerifyCommand)
	require.Len(t, doc.Sections, 8, "Art. 30(1) section list")

	headings := make([]string, 0, len(doc.Sections))
	for _, s := range doc.Sections {
		headings = append(headings, s.Heading)
		assert.False(t, s.Missing, "no section should be missing: %s", s.Heading)
	}
	assert.Equal(t, []string{
		"1. Controller (Art. 30(1)(a))",
		"2. Processing activities observed",
		"3. Purposes of processing (Art. 30(1)(b))",
		"4. Categories of data subjects and personal data (Art. 30(1)(c))",
		"5. Categories of recipients (Art. 30(1)(d))",
		"6. Transfers to third countries (Art. 30(1)(e))",
		"7. Envisaged erasure time limits (Art. 30(1)(f))",
		"8. Technical and organisational security measures (Art. 30(1)(g), Art. 32)",
	}, headings)
}

func TestGenerateRoPA_GoldenJSON(t *testing.T) {
	doc, err := GenerateRoPA(context.Background(), fullDeclarations(), ropaEvidence(), ropaOpts())
	require.NoError(t, err)
	out, err := RenderDocumentJSON(doc)
	require.NoError(t, err)
	checkGolden(t, "ropa_full.json", out)
}

func TestGenerateRoPA_GoldenHTML(t *testing.T) {
	doc, err := GenerateRoPA(context.Background(), fullDeclarations(), ropaEvidence(), ropaOpts())
	require.NoError(t, err)
	out, err := RenderDocumentHTML(doc)
	require.NoError(t, err)
	checkGolden(t, "ropa_full.html", out)
}

func TestGenerateRoPA_MissingDeclarations(t *testing.T) {
	doc, err := GenerateRoPA(context.Background(), Declarations{}, ropaEvidence(), ropaOpts())
	require.NoError(t, err, "missing declarations must never fail generation")

	assert.Len(t, doc.Warnings, 5)
	missing := map[string]bool{}
	for _, s := range doc.Sections {
		if s.Missing {
			missing[s.Heading] = true
			assert.Equal(t, MissingDeclarationText, s.Body)
		}
	}
	assert.True(t, missing["1. Controller (Art. 30(1)(a))"])
	assert.True(t, missing["3. Purposes of processing (Art. 30(1)(b))"])
	assert.True(t, missing["7. Envisaged erasure time limits (Art. 30(1)(f))"])

	// Evidence-derived sections still render.
	recipients := sectionByHeading(t, doc, "5. Categories of recipients (Art. 30(1)(d))")
	require.NotNil(t, recipients.Table)
	assert.Len(t, recipients.Table.Rows, 3)
}

func TestGenerateRoPA_ThirdCountryTransfers(t *testing.T) {
	doc, err := GenerateRoPA(context.Background(), fullDeclarations(), ropaEvidence(), ropaOpts())
	require.NoError(t, err)

	transfers := sectionByHeading(t, doc, "6. Transfers to third countries (Art. 30(1)(e))")
	require.NotNil(t, transfers.Table)
	require.Len(t, transfers.Table.Rows, 2, "US and unknown destinations are transfers; EU is not")
	assert.Equal(t, "openai", transfers.Table.Rows[0][0])
	assert.Equal(t, "US", transfers.Table.Rows[0][2])
	assert.Equal(t, "unregistered", transfers.Table.Rows[1][0])
	assert.Contains(t, transfers.Body, "unresolved region", "unknown region must be called out")
}

func TestGenerateRoPA_NoThirdCountryTransfers(t *testing.T) {
	euOnly := []evidence.Evidence{ropaEvidence()[0]}
	doc, err := GenerateRoPA(context.Background(), fullDeclarations(), euOnly, ropaOpts())
	require.NoError(t, err)

	transfers := sectionByHeading(t, doc, "6. Transfers to third countries (Art. 30(1)(e))")
	assert.Nil(t, transfers.Table)
	assert.Contains(t, transfers.Body, "no third-country transfers were observed")
	assert.Contains(t, transfers.Body, "Data flows were recorded", "EU-only must read as an assessed finding")
}

func TestGenerateRoPA_ObservedPIIMergedIntoCategories(t *testing.T) {
	doc, err := GenerateRoPA(context.Background(), fullDeclarations(), ropaEvidence(), ropaOpts())
	require.NoError(t, err)

	categories := sectionByHeading(t, doc, "4. Categories of data subjects and personal data (Art. 30(1)(c))")
	require.NotNil(t, categories.Table)
	var observedRow []string
	for _, row := range categories.Table.Rows {
		if row[0] == "Personal data identifiers observed in evidence" {
			observedRow = row
		}
	}
	require.NotNil(t, observedRow, "observed identifiers row present")
	assert.Equal(t, "email, iban", observedRow[1], "sorted, deduped union of PIIDetected and flow entity types")
}

func TestGenerateRoPA_EmptyEvidence(t *testing.T) {
	doc, err := GenerateRoPA(context.Background(), fullDeclarations(), nil, ropaOpts())
	require.NoError(t, err)

	assert.Equal(t, 0, doc.Linkage.EvidenceCount)
	activities := sectionByHeading(t, doc, "2. Processing activities observed")
	assert.Contains(t, activities.Body, "No evidence records")
	recipients := sectionByHeading(t, doc, "5. Categories of recipients (Art. 30(1)(d))")
	assert.Contains(t, recipients.Body, "No classified data flows")
	transfers := sectionByHeading(t, doc, "6. Transfers to third countries (Art. 30(1)(e))")
	assert.Contains(t, transfers.Body, "cannot be assessed yet",
		"absence of data-flow evidence must not read as a no-transfers finding")
}

func TestGenerateRoPA_MultiTenantGrouping(t *testing.T) {
	list := ropaEvidence()
	list = append(list, evidence.Evidence{
		ID: "req_ddd", TenantID: "globex", AgentID: "support-agent",
		Timestamp: time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
	})
	doc, err := GenerateRoPA(context.Background(), fullDeclarations(), list, RoPAOptions{Now: fixedTime})
	require.NoError(t, err)

	activities := sectionByHeading(t, doc, "2. Processing activities observed")
	require.NotNil(t, activities.Table)
	require.Len(t, activities.Table.Rows, 3, "one row per (tenant, agent)")
	assert.Equal(t, []string{"acme", "sales-analyst", "1", "2026-05-20", "2026-05-20"}, activities.Table.Rows[0])
	assert.Equal(t, []string{"acme", "support-agent", "2", "2026-03-01", "2026-05-20"}, activities.Table.Rows[1])
	assert.Equal(t, []string{"globex", "support-agent", "1", "2026-04-02", "2026-04-02"}, activities.Table.Rows[2])
}

func sectionByHeading(t *testing.T, doc Document, heading string) DocSection {
	t.Helper()
	for _, s := range doc.Sections {
		if s.Heading == heading {
			return s
		}
	}
	t.Fatalf("section %q not found", heading)
	return DocSection{}
}

package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidenceEnrichmentAttributionGoldenFixture(t *testing.T) {
	ev := &Evidence{
		ID:             "evt_attr",
		CorrelationID:  "corr_attr",
		Timestamp:      time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC),
		TenantID:       "acme",
		AgentID:        "support-bot",
		InvocationType: "gateway",
		PolicyDecision: PolicyDecision{
			Allowed:       true,
			Action:        "allow",
			PolicyVersion: "v1",
		},
		Classification: Classification{
			InputTier:   2,
			PIIDetected: []string{"email", "iban"},
			PIIRedacted: true,
		},
		Execution: Execution{
			ModelUsed:  "gpt-4o-mini",
			Cost:       0.001,
			Tokens:     TokenUsage{Input: 10, Output: 8},
			DurationMS: 123,
		},
		AuditTrail: AuditTrail{
			InputHash:  "sha256:in",
			OutputHash: "sha256:out",
		},
		Compliance: Compliance{
			Frameworks:   []string{"gdpr"},
			DataLocation: "eu",
		},
	}

	entities := []classifier.PIIEntity{
		{
			Type:      "email",
			Value:     "john@example.com",
			Position:  14,
			FieldPath: "choices[0].message.content",
		},
		{
			Type:      "iban",
			Value:     "DE89370400440532013000",
			Position:  42,
			FieldPath: "choices[0].message.content",
		},
	}
	ev.DataFlow = &DataFlow{
		Detector: "talon-regex",
		Items: []DataFlowItem{
			NewDataFlowItem(
				"acme",
				"corr_attr",
				FlowSourceResponse,
				"",
				2,
				entities,
				FlowDispositionRedacted,
				FlowDestination{Kind: FlowDestClient, Name: "openclaw"},
			),
		},
	}

	actual, err := json.MarshalIndent(ev, "", "  ")
	require.NoError(t, err)

	fixturePath := filepath.Join("testdata", "enrichment_attribution_golden.json")
	expected, err := os.ReadFile(fixturePath)
	require.NoError(t, err)
	assert.JSONEq(t, string(expected), string(actual))

	// Compact attribution evidence must not expose raw PII values.
	assert.NotContains(t, string(actual), "john@example.com")
	assert.NotContains(t, string(actual), "DE89370400440532013000")

	// Signature verification still works with additive attribution fields.
	signer, err := NewSigner(testSigningKey)
	require.NoError(t, err)
	canonical, err := json.Marshal(ev)
	require.NoError(t, err)
	sig, err := signer.Sign(canonical)
	require.NoError(t, err)
	ev.Signature = sig
	store := newTestStore(t)
	assert.True(t, store.VerifyRecord(ev))
}

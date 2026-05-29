package events

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
)

func TestFromEvidence_UsesExplanationFirst(t *testing.T) {
	ev := &evidence.Evidence{
		ID:            "ev-1",
		Timestamp:     time.Now().UTC(),
		TenantID:      "acme",
		AgentID:       "agent-a",
		CorrelationID: "corr-1",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: false,
			Action:  "deny",
			Reasons: []string{"budget exceeded"},
		},
		Execution: evidence.Execution{
			ModelUsed:  "gpt-4o-mini",
			Cost:       0.11,
			DurationMS: 120,
		},
		Explanations: []explanation.Item{
			{
				Code:     explanation.CodePolicyDeniedPIIInput,
				Decision: explanation.DecisionDeny,
				Reason:   "Request blocked because input PII was detected.",
				Fix:      "Remove or mask sensitive data before retrying the request.",
			},
		},
	}

	out := FromEvidence(ev)
	assert.Equal(t, "blocked", out.Decision)
	assert.Equal(t, explanation.CodePolicyDeniedPIIInput, out.ReasonCode)
	assert.Equal(t, "Request blocked because input PII was detected.", out.ReasonText)
	assert.Equal(t, "Remove or mask sensitive data before retrying the request.", out.SuggestedFix)
}

func TestFromEvidence_FallsBackWithoutExplanation(t *testing.T) {
	ev := &evidence.Evidence{
		ID:        "ev-2",
		Timestamp: time.Now().UTC(),
		TenantID:  "acme",
		AgentID:   "agent-a",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: false,
			Action:  "deny",
			Reasons: []string{"IBAN detected in input"},
		},
	}

	out := FromEvidence(ev)
	assert.Equal(t, "blocked", out.Decision)
	assert.Equal(t, "PII_IBAN", out.ReasonCode)
	assert.Equal(t, "IBAN detected in input", out.ReasonText)
}

func TestFromEvidence_SanitizesSignalsAndReasonText(t *testing.T) {
	ev := &evidence.Evidence{
		ID:        "ev-3",
		Timestamp: time.Now().UTC(),
		TenantID:  "acme",
		AgentID:   "agent-a",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: false,
			Action:  "deny",
			Reasons: []string{"line1\nline2\tline3"},
		},
		Classification: evidence.Classification{
			PIIDetected: []string{"email", "email", " ", "iban"},
		},
		ToolGovernance: &evidence.ToolGovernance{
			ToolsFiltered: []string{"rm", "", "rm", "curl"},
		},
	}

	out := FromEvidence(ev)
	assert.Equal(t, "line1 line2 line3", out.ReasonText)
	assert.Equal(t, []string{"email", "iban"}, out.PIIDetected)
	assert.Equal(t, []string{"rm", "curl"}, out.ToolsFiltered)
}

func TestSortDesc_StableTieBreakOnEvidenceID(t *testing.T) {
	ts := time.Now().UTC()
	items := []OperationalEvent{
		{Timestamp: ts, EvidenceID: "ev-a"},
		{Timestamp: ts, EvidenceID: "ev-z"},
		{Timestamp: ts.Add(1 * time.Second), EvidenceID: "ev-b"},
	}
	SortDesc(items)

	assert.Equal(t, "ev-b", items[0].EvidenceID)
	assert.Equal(t, "ev-z", items[1].EvidenceID)
	assert.Equal(t, "ev-a", items[2].EvidenceID)
	assert.True(t, LessDesc(items[1], items[2]))
}

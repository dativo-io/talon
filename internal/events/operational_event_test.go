package events

import (
	"strings"
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

func TestFromEvidence_ResidualPIIReasonGetsRemediationFix(t *testing.T) {
	ev := &evidence.Evidence{
		ID:        "ev-residual",
		Timestamp: time.Now().UTC(),
		TenantID:  "acme",
		AgentID:   "agent-a",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: false,
			Action:  "deny",
			Reasons: []string{"request residual pii after redaction"},
		},
	}

	out := FromEvidence(ev)
	assert.Equal(t, "blocked", out.Decision)
	assert.Equal(t, "PII_RESIDUAL_BLOCKED", out.ReasonCode)
	assert.Contains(t, out.SuggestedFix, "approval workflow")
	assert.Contains(t, out.SuggestedFix, "re-scan")
}

func TestFromEvidence_ControlPlaneRemediationAppliedSurfaced(t *testing.T) {
	ev := &evidence.Evidence{
		ID:              "ev-remediation-applied",
		Timestamp:       time.Now().UTC(),
		TenantID:        "acme",
		InvocationType:  "control_plane",
		RequestSourceID: "admin_api",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  "tool_approval_approved",
			Reasons: []string{"approval_id=tappr_1 remediation_mode=re_redact_rescan remediation_status=applied"},
		},
	}

	out := FromEvidence(ev)
	assert.Equal(t, "allowed", out.Decision)
	assert.Equal(t, "PII_REMEDIATED_APPROVED", out.ReasonCode)
	assert.Contains(t, strings.ToLower(out.ReasonText), "remediation applied")
	assert.Contains(t, strings.ToLower(out.SuggestedFix), "evidence")
}

func TestFromEvidence_ControlPlaneRemediationFailedSurfaced(t *testing.T) {
	ev := &evidence.Evidence{
		ID:              "ev-remediation-failed",
		Timestamp:       time.Now().UTC(),
		TenantID:        "acme",
		InvocationType:  "control_plane",
		RequestSourceID: "admin_api",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  "tool_approval_remediation_failed",
			Reasons: []string{"approval_id=tappr_2 remediation_mode=re_redact_rescan error=residual pii"},
		},
	}

	out := FromEvidence(ev)
	assert.Equal(t, "blocked", out.Decision)
	assert.Equal(t, "PII_REMEDIATION_FAILED", out.ReasonCode)
	assert.Contains(t, strings.ToLower(out.ReasonText), "remediation failed")
	assert.Contains(t, strings.ToLower(out.SuggestedFix), "retry remediation")
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

func TestFromEvidence_ReasonsParity(t *testing.T) {
	longReason := strings.Repeat("x", 300)
	tests := []struct {
		name string
		ev   *evidence.Evidence
		want []string
	}{
		{
			name: "policy_and_explanation_are_combined_and_deduped",
			ev: &evidence.Evidence{
				ID:        "ev-r1",
				Timestamp: time.Now().UTC(),
				TenantID:  "acme",
				PolicyDecision: evidence.PolicyDecision{
					Allowed: false,
					Action:  "deny",
					Reasons: []string{"PII detected", "budget exceeded", "pii detected"},
				},
				Execution: evidence.Execution{
					Error: "upstream timeout",
				},
				Explanations: []explanation.Item{
					{Reason: "Request blocked because input PII was detected."},
					{Reason: "BUDGET exceeded"},
				},
			},
			want: []string{
				"PII detected",
				"budget exceeded",
				"Request blocked because input PII was detected.",
				"upstream timeout",
			},
		},
		{
			name: "multiline_whitespace_is_collapsed",
			ev: &evidence.Evidence{
				ID:        "ev-r2",
				Timestamp: time.Now().UTC(),
				TenantID:  "acme",
				PolicyDecision: evidence.PolicyDecision{
					Reasons: []string{"line1\nline2\tline3"},
				},
			},
			want: []string{"line1 line2 line3"},
		},
		{
			name: "case_insensitive_dedupe_keeps_first",
			ev: &evidence.Evidence{
				ID:        "ev-r3",
				Timestamp: time.Now().UTC(),
				TenantID:  "acme",
				PolicyDecision: evidence.PolicyDecision{
					Reasons: []string{"PII detected", "pii detected", "Pii Detected"},
				},
			},
			want: []string{"PII detected"},
		},
		{
			name: "reasons_are_capped_to_ten",
			ev: &evidence.Evidence{
				ID:        "ev-r4",
				Timestamp: time.Now().UTC(),
				TenantID:  "acme",
				PolicyDecision: evidence.PolicyDecision{
					Reasons: []string{
						"r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
					},
				},
			},
			want: []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"},
		},
		{
			name: "long_reason_is_truncated",
			ev: &evidence.Evidence{
				ID:        "ev-r5",
				Timestamp: time.Now().UTC(),
				TenantID:  "acme",
				PolicyDecision: evidence.PolicyDecision{
					Reasons: []string{longReason},
				},
			},
			want: []string{strings.Repeat("x", 220)},
		},
		{
			name: "empty_sources_return_nil",
			ev: &evidence.Evidence{
				ID:        "ev-r6",
				Timestamp: time.Now().UTC(),
				TenantID:  "acme",
			},
			want: nil,
		},
		{
			name: "execution_error_is_included",
			ev: &evidence.Evidence{
				ID:        "ev-r7",
				Timestamp: time.Now().UTC(),
				TenantID:  "acme",
				Execution: evidence.Execution{
					Error: "context deadline exceeded",
				},
			},
			want: []string{"context deadline exceeded"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := FromEvidence(tt.ev)
			assert.Equal(t, tt.want, out.Reasons)
		})
	}
}

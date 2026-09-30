package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
)

func gatewayRecord(rs *evidence.ResponseScan, df *evidence.DataFlow, items ...explanation.Item) *evidence.Evidence {
	return &evidence.Evidence{
		ID: "ev-rs", TenantID: "acme", AgentID: "bot",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Classification: evidence.Classification{OutputPIIDetected: true, OutputPIITypes: []string{"email"}, ResponseScan: rs},
		DataFlow:       df,
		Explanations:   items,
	}
}

// Operator projections must not turn a warn observation into "redacted" or
// "blocked" (#476), while genuine preventive redaction still projects as
// redacted and a withheld response as blocked.
func TestFromEvidence_ResponseScanProjection(t *testing.T) {
	observedItem := explanation.Item{Code: explanation.CodePolicyObservedPIIOutput, Decision: explanation.DecisionAllow, Stage: explanation.StageOutputValidation, Reason: explanation.ReasonText(explanation.CodePolicyObservedPIIOutput)}
	redactedItem := explanation.Item{Code: explanation.CodePolicyRedactedPIIOutput, Decision: explanation.DecisionModify, Stage: explanation.StageOutputValidation, Reason: explanation.ReasonText(explanation.CodePolicyRedactedPIIOutput)}
	legacyDenyItem := explanation.Item{Code: explanation.CodePolicyDeniedPIIOutput, Decision: explanation.DecisionDeny, Stage: explanation.StageOutputValidation, Reason: "Request blocked because output PII was detected."}
	surfaced := &evidence.DataFlow{Items: []evidence.DataFlowItem{{Source: evidence.FlowSourceResponse, Disposition: evidence.FlowDispositionSurfaced}}}
	redactedFlow := &evidence.DataFlow{Items: []evidence.DataFlowItem{{Source: evidence.FlowSourceResponse, Disposition: evidence.FlowDispositionRedacted}}}

	cases := []struct {
		name         string
		ev           *evidence.Evidence
		wantDecision string
		wantCode     string
	}{
		{"1.10 streamed warn", gatewayRecord(&evidence.ResponseScan{Action: "warn", Enforcement: evidence.ResponseScanEnforcementPostDelivery}, surfaced, observedItem), "allowed", explanation.CodePolicyObservedPIIOutput},
		{"1.10 non-stream warn", gatewayRecord(&evidence.ResponseScan{Action: "warn", Enforcement: evidence.ResponseScanEnforcementObservation}, surfaced, observedItem), "allowed", explanation.CodePolicyObservedPIIOutput},
		{"1.10 preventive redact", gatewayRecord(&evidence.ResponseScan{Action: "redact", Enforcement: evidence.ResponseScanEnforcementPreventive}, redactedFlow, redactedItem), "redacted", explanation.CodePolicyRedactedPIIOutput},
		{"pre-1.10 warn with legacy deny explanation", gatewayRecord(nil, surfaced, legacyDenyItem), "allowed", explanation.CodePolicyObservedPIIOutput},
		{"pre-1.10 redact with legacy deny explanation", gatewayRecord(nil, redactedFlow, legacyDenyItem), "redacted", explanation.CodePolicyRedactedPIIOutput},
		{"1.10 warn without explanations (fallback path)", gatewayRecord(&evidence.ResponseScan{Action: "warn", Enforcement: evidence.ResponseScanEnforcementPostDelivery}, surfaced), "allowed", explanation.CodePolicyObservedPIIOutput},
		{"1.10 redact without explanations (fallback path)", gatewayRecord(&evidence.ResponseScan{Action: "redact", Enforcement: evidence.ResponseScanEnforcementPreventive}, redactedFlow), "redacted", "PII_REDACTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := FromEvidence(tc.ev)
			assert.Equal(t, tc.wantDecision, out.Decision)
			assert.Equal(t, tc.wantCode, out.ReasonCode)
			assert.True(t, out.Allowed)
			assert.NotContains(t, out.ReasonText, "blocked", "an allowed record must not read as blocked")
			if tc.wantCode == explanation.CodePolicyObservedPIIOutput {
				assert.Equal(t, "Response PII observed; the response was not modified.", out.ReasonText)
				assert.NotContains(t, out.ReasonText, "after delivery", "timing is a response_scan fact, not part of the generic explanation")
			}
		})
	}

	t.Run("block stays blocked", func(t *testing.T) {
		ev := gatewayRecord(&evidence.ResponseScan{Action: "block", Enforcement: evidence.ResponseScanEnforcementPreventive}, nil, legacyDenyItem)
		ev.PolicyDecision = evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"output_pii_blocked"}}
		out := FromEvidence(ev)
		assert.Equal(t, "blocked", out.Decision)
		assert.Equal(t, explanation.CodePolicyDeniedPIIOutput, out.ReasonCode)
	})
}

// The signed pre-#476 fixtures (a warn response with PII, streamed and not)
// project as allowed observations, never as blocked or redacted.
func TestFromEvidence_PreResponseScanFixturesProjectAsObserved(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "evidence", "testdata", "pre_response_scan", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, err := os.ReadFile(p) // #nosec G304 -- test fixture
			require.NoError(t, err)
			var ev evidence.Evidence
			require.NoError(t, json.Unmarshal(raw, &ev))
			require.Nil(t, ev.Classification.ResponseScan)
			out := FromEvidence(&ev)
			assert.Equal(t, "allowed", out.Decision)
			assert.Equal(t, explanation.CodePolicyObservedPIIOutput, out.ReasonCode)
			assert.True(t, out.Allowed)
		})
	}
}

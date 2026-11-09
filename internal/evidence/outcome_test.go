package evidence

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/explanation"
)

// TestOutcomeOf_SeparatesDecisionDispatchAndDownstream pins the projection
// rule by rule (#541): the People Analytics distinctions — Talon denied and
// nothing was sent, Talon allowed and the HR backend rejected the call,
// provider failed and a fallback answered — come from recorded facts, and a
// record type without such facts says not_recorded.
func TestOutcomeOf_SeparatesDecisionDispatchAndDownstream(t *testing.T) {
	allow := PolicyDecision{Allowed: true, Action: "allow"}
	deny := PolicyDecision{Allowed: false, Action: "deny"}
	tool := Execution{ToolsCalled: []string{"hr_aggregate_sql"}}
	cases := []struct {
		name       string
		ev         Evidence
		decision   string
		dispatch   string
		downstream string
		withheld   bool
	}{
		{"forbidden MCP tool: denied, never sent", Evidence{InvocationType: "proxy_tool_blocked", PolicyDecision: deny, Execution: Execution{ToolsCalled: []string{"hr_employee_export"}, Error: "forbidden_tools"}}, "denied", DispatchNotDispatched, DownstreamNone, false},
		{"allowed MCP tool answered", Evidence{InvocationType: "proxy_tool_call", PolicyDecision: allow, Execution: tool}, "allowed", DispatchDispatched, DownstreamCompleted, false},
		{"allowed MCP tool, HR backend rejected the SQL", Evidence{InvocationType: "proxy_upstream_error", PolicyDecision: allow, Status: StatusFailed, FailureReason: "upstream_error", Execution: Execution{ToolsCalled: []string{"hr_aggregate_sql"}, Error: "upstream_jsonrpc_error:invalid_params"}}, "allowed", DispatchDispatched, DownstreamRejected, false},
		{"upstream unreachable: outcome unknown", Evidence{InvocationType: "proxy_upstream_error", PolicyDecision: allow, Status: StatusUnknown, Execution: Execution{Error: "upstream_error: connection reset"}}, "allowed", DispatchUnknown, DownstreamUnknown, false},
		{"request invalid before the transport", Evidence{InvocationType: "proxy_upstream_error", PolicyDecision: allow, Status: StatusFailed, Execution: Execution{Error: "outbound_request_invalid"}}, "allowed", DispatchNotDispatched, DownstreamNone, false},
		{"tool answer withheld by output scanning", Evidence{InvocationType: "proxy_tool_call", PolicyDecision: deny, Execution: Execution{Error: "output_scanner_unavailable"}}, "denied", DispatchDispatched, DownstreamCompleted, true},
		{"gateway allowed", Evidence{InvocationType: "gateway", PolicyDecision: allow, Execution: Execution{ModelUsed: "gpt-4o-mini"}}, "allowed", DispatchDispatched, DownstreamCompleted, false},
		{"gateway allowed, provider answered an error status", Evidence{InvocationType: "gateway", PolicyDecision: allow, Execution: Execution{Error: "upstream 503"}, Failover: &FailoverContext{UpstreamStatus: 503}}, "allowed", DispatchDispatched, DownstreamFailed, false},
		{"gateway allowed, error without a provider response: delivery not proven", Evidence{InvocationType: "gateway", PolicyDecision: allow, Execution: Execution{Error: "dial tcp: connection refused"}}, "allowed", DispatchUnknown, DownstreamUnknown, false},
		{"failover attempt with a provider status", Evidence{InvocationType: "gateway_failover_attempt", PolicyDecision: allow, Failover: &FailoverContext{UpstreamStatus: 503, ErrorClass: "server_error"}}, "allowed", DispatchDispatched, DownstreamFailed, false},
		{"failover attempt timed out: unknown, not dispatched-and-failed", Evidence{InvocationType: "gateway_failover_attempt", PolicyDecision: allow, Failover: &FailoverContext{ErrorClass: "timeout"}}, "allowed", DispatchUnknown, DownstreamUnknown, false},
		{"gateway cache hit: no provider call", Evidence{InvocationType: "gateway", PolicyDecision: allow, CacheHit: true, CacheEntryID: "c1", Execution: Execution{ModelUsed: "gpt-4o-mini"}}, "allowed", DispatchNotDispatched, DownstreamCache, false},
		{"gateway denied by policy before the provider", Evidence{InvocationType: "gateway", PolicyDecision: deny, Explanations: []explanation.Item{{Code: "POLICY_DENIED_COST", Decision: "deny", Stage: "policy_evaluation"}}}, "denied", DispatchNotDispatched, DownstreamNone, false},
		{"gateway denied at output validation", Evidence{InvocationType: "gateway", PolicyDecision: deny, Explanations: []explanation.Item{{Code: "POLICY_DENIED_PII_OUTPUT", Decision: "deny", Stage: "output_validation"}}}, "denied", DispatchDispatched, DownstreamCompleted, true},
		{"gateway denial without a stage: not guessed", Evidence{InvocationType: "gateway", PolicyDecision: deny}, "denied", DispatchNotRecorded, DownstreamNotRecorded, false},
		{"action refused", Evidence{InvocationType: InvocationTypeActionLifecycle, PolicyDecision: deny, ActionLifecycle: &ActionLifecycle{Event: ActionEventAuthorizationRefused}}, "denied", DispatchNotDispatched, DownstreamNone, false},
		{"action attempt observed, succeeded", Evidence{InvocationType: InvocationTypeActionLifecycle, PolicyDecision: allow, ActionLifecycle: &ActionLifecycle{Event: ActionEventAttemptCompleted, ResultProvenance: ResultProvenanceObserved, AttemptStatus: "succeeded"}}, "allowed", DispatchDispatched, DownstreamCompleted, false},
		{"action attempt outcome unknown", Evidence{InvocationType: InvocationTypeActionLifecycle, PolicyDecision: allow, ActionLifecycle: &ActionLifecycle{Event: ActionEventAttemptCompleted, ResultProvenance: ResultProvenanceUnknown}}, "allowed", DispatchUnknown, DownstreamUnknown, false},
		{"action established: no attempt fact yet", Evidence{InvocationType: InvocationTypeActionLifecycle, PolicyDecision: allow, ActionLifecycle: &ActionLifecycle{Event: ActionEventOperationEstablished}}, "allowed", DispatchNotRecorded, DownstreamNotRecorded, false},
		{"native run: decision only", Evidence{InvocationType: "manual", PolicyDecision: allow}, "allowed", DispatchNotRecorded, DownstreamNotRecorded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := OutcomeOf(&tc.ev)
			assert.Equal(t, tc.decision, got.Decision)
			assert.Equal(t, tc.dispatch, got.Dispatch)
			assert.Equal(t, tc.downstream, got.Downstream)
			assert.Equal(t, tc.withheld, got.ResponseWithheld)
			assert.NotEmpty(t, got.Basis, "every outcome names the recorded fact it was read from")
		})
	}
	assert.Equal(t, "hr_employee_export", OutcomeOf(&cases[0].ev).Tool)
	idx := IndexOf(&cases[0].ev)
	if assert.NotNil(t, idx.Outcome, "timeline rows carry the outcome") {
		assert.Equal(t, DispatchNotDispatched, idx.Outcome.Dispatch)
	}
}

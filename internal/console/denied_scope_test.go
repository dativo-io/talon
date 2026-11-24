package console

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// #590: the use case's denial counter counts denied REQUESTS (request-class
// records: LLM gateway and tool requests). A governed action decision
// (Action Gateway, over HTTP or MCP: an action_lifecycle record) is not a
// request; it is listed under the use case's recent decisions with its own
// outcome. The Console labels the counter "Denied requests" for exactly this
// metric; this test pins the metric the label describes.
func TestUseCaseDeniedCounter_CountsRequestsNotGovernedActionDecisions(t *testing.T) {
	ctx := context.Background()
	in := newInstallation(t, map[string]string{"hr-analytics-assistant": ""})
	in.traffic(t, "llm-denied", "default", "hr-analytics-assistant", false, 0, 20)
	in.traffic(t, "llm-allowed", "default", "hr-analytics-assistant", true, 0.01, 19)
	// A governed MCP tools/call that Talon denied: prepared and refused,
	// never dispatched.
	require.NoError(t, in.writer.Store(ctx, &evidence.Evidence{
		ID: "act-export-denied", CorrelationID: "op-export", TenantID: "default", AgentID: "hr-analytics-assistant",
		Timestamp: in.now.Add(-10 * time.Minute), InvocationType: evidence.InvocationTypeActionLifecycle,
		PolicyDecision:  evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"tool not allowed by policy"}},
		ActionLifecycle: &evidence.ActionLifecycle{Event: evidence.ActionEventOperationEstablished, Verdict: "DENY", OperationID: "mcp-export"},
	}))
	svc := in.service(t)

	d, err := svc.UseCase(ctx, "default", "hr-analytics-assistant")
	require.NoError(t, err)
	require.NotNil(t, d.Row)
	assert.Equal(t, 2, d.Row.Requests, "requests are request-class records")
	assert.Equal(t, 1, d.Row.Denied, "denied requests: the governed action denial is not counted here")

	byID := map[string]evidence.Index{}
	for _, r := range d.RecentDecisions.Records {
		byID[r.ID] = r
	}
	require.Contains(t, byID, "act-export-denied", "the governed action decision is listed under recent decisions")
	require.Contains(t, byID, "llm-denied")
	act := byID["act-export-denied"]
	require.NotNil(t, act.Outcome)
	assert.Equal(t, "denied", act.Outcome.Decision, "listed as a Talon denial")
	assert.False(t, act.Allowed)

	// The day counters on the Overview are the same request-class metric.
	td := svc.Overview(ctx, "default").Today
	assert.Equal(t, 2, td.Requests)
	assert.Equal(t, 1, td.Denied)
}

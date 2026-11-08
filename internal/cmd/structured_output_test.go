package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/drift"
	"github.com/dativo-io/talon/internal/evidence"
	talonsession "github.com/dativo-io/talon/internal/session"
)

// resetAuditFlags clears the cobra flag globals shared by the audit
// subcommands between Execute calls.
func resetAuditFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		auditTenant, auditAgent, auditSession, auditRuntimeRef = "", "", "", ""
		auditLimit, auditOffset = 20, 0
		auditReport, auditJSON = false, false
		monitorTenant, monitorJSON = "", false
	}
	reset()
	t.Cleanup(reset)
}

func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestAuditListShow_JSONIsTheSharedProjection (#535): `audit list --json`
// emits the store's Index rows, `--session --json` the shared Timeline,
// `audit show --json` the shared RecordDetail with a real verification
// state. Hand counts come from the #271 fixture (seedOperationalSession).
func TestAuditListShow_JSONIsTheSharedProjection(t *testing.T) {
	dir := sessionTestEnv(t)
	resetAuditFlags(t)
	_, evStore := sessionTestStores(t, dir)
	seedOperationalSession(t, evStore)
	ctx := context.Background()

	t.Run("list", func(t *testing.T) {
		resetAuditFlags(t)
		out, err := runRoot(t, "audit", "list", "--json", "--limit", "3")
		require.NoError(t, err, out)
		var rows []evidence.Index
		require.NoError(t, json.Unmarshal([]byte(out), &rows), out)
		require.Len(t, rows, 3, "--limit bounds the JSON too")
		want, err := evStore.ListIndex(ctx, "", "", time.Time{}, time.Time{}, 3, "", "", "")
		require.NoError(t, err)
		for i := range want {
			assert.Equal(t, want[i].ID, rows[i].ID)
			assert.Equal(t, want[i].InvocationType, rows[i].InvocationType)
			assert.Equal(t, want[i].Allowed, rows[i].Allowed)
		}
		assert.False(t, rows[0].Timestamp.Before(rows[1].Timestamp), "newest first, as the text list")
	})

	t.Run("session timeline", func(t *testing.T) {
		resetAuditFlags(t)
		out, err := runRoot(t, "audit", "list", "--json", "--session", "ext-sess-1")
		require.NoError(t, err, out)
		var tl talonsession.Timeline
		require.NoError(t, json.Unmarshal([]byte(out), &tl), out)
		records, err := evStore.ListBySessionID(ctx, "ext-sess-1")
		require.NoError(t, err)
		require.Len(t, tl.Records, len(records))
		for i := 1; i < len(tl.Records); i++ {
			assert.False(t, tl.Records[i].Timestamp.Before(tl.Records[i-1].Timestamp), "timeline is in source-time order")
		}
		assert.Equal(t, "ext-sess-1", tl.Summary.SessionID)
		assert.Equal(t, len(records), tl.Summary.RecordCount)
		// The fixture's shape, by hand: one denied request and one blocked tool call are denials.
		assert.GreaterOrEqual(t, tl.Summary.Denied, 1)
		assert.Equal(t, 1, tl.Summary.ToolCallsDenied)
		assert.Equal(t, 1, tl.Summary.Fallbacks)
		// A provider sub-attempt keeps its own type in the timeline; it is not a request.
		var attempts int
		for _, r := range tl.Records {
			if r.InvocationType == "gateway_failover_attempt" {
				attempts++
				assert.True(t, r.HasError)
			}
		}
		assert.Equal(t, 1, attempts)
		assert.Equal(t, tl, talonsession.BuildTimeline("ext-sess-1", records), "CLI output is the shared projection")
	})

	t.Run("session timeline for an unknown session is an empty timeline", func(t *testing.T) {
		resetAuditFlags(t)
		out, err := runRoot(t, "audit", "list", "--json", "--session", "nope")
		require.NoError(t, err, out)
		var tl talonsession.Timeline
		require.NoError(t, json.Unmarshal([]byte(out), &tl), out)
		assert.Empty(t, tl.Records)
		assert.Zero(t, tl.Summary.RecordCount)
	})

	t.Run("show", func(t *testing.T) {
		resetAuditFlags(t)
		out, err := runRoot(t, "audit", "show", "e_served", "--json")
		require.NoError(t, err, out)
		var d evidence.RecordDetail
		require.NoError(t, json.Unmarshal([]byte(out), &d), out)
		require.NotNil(t, d.Record)
		assert.Equal(t, "e_served", d.Record.ID)
		assert.Equal(t, "valid", d.Verification.State)
		assert.False(t, d.Verification.CheckedAt.IsZero())
		assert.InDelta(t, 0.10, d.Record.Execution.Cost, 1e-9)
	})
}

// TestMonitorPlanPending_JSON (#535): `monitor --json` is the drift analyzer's
// rows in deterministic order; `plan pending --json` is the pending plans.
func TestMonitorPlanPending_JSON(t *testing.T) {
	dir := sessionTestEnv(t)
	resetAuditFlags(t)
	_, evStore := sessionTestStores(t, dir)
	seedOperationalSession(t, evStore)
	ctx := context.Background()
	// A second agent with a record in the current 24h window, so ordering is observable.
	require.NoError(t, evStore.Store(ctx, &evidence.Evidence{
		ID: "e_alpha", CorrelationID: "corr_alpha", TenantID: "default", AgentID: "alpha-bot", Timestamp: time.Now().UTC().Add(-5 * time.Minute),
		InvocationType: "gateway", PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"}, Execution: evidence.Execution{Cost: 0.01},
	}))

	out, err := runRoot(t, "monitor", "--json", "--tenant", "default")
	require.NoError(t, err, out)
	var rows []drift.AgentDrift
	require.NoError(t, json.Unmarshal([]byte(out), &rows), out)
	require.Len(t, rows, 2)
	assert.Equal(t, "alpha-bot", rows[0].AgentID, "sorted by agent id")
	assert.Equal(t, "support-bot", rows[1].AgentID)
	for _, r := range rows {
		require.Len(t, r.Signals, 3)
		assert.Equal(t, "cost_anomaly", r.Signals[0].Name)
	}
	want, err := drift.NewAnalyzer(evStore).ComputeSignals(ctx, "default", time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, len(want), len(rows))
	for i := range want {
		assert.Equal(t, want[i].AgentID, rows[i].AgentID)
		assert.InDelta(t, want[i].Signals[0].Current, rows[i].Signals[0].Current, 1e-9)
	}

	planPendingJSON = false
	t.Cleanup(func() { planPendingJSON = false })
	pout, err := runRoot(t, "plan", "pending", "--json", "--tenant", "default")
	require.NoError(t, err, pout)
	assert.Equal(t, "[]\n", pout, "no pending plans is an empty list, not prose")
}

package metrics

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// Dashboard orchestration sessions panel (#199, epic #192 PR-H).

const sessionsTestKey = "test-signing-key-1234567890123456"

func sessEvidence(id, sessionID, caller, provider, model, agentID string, cost float64, allowed bool, ts time.Time) *evidence.Evidence {
	ev := &evidence.Evidence{
		ID:             id,
		CorrelationID:  "corr_" + id,
		SessionID:      sessionID,
		Timestamp:      ts,
		TenantID:       "default",
		AgentID:        caller,
		InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: allowed, Action: "allow"},
		Execution: evidence.Execution{
			ModelUsed:  model,
			Cost:       cost,
			Tokens:     evidence.TokenUsage{Input: 100, Output: 20},
			DurationMS: 50,
		},
		RoutingDecision: &evidence.RoutingDecision{SelectedProvider: provider, SelectedModel: model},
		Orchestration: &evidence.OrchestrationContext{
			SessionID:     sessionID,
			AgentID:       agentID,
			Client:        "claude-code",
			SessionSource: "client_asserted",
			Provenance:    "client_asserted",
		},
	}
	if !allowed {
		ev.PolicyDecision.Action = "deny"
		ev.PolicyDecision.Reasons = []string{"session_budget_exceeded: session spend 6.00 + estimate 1.00 exceeds limit 5.00"}
	}
	return ev
}

func newSessionsEvidenceStore(t *testing.T) *evidence.Store {
	t.Helper()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), sessionsTestKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestFillSessions_MixedProviderIsOneSession: a session spanning two providers
// renders as ONE session with the per-provider/model breakdown — the point of
// the feature.
func TestFillSessions_MixedProviderIsOneSession(t *testing.T) {
	store := newSessionsEvidenceStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	require.NoError(t, store.Store(ctx, sessEvidence("ev1", "sess-mix", "coder", "anthropic", "claude-opus-4-8", "generator", 0.20, true, now.Add(-2*time.Minute))))
	require.NoError(t, store.Store(ctx, sessEvidence("ev2", "sess-mix", "coder", "openai", "gpt-5.3-codex", "executor", 0.10, true, now.Add(-1*time.Minute))))

	c := NewCollector("enforce", nil, WithSessionQuerier(store))
	defer c.Close()
	snap := c.Snapshot(ctx)

	require.Len(t, snap.Sessions, 1, "one session id spanning two providers must render as ONE session")
	sess := snap.Sessions[0]
	assert.Equal(t, "sess-mix", sess.SessionID)
	assert.Equal(t, []string{"anthropic", "openai"}, sess.Providers)
	assert.Len(t, sess.Models, 2)
	assert.Equal(t, 2, sess.RecordCount)
	assert.InDelta(t, 0.30, sess.TotalCost, 1e-9)
	require.Len(t, sess.Subagents, 2, "per-agent rollup embedded")
	assert.Equal(t, "generator", sess.Subagents[0].AgentID, "agents sorted by descending cost")
}

// TestFillSessions_EqualsAuditSummary: the dashboard number and the
// `talon audit --session` number come from the same function over the same
// records — assert the wiring preserves that.
func TestFillSessions_EqualsAuditSummary(t *testing.T) {
	store := newSessionsEvidenceStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	require.NoError(t, store.Store(ctx, sessEvidence("ev1", "sess-eq", "coder", "anthropic", "claude-sonnet-5", "generator", 0.07, true, now.Add(-3*time.Minute))))
	require.NoError(t, store.Store(ctx, sessEvidence("ev2", "sess-eq", "coder", "openai", "gpt-5.3-codex", "judge", 0.02, false, now.Add(-1*time.Minute))))

	c := NewCollector("enforce", nil, WithSessionQuerier(store))
	defer c.Close()
	snap := c.Snapshot(ctx)
	require.Len(t, snap.Sessions, 1)

	records, err := store.ListBySessionID(ctx, "sess-eq")
	require.NoError(t, err)
	audit := evidence.BuildSessionSummary("sess-eq", records)

	assert.Equal(t, audit, snap.Sessions[0], "dashboard and talon audit must be byte-identical for the same session")
}

// TestFillSessions_SurvivesReconcile: session stats are re-derived from the
// store on every snapshot, so a destructive ReconcileFromStore rebuild cannot
// change them.
func TestFillSessions_SurvivesReconcile(t *testing.T) {
	store := newSessionsEvidenceStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	require.NoError(t, store.Store(ctx, sessEvidence("ev1", "sess-rec", "coder", "anthropic", "claude-sonnet-5", "generator", 0.05, true, now.Add(-2*time.Minute))))
	require.NoError(t, store.Store(ctx, sessEvidence("ev2", "sess-rec", "coder", "openai", "gpt-5.3-codex", "judge", 0.01, true, now.Add(-1*time.Minute))))

	c := NewCollector("enforce", nil, WithSessionQuerier(store))
	defer c.Close()

	before := c.Snapshot(ctx).Sessions
	require.Len(t, before, 1)

	_, err := c.ReconcileFromStore(ctx, store, time.Hour, 1000)
	require.NoError(t, err)

	after := c.Snapshot(ctx).Sessions
	assert.Equal(t, before, after, "destructive rebuild must not change session stats")
}

// TestFillSessions_HiddenWithoutOrchestration: synthetic-only traffic (no
// orchestration blocks) yields no sessions — the panel stays hidden.
func TestFillSessions_HiddenWithoutOrchestration(t *testing.T) {
	store := newSessionsEvidenceStore(t)
	ctx := context.Background()
	ev := sessEvidence("ev1", "sess_gw_abc", "coder", "openai", "gpt-5.3-codex", "", 0.01, true, time.Now().UTC())
	ev.Orchestration = nil // synthetic: no orchestration block
	require.NoError(t, store.Store(ctx, ev))

	c := NewCollector("enforce", nil, WithSessionQuerier(store))
	defer c.Close()
	snap := c.Snapshot(ctx)
	assert.Empty(t, snap.Sessions)
}

// TestFillSessions_BoundedByRecency: more sessions than the cap → only the
// most recently active survive, newest first.
func TestFillSessions_BoundedByRecency(t *testing.T) {
	store := newSessionsEvidenceStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < maxDashboardSessions+5; i++ {
		id := string(rune('a'+i%26)) + "-sess-" + time.Duration(i).String()
		ev := sessEvidence("ev-"+id, "sess-"+id, "coder", "openai", "gpt-5.3-codex", "agent", 0.01, true,
			now.Add(-time.Duration(maxDashboardSessions+5-i)*time.Minute))
		require.NoError(t, store.Store(ctx, ev))
	}
	c := NewCollector("enforce", nil, WithSessionQuerier(store))
	defer c.Close()
	snap := c.Snapshot(ctx)
	require.Len(t, snap.Sessions, maxDashboardSessions)
	// Newest-first ordering: first session's LastSeen >= last session's.
	first := snap.Sessions[0].LastSeen
	last := snap.Sessions[len(snap.Sessions)-1].LastSeen
	assert.False(t, first.Before(last), "sessions must be ordered by recency")
}

// TestDenialsByReason_SessionDenialsNotLumped: a session-budget deny buckets
// under its machine code, not generic policy_deny.
func TestDenialsByReason_SessionDenialsNotLumped(t *testing.T) {
	c := NewCollector("enforce", nil)
	defer c.Close()
	now := time.Now().UTC()

	denied := sessEvidence("ev1", "s", "coder", "openai", "gpt-5.3-codex", "agent", 0, false, now)
	generic := sessEvidence("ev2", "s", "coder", "openai", "gpt-5.3-codex", "agent", 0, false, now)
	generic.PolicyDecision.Reasons = []string{"Model gpt-5.3-codex not in caller allowlist"}
	budget := sessEvidence("ev3", "s", "coder", "openai", "gpt-5.3-codex", "agent", 0, false, now)
	budget.PolicyDecision.Reasons = []string{"budget_exceeded: request would exceed caller daily cost limit (100.00)"}

	c.Record(GatewayEventFromEvidence(denied))
	c.Record(GatewayEventFromEvidence(generic))
	c.Record(GatewayEventFromEvidence(budget))
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	got := map[string]int{}
	for _, rc := range snap.DenialsByReason {
		got[rc.Reason] = rc.Count
	}
	assert.Equal(t, 1, got["session_budget_exceeded"])
	assert.Equal(t, 1, got["budget_exceeded"])
	assert.Equal(t, 1, got["policy_deny"], "prose reasons fall back to policy_deny")
}

// TestGatewayEventFromEvidence_ProjectsSessionFields: the projection carries
// the session spine + orchestration attribution (#199 — previously dropped).
func TestGatewayEventFromEvidence_ProjectsSessionFields(t *testing.T) {
	ev := sessEvidence("ev1", "sess-proj", "coder", "anthropic", "claude-sonnet-5", "generator", 0.01, true, time.Now().UTC())
	got := GatewayEventFromEvidence(ev)
	assert.Equal(t, "sess-proj", got.SessionID)
	assert.Equal(t, "client_asserted", got.SessionSource)
	assert.Equal(t, "generator", got.OrchAgentID)
	assert.Equal(t, "claude-code", got.OrchClient)
	assert.Empty(t, got.DenyReasonCode, "allowed request carries no deny code")

	den := sessEvidence("ev2", "sess-proj", "coder", "anthropic", "claude-sonnet-5", "generator", 0, false, time.Now().UTC())
	assert.Equal(t, "session_budget_exceeded", GatewayEventFromEvidence(den).DenyReasonCode)
}

func TestDenyReasonCode(t *testing.T) {
	assert.Equal(t, "policy_deny", denyReasonCode(nil))
	assert.Equal(t, "policy_deny", denyReasonCode([]string{"Data tier 2 exceeds caller restriction (max 1)"}))
	assert.Equal(t, "session_budget_exceeded", denyReasonCode([]string{"session_budget_exceeded: spend"}))
	assert.Equal(t, "egress_tier_destination_disallowed", denyReasonCode([]string{"egress_tier_destination_disallowed"}))
	assert.Equal(t, "policy_deny", denyReasonCode([]string{"<img onerror=alert(1)>: nope"}), "hostile prefix falls back")
}

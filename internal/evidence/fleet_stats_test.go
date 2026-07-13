package evidence

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// storeRec writes one signed evidence record with full control over the fields
// the fleet-stats queries read.
func storeRec(t *testing.T, s *Store, id, tenant, agent, invType string, allowed bool, cost float64, ts time.Time, failoverRole string) {
	t.Helper()
	action := "allow"
	if !allowed {
		action = "deny"
	}
	ev := &Evidence{
		ID:             id,
		CorrelationID:  "corr_" + id,
		Timestamp:      ts,
		TenantID:       tenant,
		AgentID:        agent,
		InvocationType: invType,
		PolicyDecision: PolicyDecision{Allowed: allowed, Action: action},
		Execution:      Execution{Cost: cost, Currency: "EUR"},
	}
	if failoverRole != "" {
		ev.Failover = &FailoverContext{Role: failoverRole, Provider: "openai"}
	}
	require.NoError(t, s.Store(context.Background(), ev))
}

func TestAgentTrafficStats_RequestClassOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	from := now.Add(-time.Hour)
	inWindow := now.Add(-30 * time.Minute)

	// coding: 3 request-class rows in window, 1 denied.
	storeRec(t, s, "c1", "acme", "coding", "gateway", true, 0.1, inWindow, "")
	storeRec(t, s, "c2", "acme", "coding", "api", true, 0.1, inWindow, "")
	storeRec(t, s, "c3", "acme", "coding", "http", false, 0, inWindow, "")
	// coding: non-request rows that must NOT count as traffic.
	storeRec(t, s, "c4", "acme", "coding", "config_reload", false, 0, inWindow, "")
	storeRec(t, s, "c5", "acme", "coding", "gateway_failover_attempt", false, 0, inWindow, "")
	storeRec(t, s, "c6", "acme", "coding", "agent_disabled", false, 0, inWindow, "")
	// coding: a request-class row OUTSIDE the window (2h ago) — excluded.
	storeRec(t, s, "c7", "acme", "coding", "gateway", true, 0.1, now.Add(-2*time.Hour), "")

	// summarizer: 1 allowed request-class row.
	storeRec(t, s, "s1", "acme", "summarizer", "gateway", true, 0.1, inWindow, "")

	stats, err := s.AgentTrafficStats(ctx, "acme", from, now)
	require.NoError(t, err)

	require.Equal(t, TrafficStats{Requests: 3, Denied: 1}, stats["coding"],
		"only in-window request-class rows count; failover/config/lifecycle excluded")
	require.Equal(t, TrafficStats{Requests: 1, Denied: 0}, stats["summarizer"])
}

func TestAgentTrafficStats_AllTenants(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	from := now.Add(-time.Hour)
	inWindow := now.Add(-10 * time.Minute)

	storeRec(t, s, "a1", "acme", "coding", "gateway", true, 0.1, inWindow, "")
	storeRec(t, s, "g1", "globex", "summarizer", "gateway", false, 0, inWindow, "")

	// Empty tenant spans all tenants (agent names are fleet-unique).
	all, err := s.AgentTrafficStats(ctx, "", from, now)
	require.NoError(t, err)
	require.Equal(t, 1, all["coding"].Requests)
	require.Equal(t, TrafficStats{Requests: 1, Denied: 1}, all["summarizer"])

	// Tenant-scoped sees only its own.
	scoped, err := s.AgentTrafficStats(ctx, "acme", from, now)
	require.NoError(t, err)
	require.Contains(t, scoped, "coding")
	require.NotContains(t, scoped, "summarizer")
}

func TestFallbackCountsByAgent_DispatchesOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	from := now.Add(-time.Hour)
	inWindow := now.Add(-20 * time.Minute)

	// Two dispatches (fallback_decision) count; failed_attempt / fail_closed do not.
	storeRec(t, s, "f1", "acme", "coding", "llm_failover_decision", true, 0.1, inWindow, FailoverRoleFallbackDecision)
	storeRec(t, s, "f2", "acme", "coding", "gateway", true, 0.1, inWindow, FailoverRoleFallbackDecision)
	storeRec(t, s, "f3", "acme", "coding", "llm_failover_attempt", false, 0, inWindow, FailoverRoleFailedAttempt)
	storeRec(t, s, "f4", "acme", "coding", "gateway", false, 0, inWindow, FailoverRoleFailClosed)
	// A dispatch outside the window is excluded.
	storeRec(t, s, "f5", "acme", "coding", "gateway", true, 0.1, now.Add(-2*time.Hour), FailoverRoleFallbackDecision)

	counts, err := s.FallbackCountsByAgent(ctx, "acme", from, now)
	require.NoError(t, err)
	require.Equal(t, 2, counts["coding"], "only in-window fallback dispatches count")
}

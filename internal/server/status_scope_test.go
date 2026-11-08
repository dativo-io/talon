package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// TestStatus_CountsScopeIsAllRecordClasses (#535): /v1/status counts every
// persisted record class and says so, while the fleet traffic counters count
// request-class records only. The two denominators are documented, distinct
// and both pinned here with hand counts.
func TestStatus_CountsScopeIsAllRecordClasses(t *testing.T) {
	srv, store := newEventsTestServer(t, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	if now.Sub(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)) < 2*time.Minute {
		t.Skip("too close to UTC midnight for a same-day fixture")
	}
	ts := now.Add(-time.Minute)
	// One allowed request, one denied request, one denied proxied tool action
	// (request-class, like every intercepted tool action) and one failed
	// provider sub-attempt (not request-class): 4 records, 2 denied,
	// 3 request-class.
	insertEvidence(t, store, "req-ok", "default", "bot", ts, true, 0.10)
	insertEvidence(t, store, "req-deny", "default", "bot", ts, false, 0)
	require.NoError(t, store.Store(ctx, &evidence.Evidence{
		ID: "tool-deny", CorrelationID: "corr-tool-deny", Timestamp: ts, TenantID: "default", AgentID: "bot",
		InvocationType: "proxy_tool_blocked", PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny"},
	}))
	require.NoError(t, store.Store(ctx, &evidence.Evidence{
		ID: "attempt", CorrelationID: "corr-attempt", Timestamp: ts, TenantID: "default", AgentID: "bot",
		InvocationType: "gateway_failover_attempt", PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Status: "failed", Execution: evidence.Execution{Error: "upstream status 529", Cost: 0.02},
	}))
	require.Equal(t, evidence.ClassRequest, evidence.RecordClassOf("proxy_tool_blocked"))
	require.NotEqual(t, evidence.ClassRequest, evidence.RecordClassOf("gateway_failover_attempt"))

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/status?tenant_id=default", nil)
	req.Header.Set("X-Talon-Admin-Key", "admin-secret")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "all_record_classes", body["counts_scope"])
	assert.EqualValues(t, 4, body["evidence_count_today"], "every class counts")
	assert.EqualValues(t, 2, body["blocked_count"], "denied request + denied tool action")
	assert.InDelta(t, 0.12, body["cost_today"].(float64), 1e-9, "cost sums every class, the sub-attempt's 0.02 included")

	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	traffic, err := store.AgentTrafficStats(ctx, "default", dayStart, dayStart.Add(24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 3, traffic["bot"].Requests, "fleet denominator: request-class only (the sub-attempt is excluded, the tool action included)")
	assert.Equal(t, 2, traffic["bot"].Denied)
}

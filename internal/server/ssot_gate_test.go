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

	"github.com/dativo-io/talon/internal/health"
)

// SSOT gate: ordering and core-field parity across evidence and events API.
func TestSSOTGate_RecentEventsParityOrdering(t *testing.T) {
	srv, store := newEventsTestServer(t, map[string]string{"k-default": "default"})
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-g1", "default", "agent-a", now.Add(-2*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-g2", "default", "agent-a", now.Add(-1*time.Second), false, 0.00)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/recent?limit=10", nil)
	req.Header.Set("Authorization", "Bearer k-default")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var out struct {
		Events []map[string]interface{} `json:"events"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	require.Len(t, out.Events, 2)
	assert.Equal(t, "ev-g2", out.Events[0]["evidence_id"])
	assert.Equal(t, "ev-g1", out.Events[1]["evidence_id"])
	require.NotEmpty(t, out.Events[0]["event_id"])
	require.NotEmpty(t, out.Events[0]["tenant_id"])
	require.NotEmpty(t, out.Events[0]["agent_id"])
}

// SSOT gate: reconnect path emits gap contract when replay window is exceeded.
func TestSSOTGate_StreamReconnectGapContract(t *testing.T) {
	health.ResetEventStreamStatsForTest()
	t.Cleanup(health.ResetEventStreamStatsForTest)

	srv, store := newEventsTestServer(t, map[string]string{"k-default": "default"})
	srv.eventsReplayBacklog = 1
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-r1", "default", "agent-a", now.Add(-3*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-r2", "default", "agent-a", now.Add(-2*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-r3", "default", "agent-a", now.Add(-1*time.Second), true, 0.01)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer k-default")
	req.Header.Set("Last-Event-ID", eventsIDForTest(now.Add(-3*time.Second), "ev-r1"))
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)
	srv.Routes().ServeHTTP(rec, req)

	assert.Contains(t, rec.Body.String(), "event: gap")
	assert.GreaterOrEqual(t, health.EventStreamGaps(), int64(1))
}

// SSOT gate: degraded-mode contract is surfaced via /v1/status.
func TestSSOTGate_DegradedStatusContract(t *testing.T) {
	health.ResetEvidenceWriteStatusForTest()
	t.Cleanup(health.ResetEvidenceWriteStatusForTest)
	health.MarkEvidenceWriteFailure(time.Now().UTC(), assert.AnError)

	srv, _ := newEventsTestServer(t, map[string]string{"k-default": "default"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/status", nil)
	req.Header.Set("Authorization", "Bearer k-default")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "degraded", out["status"])
	assert.Equal(t, false, out["evidence_ok"])
	_, hasReason := out["evidence_error"]
	assert.True(t, hasReason)
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/health"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestEventsRecentParityWithEvidenceList(t *testing.T) {
	srv, store := newEventsTestServer(t, map[string]string{"k-default": "default"})
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-a", "default", "agent-a", now.Add(-2*time.Second), true, 0.12)
	insertEvidence(t, store, "ev-b", "default", "agent-a", now.Add(-1*time.Second), false, 0.0)

	r := srv.Routes()
	evidenceReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/evidence?limit=10", nil)
	evidenceReq.Header.Set("Authorization", "Bearer k-default")
	evidenceRec := httptest.NewRecorder()
	r.ServeHTTP(evidenceRec, evidenceReq)
	require.Equal(t, http.StatusOK, evidenceRec.Code)

	eventsReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/recent?limit=10", nil)
	eventsReq.Header.Set("Authorization", "Bearer k-default")
	eventsRec := httptest.NewRecorder()
	r.ServeHTTP(eventsRec, eventsReq)
	require.Equal(t, http.StatusOK, eventsRec.Code)

	var evList struct {
		Entries []evidence.Index `json:"entries"`
	}
	require.NoError(t, json.NewDecoder(evidenceRec.Body).Decode(&evList))
	var recent struct {
		Events []map[string]interface{} `json:"events"`
	}
	require.NoError(t, json.NewDecoder(eventsRec.Body).Decode(&recent))

	require.Len(t, recent.Events, len(evList.Entries))
	assert.Equal(t, evList.Entries[0].ID, recent.Events[0]["evidence_id"])
}

func TestEventsRecentTenantIsolation(t *testing.T) {
	srv, store := newEventsTestServer(t, map[string]string{"k-acme": "acme", "k-other": "other"})
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-acme", "acme", "agent-a", now, true, 0.01)
	insertEvidence(t, store, "ev-other", "other", "agent-b", now.Add(1*time.Millisecond), true, 0.02)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/recent?limit=10", nil)
	req.Header.Set("Authorization", "Bearer k-acme")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var recent struct {
		Events []struct {
			TenantID string `json:"tenant_id"`
		} `json:"events"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&recent))
	require.NotEmpty(t, recent.Events)
	for _, ev := range recent.Events {
		assert.Equal(t, "acme", ev.TenantID)
	}
}

func TestEventsStreamRespectsLastEventID(t *testing.T) {
	health.ResetEventStreamStatsForTest()
	t.Cleanup(health.ResetEventStreamStatsForTest)
	srv, store := newEventsTestServer(t, map[string]string{"k-default": "default"})
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-1", "default", "agent-a", now.Add(-2*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-2", "default", "agent-a", now.Add(-1*time.Second), true, 0.01)

	since := "0-"
	list, err := store.List(context.Background(), "default", "", time.Time{}, time.Now().UTC(), 10)
	require.NoError(t, err)
	for i := range list {
		if list[i].ID == "ev-1" {
			since = eventsIDForTest(list[i].Timestamp, list[i].ID)
		}
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer k-default")
	req.Header.Set("Last-Event-ID", since)
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	srv.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	assert.Contains(t, body, "id: ")
	assert.Contains(t, body, "\"evidence_id\":\"ev-2\"")
	assert.NotContains(t, body, "\"evidence_id\":\"ev-1\"")
}

func TestEventsStreamGapSignalAndTelemetry(t *testing.T) {
	health.ResetEventStreamStatsForTest()
	t.Cleanup(health.ResetEventStreamStatsForTest)
	srv, store := newEventsTestServer(t, map[string]string{"k-default": "default"})
	srv.eventsReplayBacklog = 3
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-1", "default", "agent-a", now.Add(-4*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-2", "default", "agent-a", now.Add(-3*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-3", "default", "agent-a", now.Add(-2*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-4", "default", "agent-a", now.Add(-1*time.Second), true, 0.01)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer k-default")
	req.Header.Set("Last-Event-ID", eventsIDForTest(now.Add(-4*time.Second), "ev-1"))
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	srv.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	assert.Contains(t, body, "event: gap")
	assert.GreaterOrEqual(t, health.EventReplayMisses(), int64(1))
	assert.GreaterOrEqual(t, health.EventStreamGaps(), int64(1))
}

func TestEventsStreamTenantIsolation(t *testing.T) {
	srv, store := newEventsTestServer(t, map[string]string{"k-acme": "acme", "k-other": "other"})
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-acme-1", "acme", "agent-a", now.Add(-2*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-acme-2", "acme", "agent-a", now.Add(-1*time.Second), true, 0.02)
	insertEvidence(t, store, "ev-other-1", "other", "agent-b", now, true, 0.03)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer k-acme")
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	srv.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	assert.Contains(t, body, "\"tenant_id\":\"acme\"")
	assert.Contains(t, body, "\"evidence_id\":\"ev-acme-1\"")
	assert.Contains(t, body, "\"evidence_id\":\"ev-acme-2\"")
	assert.NotContains(t, body, "\"tenant_id\":\"other\"")
	assert.NotContains(t, body, "\"evidence_id\":\"ev-other-1\"")
}

func TestEventsStreamHonorsConnectionLimit(t *testing.T) {
	health.ResetEventStreamStatsForTest()
	t.Cleanup(health.ResetEventStreamStatsForTest)
	srv, _ := newEventsTestServer(t, map[string]string{"k-default": "default"})
	srv.eventsStreamMaxConn = 1
	health.IncActiveEventStreams()
	t.Cleanup(func() { health.DecActiveEventStreams() })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer k-default")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestStatusIncludesEvidenceDegradedFields(t *testing.T) {
	health.ResetEvidenceWriteStatusForTest()
	health.ResetEventStreamStatsForTest()
	health.MarkEvidenceWriteFailure(time.Now().UTC(), assert.AnError)
	t.Cleanup(func() {
		health.ResetEvidenceWriteStatusForTest()
		health.ResetEventStreamStatsForTest()
	})

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
	_, hasLastGood := out["last_good_write"]
	_ = hasLastGood
	_, hasErr := out["evidence_error"]
	assert.True(t, hasErr)
	_, hasStreamActive := out["events_stream_active"]
	_, hasStreamGaps := out["events_stream_gaps"]
	_, hasReplayMisses := out["events_replay_misses"]
	assert.True(t, hasStreamActive && hasStreamGaps && hasReplayMisses)
}

func newEventsTestServer(t *testing.T, tenantKeys map[string]string) (*Server, *evidence.Store) {
	t.Helper()
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, "admin-secret", tenantKeys)
	return srv, store
}

func insertEvidence(t *testing.T, store *evidence.Store, id, tenantID, agentID string, ts time.Time, allowed bool, cost float64) {
	t.Helper()
	ev := evidence.Evidence{
		ID:              id,
		CorrelationID:   "corr-" + id,
		Timestamp:       ts.UTC(),
		TenantID:        tenantID,
		AgentID:         agentID,
		InvocationType:  "gateway",
		RequestSourceID: agentID,
		PolicyDecision: evidence.PolicyDecision{
			Allowed: allowed,
			Action:  map[bool]string{true: "allow", false: "deny"}[allowed],
		},
		Classification: evidence.Classification{},
		Execution: evidence.Execution{
			ModelUsed:  "gpt-4o-mini",
			Cost:       cost,
			DurationMS: 100,
		},
	}
	require.NoError(t, store.Store(context.Background(), &ev))
}

func eventsIDForTest(ts time.Time, evidenceID string) string {
	return fmt.Sprintf("%d-%s", ts.UTC().UnixMilli(), evidenceID)
}

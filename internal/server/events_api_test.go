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

	"github.com/dativo-io/talon/internal/events"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
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

func TestEventsRecentParityWithEvidenceList_TieBreakByEvidenceID(t *testing.T) {
	srv, store := newEventsTestServer(t, map[string]string{"k-default": "default"})
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-a", "default", "agent-a", now, true, 0.12)
	insertEvidence(t, store, "ev-z", "default", "agent-a", now, false, 0.0)

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
	require.GreaterOrEqual(t, len(evList.Entries), 2)
	require.GreaterOrEqual(t, len(recent.Events), 2)
	assert.Equal(t, evList.Entries[0].ID, recent.Events[0]["evidence_id"])
	assert.Equal(t, "ev-z", evList.Entries[0].ID)
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

func TestEventsRecentIncludesReasonsAndPreservesTenantIsolation(t *testing.T) {
	srv, store := newEventsTestServer(t, map[string]string{"k-acme": "acme", "k-other": "other"})
	now := time.Now().UTC()

	denied := evidence.Evidence{
		ID:              "ev-reasons-denied",
		CorrelationID:   "corr-ev-reasons-denied",
		Timestamp:       now,
		TenantID:        "acme",
		AgentID:         "agent-a",
		InvocationType:  "gateway",
		RequestSourceID: "agent-a",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: false,
			Action:  "deny",
			Reasons: []string{"PII detected", "budget exceeded"},
		},
		Explanations: []explanation.Item{
			{Reason: "Request blocked because input PII was detected."},
		},
		Execution: evidence.Execution{
			ModelUsed:  "gpt-4o-mini",
			Cost:       0.00,
			DurationMS: 100,
			Error:      "upstream timeout",
		},
	}
	require.NoError(t, store.Store(context.Background(), &denied))

	allowed := evidence.Evidence{
		ID:              "ev-reasons-allowed",
		CorrelationID:   "corr-ev-reasons-allowed",
		Timestamp:       now.Add(1 * time.Millisecond),
		TenantID:        "other",
		AgentID:         "agent-b",
		InvocationType:  "gateway",
		RequestSourceID: "agent-b",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  "allow",
		},
		Execution: evidence.Execution{
			ModelUsed:  "gpt-4o-mini",
			Cost:       0.01,
			DurationMS: 100,
		},
	}
	require.NoError(t, store.Store(context.Background(), &allowed))
	r := srv.Routes()

	tenantReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/recent?limit=10", nil)
	tenantReq.Header.Set("Authorization", "Bearer k-acme")
	tenantRec := httptest.NewRecorder()
	r.ServeHTTP(tenantRec, tenantReq)
	require.Equal(t, http.StatusOK, tenantRec.Code)

	var tenantRecent struct {
		Events []struct {
			EvidenceID string   `json:"evidence_id"`
			TenantID   string   `json:"tenant_id"`
			Reasons    []string `json:"reasons"`
		} `json:"events"`
	}
	require.NoError(t, json.NewDecoder(tenantRec.Body).Decode(&tenantRecent))
	require.Len(t, tenantRecent.Events, 1)
	assert.Equal(t, "ev-reasons-denied", tenantRecent.Events[0].EvidenceID)
	assert.Equal(t, "acme", tenantRecent.Events[0].TenantID)
	assert.Equal(t, []string{
		"PII detected",
		"budget exceeded",
		"Request blocked because input PII was detected.",
		"upstream timeout",
	}, tenantRecent.Events[0].Reasons)

	adminReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/recent?tenant_id=*&limit=10", nil)
	adminReq.Header.Set("X-Talon-Admin-Key", "admin-secret")
	adminRec := httptest.NewRecorder()
	r.ServeHTTP(adminRec, adminReq)
	require.Equal(t, http.StatusOK, adminRec.Code)

	var adminRecent struct {
		Events []map[string]interface{} `json:"events"`
	}
	require.NoError(t, json.NewDecoder(adminRec.Body).Decode(&adminRecent))
	require.Len(t, adminRecent.Events, 2)

	var foundDenied bool
	var foundAllowed bool
	for _, ev := range adminRecent.Events {
		switch ev["evidence_id"] {
		case "ev-reasons-denied":
			foundDenied = true
			reasons, ok := ev["reasons"].([]interface{})
			require.True(t, ok)
			require.NotEmpty(t, reasons)
		case "ev-reasons-allowed":
			foundAllowed = true
			if reasonsRaw, hasReasons := ev["reasons"]; hasReasons {
				reasons, ok := reasonsRaw.([]interface{})
				require.True(t, ok)
				for _, reason := range reasons {
					reasonText, ok := reason.(string)
					require.True(t, ok)
					assert.NotEmpty(t, reasonText)
				}
			}
		}
	}
	assert.True(t, foundDenied)
	assert.True(t, foundAllowed)
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

func TestEventsParity_BoundedWindowAcrossCLIAndAPI(t *testing.T) {
	srv, store := newEventsTestServer(t, map[string]string{"k-default": "default"})
	now := time.Now().UTC()
	insertEvidence(t, store, "ev-p1", "default", "agent-a", now.Add(-2*time.Second), true, 0.01)
	insertEvidence(t, store, "ev-p2", "default", "agent-a", now.Add(-1*time.Second), false, 0.00)

	cliSource, err := store.List(context.Background(), "default", "", time.Time{}, time.Now().UTC(), 20)
	require.NoError(t, err)
	cliEvents := make([]map[string]interface{}, 0, len(cliSource))
	for i := range cliSource {
		ev := events.FromEvidence(&cliSource[i])
		cliEvents = append(cliEvents, map[string]interface{}{
			"event_id":       ev.EventID,
			"evidence_id":    ev.EvidenceID,
			"tenant_id":      ev.TenantID,
			"agent_id":       ev.AgentID,
			"correlation_id": ev.CorrelationID,
			"allowed":        ev.Allowed,
			"decision":       ev.Decision,
			"cost_eur":       ev.CostEUR,
			"model":          ev.Model,
		})
	}

	r := srv.Routes()
	evidenceReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/evidence?limit=20", nil)
	evidenceReq.Header.Set("Authorization", "Bearer k-default")
	evidenceRec := httptest.NewRecorder()
	r.ServeHTTP(evidenceRec, evidenceReq)
	require.Equal(t, http.StatusOK, evidenceRec.Code)
	var evList struct {
		Entries []evidence.Index `json:"entries"`
	}
	require.NoError(t, json.NewDecoder(evidenceRec.Body).Decode(&evList))

	eventsReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events/recent?limit=20", nil)
	eventsReq.Header.Set("Authorization", "Bearer k-default")
	eventsRec := httptest.NewRecorder()
	r.ServeHTTP(eventsRec, eventsReq)
	require.Equal(t, http.StatusOK, eventsRec.Code)
	var recent struct {
		Events []map[string]interface{} `json:"events"`
	}
	require.NoError(t, json.NewDecoder(eventsRec.Body).Decode(&recent))

	require.Equal(t, len(evList.Entries), len(recent.Events))
	require.Equal(t, len(cliEvents), len(recent.Events))
	for i := range recent.Events {
		assert.Equal(t, evList.Entries[i].ID, recent.Events[i]["evidence_id"])
		assert.Equal(t, cliEvents[i]["evidence_id"], recent.Events[i]["evidence_id"])
		assert.Equal(t, cliEvents[i]["decision"], recent.Events[i]["decision"])
		assert.Equal(t, cliEvents[i]["tenant_id"], recent.Events[i]["tenant_id"])
		assert.Equal(t, cliEvents[i]["agent_id"], recent.Events[i]["agent_id"])
		assert.Equal(t, cliEvents[i]["correlation_id"], recent.Events[i]["correlation_id"])
		assert.InDelta(t, cliEvents[i]["cost_eur"].(float64), recent.Events[i]["cost_eur"].(float64), 0.0001)
	}
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
	assert.GreaterOrEqual(t, health.EventBacklogDrops(), int64(1))
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
	assert.GreaterOrEqual(t, health.EventStreamDisconnects(), int64(1))
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
	_, hasDisconnects := out["events_stream_disconnects"]
	_, hasBacklogDrops := out["events_backlog_drops"]
	assert.True(t, hasStreamActive && hasStreamGaps && hasReplayMisses && hasDisconnects && hasBacklogDrops)
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

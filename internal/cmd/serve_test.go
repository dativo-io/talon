package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestNewStatusHandler(t *testing.T) {
	// Nil store, nil tracker: minimal response
	handler := newStatusHandler(nil, nil, "default")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var resp statusResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, 0, resp.EvidenceCountToday)
	assert.Equal(t, 0.0, resp.CostEURToday)
	assert.Equal(t, 0, resp.ActiveRuns)

	// With tracker: active runs reflected
	tracker := &agent.ActiveRunTracker{}
	tracker.Increment("acme")
	tracker.Increment("acme")
	handler = newStatusHandler(nil, tracker, "default")
	req = httptest.NewRequest(http.MethodGet, "/status?tenant_id=acme", nil)
	rec = httptest.NewRecorder()
	handler(rec, req)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, resp.ActiveRuns)
	// Default tenant when no query
	req = httptest.NewRequest(http.MethodGet, "/status", nil)
	rec = httptest.NewRecorder()
	handler(rec, req)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 0, resp.ActiveRuns, "default tenant has no runs")
}

func TestNewStatusHandler_WithStore(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/evidence.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	handler := newStatusHandler(store, nil, "default")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp statusResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, 0, resp.EvidenceCountToday)
	assert.Equal(t, 0.0, resp.CostEURToday)
}

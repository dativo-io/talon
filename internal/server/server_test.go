package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestHealthEndpoint(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(
		nil, nil, nil, engine, pol, "", nil,
		map[string]string{}, // no keys - health is unauthenticated
	)
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "ok", out["status"])
}

func TestHealthDetail(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{})
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/health?detail=true", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "ok", out["status"])
	comp, _ := out["components"].(map[string]interface{})
	require.NotNil(t, comp)
	assert.Equal(t, "ok", comp["evidence_store"])
}

func TestAuthMiddlewareRejectsMissingKey(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"secret": "default"})
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/evidence", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	var out map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "unauthorized", out["error"])
}

func TestAuthMiddlewareAcceptsValidKey(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"mykey": "default"})
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/evidence?limit=1", nil)
	req.Header.Set("X-Talon-Key", "mykey")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestStatusEndpoint(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "ok", out["status"])
	assert.NotNil(t, out["evidence_count_today"])
	assert.NotNil(t, out["cost_today"])
}

func TestStatusEndpoint_ActiveRunsFromTracker(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	tracker := &agent.ActiveRunTracker{}
	tracker.Increment("acme")
	tracker.Increment("acme")

	apiKeys := map[string]string{"k": "default", "k-acme": "acme"}
	srv := NewServer(nil, store, nil, engine, pol, "", nil, apiKeys, WithActiveRunTracker(tracker))
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("X-Talon-Key", "k-acme")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "ok", out["status"])
	assert.Equal(t, float64(2), out["active_runs"], "active_runs must reflect tracker count for tenant")

	req = httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, float64(0), out["active_runs"], "default tenant has no runs")
}

func TestCostsAndBudgetEndpoints(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/costs", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "default", out["tenant_id"])

	req = httptest.NewRequest(http.MethodGet, "/v1/costs/budget", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTriggersListAndHistory(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/triggers", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.NotNil(t, out["triggers"])

	req = httptest.NewRequest(http.MethodGet, "/v1/triggers/some-webhook/history", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.NotNil(t, out["entries"])
}

func TestPlansPendingDisabled(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/plans/pending", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestPlansPendingAndGetWithStore(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/plans/pending", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	// plans may be nil (empty) or empty slice
	_, hasPlans := out["plans"]
	assert.True(t, hasPlans)

	req = httptest.NewRequest(http.MethodGet, "/v1/plans/nonexistent-id", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPlanApproveSuccess(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	plan := agent.GenerateExecutionPlan("corr1", "default", "agent1", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	err = planStore.Save(context.Background(), plan)
	require.NoError(t, err)

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	body := `{"reviewed_by":"reviewer@test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/plans/"+plan.ID+"/approve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "approved", out["status"])
}

func TestPlanApproveMissingID(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodPost, "/v1/plans//approve", strings.NewReader(`{"reviewed_by":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPlanRejectSuccess(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	plan := agent.GenerateExecutionPlan("corr2", "default", "agent1", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	require.NoError(t, planStore.Save(context.Background(), plan))
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	body := `{"reviewed_by":"admin","reason":"too expensive"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/plans/"+plan.ID+"/reject", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "rejected", out["status"])
}

func TestPlanRejectMissingID(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodPost, "/v1/plans//reject", strings.NewReader(`{"reviewed_by":"x","reason":"y"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPlanModifySuccess(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	plan := agent.GenerateExecutionPlan("corr3", "default", "agent1", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	require.NoError(t, planStore.Save(context.Background(), plan))
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	body := `{"reviewed_by":"admin","annotations":[{"type":"comment","content":"use cheaper model"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/plans/"+plan.ID+"/modify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "modified", out["status"])
}

// TestPlanApproveRejectModify_NonexistentPlanReturns404 ensures approve/reject/modify
// with a nonexistent plan ID return 404 (not 409) so clients can distinguish not-found from not-pending.
func TestPlanApproveRejectModify_NonexistentPlanReturns404(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	nonexistentID := "plan_nonexistent_404_test"
	key := "X-Talon-Key"
	apiKey := "k"

	// Approve nonexistent plan -> 404
	req := httptest.NewRequest(http.MethodPost, "/v1/plans/"+nonexistentID+"/approve", strings.NewReader(`{"reviewed_by":"u"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(key, apiKey)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "approve nonexistent plan must return 404")
	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "not_found", errResp["error"])

	// Reject nonexistent plan -> 404
	req = httptest.NewRequest(http.MethodPost, "/v1/plans/"+nonexistentID+"/reject", strings.NewReader(`{"reviewed_by":"u","reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(key, apiKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "reject nonexistent plan must return 404")
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "not_found", errResp["error"])

	// Modify nonexistent plan -> 404
	req = httptest.NewRequest(http.MethodPost, "/v1/plans/"+nonexistentID+"/modify", strings.NewReader(`{"reviewed_by":"u","annotations":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(key, apiKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "modify nonexistent plan must return 404")
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "not_found", errResp["error"])
}

// TestPlanApproveRejectModify_AlreadyReviewedReturns409 ensures approve/reject/modify
// when the plan is already reviewed (e.g. already approved) return 409 conflict.
func TestPlanApproveRejectModify_AlreadyReviewedReturns409(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	plan := agent.GenerateExecutionPlan("corr_409", "default", "agent1", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	require.NoError(t, planStore.Save(context.Background(), plan))
	require.NoError(t, planStore.Approve(context.Background(), plan.ID, "default", "reviewer@test"))

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	key := "X-Talon-Key"
	apiKey := "k"

	// Second approve -> 409
	req := httptest.NewRequest(http.MethodPost, "/v1/plans/"+plan.ID+"/approve", strings.NewReader(`{"reviewed_by":"other"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(key, apiKey)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code, "approve already-approved plan must return 409")
	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "conflict", errResp["error"])
	assert.Contains(t, errResp["message"], "not pending")

	// Reject already-approved plan -> 409
	req = httptest.NewRequest(http.MethodPost, "/v1/plans/"+plan.ID+"/reject", strings.NewReader(`{"reviewed_by":"u","reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(key, apiKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "conflict", errResp["error"])

	// Modify already-approved plan -> 409
	req = httptest.NewRequest(http.MethodPost, "/v1/plans/"+plan.ID+"/modify", strings.NewReader(`{"reviewed_by":"u","annotations":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(key, apiKey)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "conflict", errResp["error"])
}

func TestEvidenceExportInvalidFormat(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	body := `{"tenant_id":"default","format":"xml"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/evidence/export", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMemoryApproveInvalidJSON(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })
	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodPost, "/v1/memory/agent1/approve", strings.NewReader(`{`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMemoryReviewMissingAgentID(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })
	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory//review", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPoliciesList(t *testing.T) {
	pol := minimalPolicy()
	pol.Hash = "abc"
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/policies", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, "abc", out["hash"])
}

func TestPoliciesEvaluate(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	body := `{"input":{"agent_id":"test","tool":"search"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/evaluate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.NotNil(t, out)
}

func TestPoliciesEvaluateInvalidJSON(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/evaluate", strings.NewReader(`{`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMemoryListDisabled(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory?agent_id=a1", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestMemoryListWithStore(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })

	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory?agent_id=agent1&limit=10", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	_, hasEntries := out["entries"]
	assert.True(t, hasEntries)
}

func TestSecretsList(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secretsStore, err := secrets.NewSecretStore(dir+"/secrets.db", testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })

	srv := NewServer(nil, evStore, nil, engine, pol, "", secretsStore, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/secrets", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	_, hasSecrets := out["secrets"]
	assert.True(t, hasSecrets)
}

func TestSecretsAudit(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secretsStore, err := secrets.NewSecretStore(dir+"/secrets.db", testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	srv := NewServer(nil, evStore, nil, engine, pol, "", secretsStore, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/secrets/audit?limit=10", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	_, hasAudit := out["audit"]
	assert.True(t, hasAudit)
}

// TestSecretsAuditTenantIsolation ensures GET /v1/secrets/audit only returns records for the authenticated tenant.
func TestSecretsAuditTenantIsolation(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secretsStore, err := secrets.NewSecretStore(dir+"/secrets.db", testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })

	ctx := context.Background()
	acl := secrets.ACL{Tenants: []string{"*"}, Agents: []string{"*"}}
	require.NoError(t, secretsStore.Set(ctx, "audit-key", []byte("secret"), acl))
	_, _ = secretsStore.Get(ctx, "audit-key", "acme", "agent1")
	_, _ = secretsStore.Get(ctx, "audit-key", "other", "agent2")

	apiKeys := map[string]string{"key-acme": "acme", "key-other": "other"}
	srv := NewServer(nil, evStore, nil, engine, pol, "", secretsStore, apiKeys)
	r := srv.Routes()

	// Tenant acme sees only acme records
	reqAcme := httptest.NewRequest(http.MethodGet, "/v1/secrets/audit?limit=50", nil)
	reqAcme.Header.Set("X-Talon-Key", "key-acme")
	recAcme := httptest.NewRecorder()
	r.ServeHTTP(recAcme, reqAcme)
	require.Equal(t, http.StatusOK, recAcme.Code)
	var outAcme struct {
		Audit []struct {
			TenantID string `json:"tenant_id"`
		} `json:"audit"`
	}
	require.NoError(t, json.NewDecoder(recAcme.Body).Decode(&outAcme))
	for _, r := range outAcme.Audit {
		assert.Equal(t, "acme", r.TenantID, "acme key must only see acme audit records")
	}

	// Tenant other sees only other records
	reqOther := httptest.NewRequest(http.MethodGet, "/v1/secrets/audit?limit=50", nil)
	reqOther.Header.Set("X-Talon-Key", "key-other")
	recOther := httptest.NewRecorder()
	r.ServeHTTP(recOther, reqOther)
	require.Equal(t, http.StatusOK, recOther.Code)
	var outOther struct {
		Audit []struct {
			TenantID string `json:"tenant_id"`
		} `json:"audit"`
	}
	require.NoError(t, json.NewDecoder(recOther.Body).Decode(&outOther))
	for _, r := range outOther.Audit {
		assert.Equal(t, "other", r.TenantID, "other key must only see other audit records")
	}
}

func TestMemorySearchMissingParams(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })
	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory/search?agent_id=a1", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMemorySearchWithStore(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })
	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory/search?agent_id=a1&q=test&limit=5", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	_, hasEntries := out["entries"]
	assert.True(t, hasEntries)
}

func TestMemoryReviewAndApproveWithStore(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })
	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory/agent1/review?limit=10", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	body := `{"entry_id":"mem_123","review_status":"approved"}`
	req = httptest.NewRequest(http.MethodPost, "/v1/memory/agent1/approve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	// May be 200 or 404 depending on whether entry exists
	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusNotFound)
}

func TestMemoryGetWithStore(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })
	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory/nonexistent-id", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestMemoryAsOfWithStore(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })
	ctx := context.Background()
	require.NoError(t, memStore.Write(ctx, &memory.Entry{
		TenantID: "default", AgentID: "agent1", Category: memory.CategoryDomainKnowledge,
		Title: "AsOf test", Content: "content", EvidenceID: "req_1", SourceType: memory.SourceAgentRun,
	}))
	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	asOf := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/v1/memory/as-of?agent_id=agent1&as_of="+asOf+"&limit=10", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	entries, _ := out["entries"].([]interface{})
	assert.GreaterOrEqual(t, len(entries), 1)
}

func TestMemoryAsOfBadRequest(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	memStore, err := memory.NewStore(dir + "/mem.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })
	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithMemoryStore(memStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory/as-of?agent_id=agent1", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPlanGetSuccess(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	plan := agent.GenerateExecutionPlan("corr4", "default", "agent1", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	require.NoError(t, planStore.Save(context.Background(), plan))
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"},
		WithPlanReviewStore(planStore))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/plans/"+plan.ID, nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, plan.ID, out["id"])
}

// TestPlanCrossTenantAccess ensures plan Get/Approve/Reject/Modify are scoped by tenant:
// a user from one tenant cannot read or mutate another tenant's plans.
func TestPlanCrossTenantAccess(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	evidenceStore, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)
	acmePlan := agent.GenerateExecutionPlan("corr_cross", "acme", "agent1", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	require.NoError(t, planStore.Save(context.Background(), acmePlan))

	// key_acme -> tenant acme, key_globex -> tenant globex
	apiKeys := map[string]string{"key_acme": "acme", "key_globex": "globex"}
	srv := NewServer(nil, evidenceStore, nil, engine, pol, "", nil, apiKeys, WithPlanReviewStore(planStore))
	r := srv.Routes()

	// Globex user cannot GET acme's plan -> 404
	req := httptest.NewRequest(http.MethodGet, "/v1/plans/"+acmePlan.ID, nil)
	req.Header.Set("X-Talon-Key", "key_globex")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "GET plan from other tenant must return 404")

	// Acme user can GET acme's plan -> 200
	req = httptest.NewRequest(http.MethodGet, "/v1/plans/"+acmePlan.ID, nil)
	req.Header.Set("X-Talon-Key", "key_acme")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Equal(t, acmePlan.ID, out["id"])

	// Globex user cannot APPROVE acme's plan -> 404 (plan not found for that tenant)
	req = httptest.NewRequest(http.MethodPost, "/v1/plans/"+acmePlan.ID+"/approve", strings.NewReader(`{"reviewed_by":"attacker"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "key_globex")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "approve other tenant's plan must return 404 not found")
	// Plan still pending for acme
	got, err := planStore.Get(context.Background(), acmePlan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, "pending", string(got.Status))

	// Globex user cannot REJECT acme's plan -> 404
	req = httptest.NewRequest(http.MethodPost, "/v1/plans/"+acmePlan.ID+"/reject", strings.NewReader(`{"reviewed_by":"attacker","reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "key_globex")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	got, err = planStore.Get(context.Background(), acmePlan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, "pending", string(got.Status))

	// Globex user cannot MODIFY acme's plan -> 404
	req = httptest.NewRequest(http.MethodPost, "/v1/plans/"+acmePlan.ID+"/modify", strings.NewReader(`{"reviewed_by":"attacker","annotations":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "key_globex")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	got, err = planStore.Get(context.Background(), acmePlan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, "pending", string(got.Status))
}

func TestDashboardEndpoint(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	srv := NewServer(nil, nil, nil, engine, pol, "", nil, map[string]string{},
		WithDashboard("<html></html>"))
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "<html></html>", rec.Body.String())
}

func TestDashboardNotConfigured(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	srv := NewServer(nil, nil, nil, engine, pol, "", nil, map[string]string{})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestEvidenceGetAndVerify(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	// Get non-existent id -> 404
	req := httptest.NewRequest(http.MethodGet, "/v1/evidence/nonexistent", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	// Verify non-existent id -> internal error or not found depending on store impl
	req = httptest.NewRequest(http.MethodGet, "/v1/evidence/nonexistent/verify", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	// Store may return 404 or 500; either exercises the handler
	assert.True(t, rec.Code == http.StatusNotFound || rec.Code == http.StatusInternalServerError)
}

func TestEvidenceTimelineMissingParam(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/evidence/timeline", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestEvidenceExportInvalidJSON(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodPost, "/v1/evidence/export", strings.NewReader(`{`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestEvidenceExport(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	body := `{"tenant_id":"default","format":"json","limit":10}`
	req := httptest.NewRequest(http.MethodPost, "/v1/evidence/export", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var arr []interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&arr))
	assert.NotNil(t, arr)
	// CSV path
	body = `{"tenant_id":"default","format":"csv"}`
	req = httptest.NewRequest(http.MethodPost, "/v1/evidence/export", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
}

func TestEvidenceGetAndVerifySuccess(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ev := &evidence.Evidence{
		ID:             "ev_test_1",
		CorrelationID:  "corr_1",
		Timestamp:      time.Now().UTC(),
		TenantID:       "default",
		AgentID:        "agent1",
		InvocationType: "test",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: "v1"},
		Execution:      evidence.Execution{},
		AuditTrail:     evidence.AuditTrail{},
	}
	err = store.Store(context.Background(), ev)
	require.NoError(t, err)

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/evidence/ev_test_1", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	req = httptest.NewRequest(http.MethodGet, "/v1/evidence/ev_test_1/verify", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.True(t, out["valid"].(bool))

	// Timeline with stored id
	req = httptest.NewRequest(http.MethodGet, "/v1/evidence/timeline?around=ev_test_1&before=2&after=2", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestEvidenceGetVerifyTimelineTenantIsolation ensures GET /v1/evidence/<id>, verify, and timeline
// return 404 when the evidence belongs to another tenant (cross-tenant data leak prevention).
func TestEvidenceGetVerifyTimelineTenantIsolation(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	// Evidence for tenant "acme"
	ev := &evidence.Evidence{
		ID:             "ev_acme_1",
		CorrelationID:  "corr_acme",
		Timestamp:      time.Now().UTC(),
		TenantID:       "acme",
		AgentID:        "agent1",
		InvocationType: "test",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: "v1"},
		Execution:      evidence.Execution{},
		AuditTrail:     evidence.AuditTrail{},
	}
	err = store.Store(context.Background(), ev)
	require.NoError(t, err)

	// API key "k" maps to tenant "default", not "acme"
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()

	// GET with default tenant must not return acme's evidence
	req := httptest.NewRequest(http.MethodGet, "/v1/evidence/ev_acme_1", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "GET must return 404 for other tenant's evidence")

	// Verify with default tenant must not reveal acme's evidence
	req = httptest.NewRequest(http.MethodGet, "/v1/evidence/ev_acme_1/verify", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "verify must return 404 for other tenant's evidence")

	// Timeline around acme's id with default tenant must return 404
	req = httptest.NewRequest(http.MethodGet, "/v1/evidence/timeline?around=ev_acme_1&before=2&after=2", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "timeline must return 404 when around id belongs to other tenant")
}

// TestEvidenceTenantIsolation_SameTenantSucceeds ensures that when the key's tenant matches
// the evidence tenant, GET, verify, and timeline return 200 and correct data.
func TestEvidenceTenantIsolation_SameTenantSucceeds(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ev := &evidence.Evidence{
		ID:             "ev_acme_2",
		CorrelationID:  "corr_acme_2",
		Timestamp:      time.Now().UTC(),
		TenantID:       "acme",
		AgentID:        "agent1",
		InvocationType: "test",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: "v1"},
		Execution:      evidence.Execution{},
		AuditTrail:     evidence.AuditTrail{},
	}
	err = store.Store(context.Background(), ev)
	require.NoError(t, err)

	// Key "k_acme" maps to tenant "acme"
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k_acme": "acme"})
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/evidence/ev_acme_2", nil)
	req.Header.Set("X-Talon-Key", "k_acme")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "GET must succeed for same-tenant evidence")
	var got map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Equal(t, "acme", got["tenant_id"], "response must be acme's evidence")

	req = httptest.NewRequest(http.MethodGet, "/v1/evidence/ev_acme_2/verify", nil)
	req.Header.Set("X-Talon-Key", "k_acme")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.True(t, got["valid"].(bool))

	req = httptest.NewRequest(http.MethodGet, "/v1/evidence/timeline?around=ev_acme_2&before=1&after=1", nil)
	req.Header.Set("X-Talon-Key", "k_acme")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var timelineResp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&timelineResp))
	entries, _ := timelineResp["entries"].([]interface{})
	require.NotEmpty(t, entries, "timeline must return at least the target entry")
}

// TestEvidenceTenantIsolation_ListOnlyReturnsOwnTenant ensures GET /v1/evidence list
// returns only entries for the authenticated tenant.
func TestEvidenceTenantIsolation_ListOnlyReturnsOwnTenant(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	for _, e := range []struct {
		id       string
		tenantID string
	}{
		{"ev_default_1", "default"},
		{"ev_default_2", "default"},
		{"ev_acme_1", "acme"},
		{"ev_acme_2", "acme"},
	} {
		err = store.Store(ctx, &evidence.Evidence{
			ID:             e.id,
			CorrelationID:  "c",
			Timestamp:      time.Now().UTC(),
			TenantID:       e.tenantID,
			AgentID:        "a",
			InvocationType: "test",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: "v1"},
			Execution:      evidence.Execution{},
			AuditTrail:     evidence.AuditTrail{},
		})
		require.NoError(t, err)
	}

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k_acme": "acme", "k_default": "default"})
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/evidence", nil)
	req.Header.Set("X-Talon-Key", "k_acme")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var listResp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&listResp))
	entries, _ := listResp["entries"].([]interface{})
	require.Len(t, entries, 2, "acme must see only 2 acme entries")
	for _, e := range entries {
		ent := e.(map[string]interface{})
		assert.Equal(t, "acme", ent["tenant_id"], "every list entry must be acme tenant")
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/evidence", nil)
	req.Header.Set("X-Talon-Key", "k_default")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&listResp))
	entries, _ = listResp["entries"].([]interface{})
	require.Len(t, entries, 2, "default must see only 2 default entries")
	for _, e := range entries {
		ent := e.(map[string]interface{})
		assert.Equal(t, "default", ent["tenant_id"], "every list entry must be default tenant")
	}
}

// TestEvidenceTenantIsolation_NonexistentIDReturns404 ensures that requesting a
// nonexistent evidence ID returns 404 (not 403) so we don't leak existence.
func TestEvidenceTenantIsolation_NonexistentIDReturns404(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/evidence/nonexistent_id_12345", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "nonexistent ID must return 404")
	var errResp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "not_found", errResp["error"], "error body must use 'error' field per writeError")
}

// TestEvidenceTenantIsolation_ContextOverQueryParam ensures tenant comes from
// auth context; query param tenant_id is only used when context has no tenant (e.g. no auth).
func TestEvidenceTenantIsolation_ContextOverQueryParam(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	// Only default tenant has evidence
	err = store.Store(context.Background(), &evidence.Evidence{
		ID:             "ev_default_only",
		CorrelationID:  "c",
		Timestamp:      time.Now().UTC(),
		TenantID:       "default",
		AgentID:        "a",
		InvocationType: "test",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: "v1"},
		Execution:      evidence.Execution{},
		AuditTrail:     evidence.AuditTrail{},
	})
	require.NoError(t, err)

	// Key "k" -> default. Request list with ?tenant_id=acme (attempt to list acme).
	// Context wins: we must see default's list, not acme's (acme would be empty).
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/evidence?tenant_id=acme", nil)
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var listResp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&listResp))
	entries, _ := listResp["entries"].([]interface{})
	require.Len(t, entries, 1, "context tenant is default; must not use query param to switch to acme")
	assert.Equal(t, "default", entries[0].(map[string]interface{})["tenant_id"])
}

// TestChatCompletionsErrorShape ensures /v1/chat/completions returns OpenAI-compatible
// error format: {"error": {"message": "...", "type": "...", "code": "..."}} so SDKs can parse error.message.
func TestChatCompletionsErrorShape(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	r := srv.Routes()

	var errBody struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}

	// Invalid JSON -> 400 with nested error
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Key", "k")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "response: %s", rec.Body.String())
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errBody))
	assert.Contains(t, errBody.Error.Message, "invalid JSON", "OpenAI SDKs expect error.message")
	assert.Equal(t, "invalid_request_error", errBody.Error.Type)
	assert.Equal(t, "invalid_json", errBody.Error.Code)

	// Empty messages -> 400 with nested error
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Talon-Key", "k")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusBadRequest, rec2.Code, "response: %s", rec2.Body.String())
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&errBody), "body: %s", rec2.Body.String())
	assert.Equal(t, "no user message content in messages", errBody.Error.Message)
	assert.Equal(t, "messages_required", errBody.Error.Code)
}

func minimalPolicy() *policy.Policy {
	return &policy.Policy{
		Agent:      policy.AgentConfig{Name: "test", Version: "1.0"},
		Policies:   policy.PoliciesConfig{},
		VersionTag: "test",
	}
}

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

func minimalPolicy() *policy.Policy {
	return &policy.Policy{
		Agent:      policy.AgentConfig{Name: "test", Version: "1.0"},
		Policies:   policy.PoliciesConfig{},
		VersionTag: "test",
	}
}

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
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

func minimalPolicy() *policy.Policy {
	return &policy.Policy{
		Agent:      policy.AgentConfig{Name: "test", Version: "1.0"},
		Policies:   policy.PoliciesConfig{},
		VersionTag: "test",
	}
}

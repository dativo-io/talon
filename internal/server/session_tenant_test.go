package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	talonsession "github.com/dativo-io/talon/internal/session"
)

// Session endpoint tenant-ownership checks (#215, epic #192 PR-G): a
// tenant-authenticated caller can never read, list, or complete another
// tenant's sessions; missing and other-tenant sessions are indistinguishable.

func newSessionTenantServer(t *testing.T) (*talonsession.Store, http.Handler) {
	t.Helper()
	ss, err := talonsession.NewStore(filepath.Join(t.TempDir(), "sessions.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	srv := NewServer(nil, nil, nil, nil, minimalPolicy(), "", nil, "test-admin-key",
		map[string]string{"key-a": "tenant-a", "key-b": "tenant-b"},
		WithSessionStore(ss))
	return ss, srv.Routes()
}

func sessReq(t *testing.T, h http.Handler, method, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSessionComplete_CrossTenant404(t *testing.T) {
	ss, h := newSessionTenantServer(t)
	sess, err := ss.Create(context.Background(), "tenant-a", "agent", "", 0)
	require.NoError(t, err)

	// Tenant B cannot complete tenant A's session.
	rec := sessReq(t, h, http.MethodPost, "/v1/sessions/"+sess.ID+"/complete", "key-b")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	got, err := ss.Get(context.Background(), sess.ID, "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, talonsession.StatusActive, got.Status, "cross-tenant complete must not mutate")

	// The owner can.
	rec = sessReq(t, h, http.MethodPost, "/v1/sessions/"+sess.ID+"/complete", "key-a")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSessionGet_CrossTenant404(t *testing.T) {
	ss, h := newSessionTenantServer(t)
	sess, err := ss.Create(context.Background(), "tenant-a", "agent", "", 0)
	require.NoError(t, err)

	rec := sessReq(t, h, http.MethodGet, "/v1/sessions/"+sess.ID, "key-b")
	assert.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant get must be indistinguishable from missing")

	rec = sessReq(t, h, http.MethodGet, "/v1/sessions/"+sess.ID, "key-a")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSessionList_TenantScopedQueryParamCannotWiden(t *testing.T) {
	ss, h := newSessionTenantServer(t)
	_, err := ss.Create(context.Background(), "tenant-a", "agent", "", 0)
	require.NoError(t, err)
	_, err = ss.Create(context.Background(), "tenant-b", "agent", "", 0)
	require.NoError(t, err)

	// Tenant B asks for tenant A's sessions: gets its own instead.
	rec := sessReq(t, h, http.MethodGet, "/v1/sessions?tenant_id=tenant-a", "key-b")
	require.Equal(t, http.StatusOK, rec.Code)
	var got []talonsession.Session
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	require.Len(t, got, 1)
	assert.Equal(t, "tenant-b", got[0].TenantID, "query param must not widen tenant scope")
}

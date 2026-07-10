package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Auth openness is governed by the admin-key dev rule ONLY (#266, #280): an
// empty agent registry must never by itself open tenant-scoped APIs when an
// admin key is configured.
func TestTenantKeyMiddleware_AdminKeyDevRule(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	do := func(mw func(http.Handler) http.Handler, bearer string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/agents/run", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		mw(next).ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("empty registry + configured admin key: tenant APIs stay closed", func(t *testing.T) {
		mw := TenantKeyMiddleware(map[string]string{}, "admin-secret")
		assert.Equal(t, http.StatusUnauthorized, do(mw, ""), "no key must not pass")
		assert.Equal(t, http.StatusUnauthorized, do(mw, "anything"), "unknown key must not pass")
	})

	t.Run("no auth configured at all: dev-mode open", func(t *testing.T) {
		mw := TenantKeyMiddleware(map[string]string{}, "")
		assert.Equal(t, http.StatusOK, do(mw, ""))
	})

	t.Run("agent key resolves and scopes", func(t *testing.T) {
		var gotTenant string
		capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotTenant = TenantIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		mw := TenantKeyMiddleware(map[string]string{"tk-agent-1": "acme"}, "admin-secret")
		req := httptest.NewRequest(http.MethodPost, "/v1/agents/run", nil)
		req.Header.Set("Authorization", "Bearer tk-agent-1")
		rec := httptest.NewRecorder()
		mw(capture).ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "acme", gotTenant, "tenant derived key → agent → tenant_id")

		assert.Equal(t, http.StatusUnauthorized, do(mw, "tk-wrong"))
	})
}

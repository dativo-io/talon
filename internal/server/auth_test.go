package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/requestctx"
)

// TestResolveRunAttribution proves an agent key may only act as its own agent
// (#266 review round 4): a body/header agent name or tenant that differs from
// the authenticated identity is rejected, and neither ever defaults to
// "default"; admin/dev requests keep the client-asserted values.
func TestResolveRunAttribution(t *testing.T) {
	agentCtx := requestctx.SetAgentIdentity(context.Background(),
		requestctx.AgentIdentity{AgentID: "support-bot", TenantID: "acme"})

	t.Run("agent key: identity is authoritative", func(t *testing.T) {
		ten, ag, err := resolveRunAttribution(agentCtx, "", "")
		require.NoError(t, err)
		assert.Equal(t, "acme", ten)
		assert.Equal(t, "support-bot", ag)
	})
	t.Run("agent key: matching assertions accepted", func(t *testing.T) {
		ten, ag, err := resolveRunAttribution(agentCtx, "acme", "support-bot")
		require.NoError(t, err)
		assert.Equal(t, "acme", ten)
		assert.Equal(t, "support-bot", ag)
	})
	t.Run("agent key: spoofed agent rejected", func(t *testing.T) {
		_, _, err := resolveRunAttribution(agentCtx, "", "finance-bot")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "may only act as its own agent")
	})
	t.Run("agent key: spoofed tenant rejected", func(t *testing.T) {
		_, _, err := resolveRunAttribution(agentCtx, "globex", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the authenticated agent's tenant")
	})
	t.Run("admin/dev: client-asserted, defaults apply", func(t *testing.T) {
		ten, ag, err := resolveRunAttribution(context.Background(), "", "")
		require.NoError(t, err)
		assert.Equal(t, "default", ten)
		assert.Equal(t, "default", ag)

		ten, ag, err = resolveRunAttribution(context.Background(), "globex", "any-agent")
		require.NoError(t, err)
		assert.Equal(t, "globex", ten)
		assert.Equal(t, "any-agent", ag)
	})
}

// Auth openness is governed by the admin-key dev rule ONLY (#266, #280): an
// empty agent registry must never by itself open tenant-scoped APIs when an
// admin key is configured.
func TestTenantKeyMiddleware_AdminKeyDevRule(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	do := func(mw func(http.Handler) http.Handler, bearer string) int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/agents/run", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		mw(next).ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("empty registry + configured admin key: tenant APIs stay closed", func(t *testing.T) {
		mw := TenantKeyMiddleware(map[string]requestctx.AgentIdentity{}, "admin-secret")
		assert.Equal(t, http.StatusUnauthorized, do(mw, ""), "no key must not pass")
		assert.Equal(t, http.StatusUnauthorized, do(mw, "anything"), "unknown key must not pass")
	})

	t.Run("no auth configured at all: dev-mode open", func(t *testing.T) {
		mw := TenantKeyMiddleware(map[string]requestctx.AgentIdentity{}, "")
		assert.Equal(t, http.StatusOK, do(mw, ""))
	})

	t.Run("agent key resolves and scopes", func(t *testing.T) {
		var gotTenant string
		capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotTenant = TenantIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		mw := TenantKeyMiddleware(map[string]requestctx.AgentIdentity{"tk-agent-1": {AgentID: "agent-a", TenantID: "acme"}}, "admin-secret")
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/agents/run", nil)
		req.Header.Set("Authorization", "Bearer tk-agent-1")
		rec := httptest.NewRecorder()
		mw(capture).ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "acme", gotTenant, "tenant derived key → agent → tenant_id")

		assert.Equal(t, http.StatusUnauthorized, do(mw, "tk-wrong"))
	})
}

// Package server provides the HTTP API server, middleware, and handlers for Talon.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/tenant"
)

const (
	adminSessionCookieName   = "talon_admin_session"
	adminSessionCookieMaxAge = 8 * 60 * 60 // 8 hours
)

// SetTenantID stores tenant_id in the request context.
func SetTenantID(ctx context.Context, tenantID string) context.Context {
	return requestctx.SetTenantID(ctx, tenantID)
}

// TenantIDFromContext returns the tenant_id from context, or "" if not set.
func TenantIDFromContext(ctx context.Context) string {
	return requestctx.TenantID(ctx)
}

// IsAdminFromContext returns true when the request is authenticated as admin.
func IsAdminFromContext(ctx context.Context) bool {
	return requestctx.IsAdmin(ctx)
}

// AgentIdentityFromContext returns the resolved agent identity and true when
// the request authenticated with an agent key (#266).
func AgentIdentityFromContext(ctx context.Context) (requestctx.AgentIdentity, bool) {
	return requestctx.AgentIdentityFrom(ctx)
}

// resolveRunAttribution decides the (tenant, agent) a native run/chat records
// under (#266 review round 4). When the request authenticated with an agent
// key, that resolved identity is AUTHORITATIVE: a body/header agent name or
// tenant that differs is rejected (spoofing), and neither ever defaults to
// "default". Admin and dev-mode requests keep the client-asserted values,
// defaulting to "default", so operator tooling can still attribute a run to
// any agent.
func resolveRunAttribution(ctx context.Context, requestedTenant, requestedAgent string) (tenant, agent string, err error) {
	if id, ok := requestctx.AgentIdentityFrom(ctx); ok {
		if requestedAgent != "" && requestedAgent != id.AgentID {
			return "", "", fmt.Errorf("agent %q does not match the authenticated agent key (bound to %q) — an agent key may only act as its own agent", requestedAgent, id.AgentID)
		}
		if requestedTenant != "" && requestedTenant != id.TenantID {
			return "", "", fmt.Errorf("tenant %q does not match the authenticated agent's tenant %q", requestedTenant, id.TenantID)
		}
		return id.TenantID, id.AgentID, nil
	}
	tenant = requestctx.TenantID(ctx)
	if tenant == "" {
		tenant = requestedTenant
	}
	if tenant == "" {
		tenant = "default"
	}
	agent = requestedAgent
	if agent == "" {
		agent = "default"
	}
	return tenant, agent, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// agentReadScope returns the agent_id a tenant-API READ must be confined to
// (#266 review round 4 — agent-scoped reads). An agent key may read only its
// OWN agent's records: the returned filter is the authenticated agent name,
// overriding any client-supplied agent_id. Admin and dev-mode requests use
// the caller-supplied filter (tenant-wide operator visibility). The bool is
// true when the request is agent-scoped.
func agentReadScope(ctx context.Context, requestedAgentID string) (string, bool) {
	if id, ok := requestctx.AgentIdentityFrom(ctx); ok {
		return id.AgentID, true
	}
	return requestedAgentID, false
}

// recordVisibleToCaller reports whether a fetched-by-id record may be returned
// to the caller: an agent key sees only records for its own agent (#266). The
// tenant check is applied separately by each handler.
func recordVisibleToCaller(ctx context.Context, recordAgentID string) bool {
	if id, ok := requestctx.AgentIdentityFrom(ctx); ok {
		return recordAgentID == id.AgentID
	}
	return true
}

// TenantKeyMiddleware returns a middleware that validates
// Authorization: Bearer <agent key> and sets the resolved agent identity
// (agent name, tenant, team) in context. agentKeys is the identity
// registry's key → AuthPrincipal projection. Openness is governed by the
// admin-key dev rule ONLY: an empty agent registry must never by itself open
// tenant APIs when an admin key is configured (#266, #280).
func TenantKeyMiddleware(agentKeys map[string]requestctx.AgentIdentity, adminKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dev mode: no auth configured at all.
			if adminKey == "" && len(agentKeys) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			key := bearerToken(r)
			if key == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing agent key")
				return
			}
			id, ok := lookupAgentIdentity(agentKeys, key)
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing agent key")
				return
			}
			next.ServeHTTP(w, r.WithContext(withAgentAuth(r.Context(), id)))
		})
	}
}

// withAgentAuth records both the derived tenant and the full resolved agent
// identity so native handlers can bind attribution to the authenticated
// agent, not a client-asserted name (#266 review round 4).
func withAgentAuth(ctx context.Context, id requestctx.AgentIdentity) context.Context {
	ctx = requestctx.SetTenantID(ctx, id.TenantID)
	return requestctx.SetAgentIdentity(ctx, id)
}

// AdminKeyMiddleware returns a middleware that validates X-Talon-Admin-Key
// (or Authorization: Bearer fallback) against the configured admin key.
func AdminKeyMiddleware(adminKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dev mode: no admin key configured.
			if adminKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			provided, source := adminKeyFromRequestWithSource(r)
			if !isValidAdminKeyValue(provided, adminKey) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing admin key. Provide X-Talon-Admin-Key header or ?talon_admin_key=YOUR_TALON_ADMIN_KEY")
				return
			}
			if source != "cookie" {
				setAdminSessionCookie(w, r, provided)
			}
			r = r.WithContext(requestctx.SetIsAdmin(r.Context(), true))
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdminKeyMiddleware is AdminKeyMiddleware WITHOUT the dev-open rule:
// an absent admin key denies every request instead of enabling dev mode. Used
// for the native execution routes when a gateway is served — those routes run
// outside gateway.organization_policy and the resolved effective policy, so
// leaving them unauthenticated just because the operator did not set
// TALON_ADMIN_KEY would be a fail-open governance bypass (#266 review round 6:
// gateway mode + no admin key must deny, not open).
func RequireAdminKeyMiddleware(adminKey string) func(http.Handler) http.Handler {
	inner := AdminKeyMiddleware(adminKey)
	return func(next http.Handler) http.Handler {
		guarded := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if adminKey == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized",
					"Native execution routes require TALON_ADMIN_KEY when a gateway is served (agent traffic must use /v1/proxy). Set TALON_ADMIN_KEY to enable them.")
				return
			}
			guarded.ServeHTTP(w, r)
		})
	}
}

// TenantOrAdminMiddleware allows either an admin key or an agent key.
// Admin auth checks X-Talon-Admin-Key first, then Bearer fallback.
// Agent auth checks Authorization: Bearer <agent key> (#266).
func TenantOrAdminMiddleware(agentKeys map[string]requestctx.AgentIdentity, adminKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dev mode: no auth configured.
			if adminKey == "" && len(agentKeys) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			if provided, source := adminKeyFromRequestWithSource(r); isValidAdminKeyValue(provided, adminKey) {
				if source != "cookie" {
					setAdminSessionCookie(w, r, provided)
				}
				r = r.WithContext(requestctx.SetIsAdmin(r.Context(), true))
				next.ServeHTTP(w, r)
				return
			}
			if id, ok := lookupAgentIdentity(agentKeys, bearerToken(r)); ok {
				next.ServeHTTP(w, r.WithContext(withAgentAuth(r.Context(), id)))
				return
			}
			writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing agent/admin key. Use Authorization: Bearer <agent key> or ?talon_admin_key=YOUR_TALON_ADMIN_KEY for admin GET endpoints")
		})
	}
}

// RateLimitMiddleware returns a middleware that calls tenantManager.ValidateRequest(tenantID)
// and returns 429 with Retry-After and X-RateLimit-* headers when exceeded.
func RateLimitMiddleware(tm *tenant.Manager) func(http.Handler) http.Handler {
	if tm == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := TenantIDFromContext(r.Context())
			if tenantID == "" {
				next.ServeHTTP(w, r)
				return
			}
			err := tm.ValidateRequest(r.Context(), tenantID)
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}
			switch err {
			case tenant.ErrRateLimitExceeded:
				w.Header().Set("Retry-After", "1")
				w.Header().Set("X-RateLimit-Limit", "0")
				w.Header().Set("X-RateLimit-Remaining", "0")
				writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", err.Error())
			case tenant.ErrTenantNotFound:
				writeError(w, http.StatusForbidden, "forbidden", err.Error())
			case tenant.ErrDailyBudgetExceeded, tenant.ErrMonthlyBudgetExceeded:
				w.Header().Set("Retry-After", "3600") // suggest retry next hour
				writeError(w, http.StatusTooManyRequests, "budget_exceeded", err.Error())
			default:
				writeError(w, http.StatusInternalServerError, "internal", err.Error())
			}
		})
	}
}

// CORSMiddleware returns a middleware that sets CORS headers. allowedOrigins can be ["*"] for any.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowAll := false
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
			break
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" {
				for _, o := range allowedOrigins {
					if o == origin {
						w.Header().Set("Access-Control-Allow-Origin", origin)
						break
					}
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Talon-Admin-Key, X-Talon-Tenant, X-Talon-Agent")
			w.Header().Set("Access-Control-Max-Age", "300")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeError writes a JSON error response. Defined here so AuthMiddleware can use it;
// handlers.go will use the same helper.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

func bearerToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return ""
}

// lookupAgentIdentity resolves a presented key to its authenticated identity.
// Both sides are SHA-256 digested to a fixed length before the constant-time
// compare, so timing does not vary with key length (#266 review round 4).
// Returns (zero, false) for unknown keys.
func lookupAgentIdentity(agentKeys map[string]requestctx.AgentIdentity, key string) (requestctx.AgentIdentity, bool) {
	if key == "" {
		return requestctx.AgentIdentity{}, false
	}
	presentedDigest := sha256.Sum256([]byte(key))
	var match requestctx.AgentIdentity
	found := false
	for configuredKey, id := range agentKeys {
		cfgDigest := sha256.Sum256([]byte(configuredKey))
		if subtle.ConstantTimeCompare(cfgDigest[:], presentedDigest[:]) == 1 {
			match = id
			found = true
		}
	}
	return match, found
}

func isValidAdminKeyValue(provided, adminKey string) bool {
	return provided != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(adminKey)) == 1
}

// adminKeyFromRequestWithSource returns admin key and source from X-Talon-Admin-Key,
// Authorization: Bearer, GET query (`talon_admin_key` or legacy `token`), or
// an HTTP-only session cookie.
func adminKeyFromRequestWithSource(r *http.Request) (key string, source string) {
	if k := r.Header.Get("X-Talon-Admin-Key"); k != "" {
		return k, "header"
	}
	if k := bearerToken(r); k != "" {
		return k, "bearer"
	}
	if r.Method == http.MethodGet && r.URL != nil {
		if k := r.URL.Query().Get("talon_admin_key"); k != "" {
			return k, "query"
		}
		if k := r.URL.Query().Get("token"); k != "" {
			return k, "query"
		}
	}
	if c, err := r.Cookie(adminSessionCookieName); err == nil && c != nil && c.Value != "" {
		return c.Value, "cookie"
	}
	return "", ""
}

func setAdminSessionCookie(w http.ResponseWriter, r *http.Request, key string) {
	if key == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   adminSessionCookieMaxAge,
	})
}

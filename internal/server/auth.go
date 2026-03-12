// Package server provides the HTTP API server, middleware, and handlers for Talon.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/tenant"
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

// TenantKeyMiddleware returns a middleware that validates Authorization: Bearer <tenant_key>
// and sets tenant_id in context. tenantKeys maps key -> tenant_id.
func TenantKeyMiddleware(tenantKeys map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dev mode: no tenant keys configured.
			if len(tenantKeys) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			key := bearerToken(r)
			if key == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing tenant key")
				return
			}
			tenantID := lookupTenantID(tenantKeys, key)
			if tenantID == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing tenant key")
				return
			}
			r = r.WithContext(requestctx.SetTenantID(r.Context(), tenantID))
			next.ServeHTTP(w, r)
		})
	}
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
			if !isValidAdminKey(r, adminKey) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing admin key")
				return
			}
			r = r.WithContext(requestctx.SetIsAdmin(r.Context(), true))
			next.ServeHTTP(w, r)
		})
	}
}

// TenantOrAdminMiddleware allows either an admin key or tenant key.
// Admin auth checks X-Talon-Admin-Key first, then Bearer fallback.
// Tenant auth checks Authorization: Bearer <tenant_key>.
func TenantOrAdminMiddleware(tenantKeys map[string]string, adminKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dev mode: no auth configured.
			if adminKey == "" && len(tenantKeys) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			if isValidAdminKey(r, adminKey) {
				r = r.WithContext(requestctx.SetIsAdmin(r.Context(), true))
				next.ServeHTTP(w, r)
				return
			}
			tenantToken := bearerToken(r)
			tenantID := lookupTenantID(tenantKeys, tenantToken)
			if tenantID != "" {
				r = r.WithContext(requestctx.SetTenantID(r.Context(), tenantID))
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing tenant/admin key")
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
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func lookupTenantID(tenantKeys map[string]string, key string) string {
	if key == "" {
		return ""
	}
	for configuredKey, tenantID := range tenantKeys {
		if subtle.ConstantTimeCompare([]byte(configuredKey), []byte(key)) == 1 {
			return tenantID
		}
	}
	return ""
}

func isValidAdminKey(r *http.Request, adminKey string) bool {
	if adminKey == "" {
		return false
	}
	headerKey := r.Header.Get("X-Talon-Admin-Key")
	if headerKey != "" && subtle.ConstantTimeCompare([]byte(headerKey), []byte(adminKey)) == 1 {
		return true
	}
	token := bearerToken(r)
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(adminKey)) == 1
}

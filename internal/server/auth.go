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

// AuthMiddleware returns a middleware that validates X-Talon-Key or Authorization: Bearer <key>
// and sets tenant_id in context. apiKeys maps key -> tenant_id.
func AuthMiddleware(apiKeys map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-Talon-Key")
			if key == "" {
				if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
					key = strings.TrimPrefix(auth, "Bearer ")
				}
			}
			if key == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing API key")
				return
			}
			var tenantID string
			for k, t := range apiKeys {
				if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
					tenantID = t
					break
				}
			}
			if tenantID == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing API key")
				return
			}
			r = r.WithContext(requestctx.SetTenantID(r.Context(), tenantID))
			next.ServeHTTP(w, r)
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
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":   "rate_limit_exceeded",
					"message": err.Error(),
				})
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
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Talon-Key, X-Talon-Tenant, X-Talon-Agent")
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

// Package requestctx provides request-scoped values (e.g. tenant_id) set by middleware.
package requestctx

import "context"

type contextKey struct{}

var (
	tenantIDKey = &contextKey{}
	isAdminKey  = &contextKey{}
)

// SetTenantID stores tenant_id in the context.
func SetTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// TenantID returns the tenant_id from context, or "" if not set.
func TenantID(ctx context.Context) string {
	v, _ := ctx.Value(tenantIDKey).(string)
	return v
}

// SetIsAdmin stores whether request auth is admin-scoped.
func SetIsAdmin(ctx context.Context, isAdmin bool) context.Context {
	return context.WithValue(ctx, isAdminKey, isAdmin)
}

// IsAdmin returns true when request auth is admin-scoped.
func IsAdmin(ctx context.Context) bool {
	v, _ := ctx.Value(isAdminKey).(bool)
	return v
}

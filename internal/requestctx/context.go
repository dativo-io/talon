// Package requestctx provides request-scoped values (e.g. tenant_id) set by middleware.
package requestctx

import "context"

type contextKey struct{}

var tenantIDKey = &contextKey{}

// SetTenantID stores tenant_id in the context.
func SetTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// TenantID returns the tenant_id from context, or "" if not set.
func TenantID(ctx context.Context) string {
	v, _ := ctx.Value(tenantIDKey).(string)
	return v
}

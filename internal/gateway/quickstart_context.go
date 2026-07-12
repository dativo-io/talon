package gateway

import "context"

type quickstartIdentityCtxKey struct{}

// WithQuickstartIdentity attaches the trusted synthetic quickstart identity to
// the request context. This is the ONLY identity path that bypasses key
// resolution, and only the in-process quickstart facade can set it — it is
// impossible to reach through normal gateway authentication.
func WithQuickstartIdentity(ctx context.Context, id *ResolvedIdentity) context.Context {
	return context.WithValue(ctx, quickstartIdentityCtxKey{}, id)
}

// QuickstartIdentityFromContext returns the synthetic quickstart identity when present.
func QuickstartIdentityFromContext(ctx context.Context) *ResolvedIdentity {
	v := ctx.Value(quickstartIdentityCtxKey{})
	id, _ := v.(*ResolvedIdentity)
	return id
}

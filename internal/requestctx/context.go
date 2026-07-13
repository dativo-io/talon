// Package requestctx provides request-scoped values (e.g. tenant_id) set by middleware.
package requestctx

import "context"

// contextKey is an int-valued key type so each key has a DISTINCT value.
// (A pointer-to-empty-struct key aliases: Go may place every &struct{}{} at
// the same address, so distinct zero-size keys compare equal and clobber each
// other in context.WithValue — which silently dropped tenant_id once a third
// key was added, #266 review round 4.)
type contextKey int

const (
	tenantIDKey contextKey = iota
	isAdminKey
	agentIdentityKey
)

// AgentIdentity is the identity an agent traffic key resolves to (#266): the
// agent name, its derived tenant, and team. It is set on the request context
// by the tenant-key middleware when a request authenticates with an AGENT
// key (not the admin key), so native handlers can bind attribution to the
// authenticated identity instead of trusting a client-asserted agent name.
type AgentIdentity struct {
	AgentID  string
	TenantID string
	Team     string
	// Generation is the runtime-catalog generation the key authenticated
	// against (#267): execution fails closed when the generation changed
	// between authentication and run resolution — a key rotated or a policy
	// replaced in a newer generation can never be exercised by a request
	// authenticated under the older one.
	Generation string
}

// SetAgentIdentity stores the resolved agent identity in the context.
func SetAgentIdentity(ctx context.Context, id AgentIdentity) context.Context {
	return context.WithValue(ctx, agentIdentityKey, id)
}

// AgentIdentityFrom returns the resolved agent identity and true when the
// request authenticated with an agent key. Returns (zero, false) for admin
// or dev-mode (unauthenticated) requests.
func AgentIdentityFrom(ctx context.Context) (AgentIdentity, bool) {
	id, ok := ctx.Value(agentIdentityKey).(AgentIdentity)
	return id, ok && id.AgentID != ""
}

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

package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegistryHolder_SwapPropagatesToResolution (#289): the gateway resolves
// identity against the holder's CURRENT snapshot, so one Swap changes what
// the data plane accepts — no gateway reconstruction.
func TestRegistryHolder_SwapPropagatesToResolution(t *testing.T) {
	oldReg := testRegistry(testIdentity("support", "acme", "tk-old", nil))
	holder := NewRegistryHolder(oldReg)
	g := &Gateway{registry: holder}

	id, err := g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tk-old")
	}))
	require.NoError(t, err)
	assert.Equal(t, "support", id.Name)

	// Reload: a NEW registry replaces the old one atomically.
	holder.Swap(testRegistry(testIdentity("support", "acme", "tk-new", nil)))

	_, err = g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tk-old")
	}))
	assert.ErrorIs(t, err, ErrUnknownKey, "rotated-out key must stop resolving after the swap")

	id, err = g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tk-new")
	}))
	require.NoError(t, err)
	assert.Equal(t, "support", id.Name, "rotated-in key resolves after the swap")
}

// TestRegistryHolder_NilSafety: a nil holder and a holder over a nil registry
// both read as "no agents" and fail closed.
func TestRegistryHolder_NilSafety(t *testing.T) {
	var nilHolder *RegistryHolder
	assert.Nil(t, nilHolder.Current())
	nilHolder.Swap(testRegistry()) // must not panic

	empty := NewRegistryHolder(nil)
	assert.Equal(t, 0, empty.Current().Len())
	_, ok := empty.Current().ResolveKey("tk-anything")
	assert.False(t, ok, "nil registry resolves nothing (fail closed)")
}

// TestRegistryHolder_CacheTenantScopeFollowsSwap (#289): cache-key tenant
// canonicalization reads the CURRENT snapshot, so a reload re-scopes it.
func TestRegistryHolder_CacheTenantScopeFollowsSwap(t *testing.T) {
	holder := NewRegistryHolder(testRegistry(testIdentity("a", "acme", "k1", nil)))
	g := &Gateway{registry: holder}

	canonical := g.canonicalTenantIDForCache("acme")
	assert.Equal(t, "acme", canonical)
	assert.Equal(t, quickstartTenantID, g.canonicalTenantIDForCache(quickstartTenantID))

	holder.Swap(testRegistry(testIdentity("b", "globex", "k2", nil)))
	assert.Equal(t, "globex", g.canonicalTenantIDForCache("globex"), "new tenant known after swap")

	// MetricsTenantScope through the same holder (what serve's live scope
	// function reads) follows too.
	assert.Equal(t, "globex", holder.Current().MetricsTenantScope())
}

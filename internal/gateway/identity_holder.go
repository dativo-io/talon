package gateway

import "sync/atomic"

// RegistryHolder is the shared atomic snapshot holder for the identity
// registry (#289, the seam for #269 reload). Every consumer — gateway data
// plane, server tenant-API auth, dashboard caps lookup, metrics tenant
// scoping — reads the CURRENT registry through the holder instead of
// capturing its own copy at startup, so one reload swap propagates
// everywhere at once. Registries themselves are immutable (built once,
// deep-copied projections), which is what makes the single pointer swap
// safe: a reader holds either the old snapshot or the new one, never a
// half-updated mix.
type RegistryHolder struct {
	p atomic.Pointer[IdentityRegistry]
}

// NewRegistryHolder wraps an initial registry (nil is valid: plain serve
// with no minted key and quickstart mode run keyless — every read then
// resolves against the nil registry, which fails closed).
func NewRegistryHolder(initial *IdentityRegistry) *RegistryHolder {
	h := &RegistryHolder{}
	h.p.Store(initial)
	return h
}

// Current returns the registry snapshot to use for this operation. Callers
// must not retain it across requests — re-read on each use so a reload is
// picked up. Safe on a nil holder (returns the nil registry, which every
// IdentityRegistry method treats as empty/fail-closed).
func (h *RegistryHolder) Current() *IdentityRegistry {
	if h == nil {
		return nil
	}
	return h.p.Load()
}

// Swap atomically replaces the registry. Reload (#269) builds a complete new
// registry off to the side, then publishes it here; in-flight operations
// finish on the snapshot they started with.
func (h *RegistryHolder) Swap(next *IdentityRegistry) {
	if h == nil {
		return
	}
	h.p.Store(next)
}

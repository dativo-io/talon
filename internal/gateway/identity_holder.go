package gateway

import "sync/atomic"

// RegistrySource yields the CURRENT identity registry for one operation.
// In fleet mode (#267) the ONE implementation that matters is the view over
// the agentcatalog RuntimeHolder: catalog, compiled bundles, and registry
// publish as ONE generation behind ONE pointer, so gateway auth, server
// agent-key auth, dashboard caps, and metrics scope can never observe a
// different generation than native execution. RegistryHolder below is the
// standalone implementation for gateway-internal tests.
type RegistrySource interface {
	Current() *IdentityRegistry
}

// RegistryHolder is a standalone atomic holder for the identity registry
// (#289). Production serve publishes the registry inside the runtime
// snapshot instead (one generation, one pointer, #267); this holder remains
// for gateway-scoped tests and keyless defaults. Registries are immutable
// (built once, deep-copied projections), which is what makes a single
// pointer swap safe: a reader holds either the old snapshot or the new one,
// never a half-updated mix.
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

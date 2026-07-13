package agentcatalog

import (
	"sync/atomic"
	"time"

	"github.com/dativo-io/talon/internal/gateway"
)

// RuntimeAgent is one agent as every execution surface resolves it. PR-2 of
// Fleet Operations v1 (#267) adds the compiled per-agent runtime bundle
// (policy engine, scanner, router) so a native run can never execute agent
// A's config under agent B's engine or routing; until then it carries the
// catalog identity.
type RuntimeAgent struct {
	CatalogAgent
}

// ScanMeta is the discovery provenance a snapshot carries for the fleet
// view (#270) and the runtime-state endpoint.
type ScanMeta struct {
	// Source names what was scanned (agents_dir or the single file).
	Source string
	// Issues lists the rejected files by path from the scan that produced
	// this snapshot (empty for an activated generation — an invalid set never
	// activates; a serving snapshot may carry issues only through the
	// reloader's last-known-good state, #269).
	Issues []FleetIssue
}

// RuntimeSnapshot is ONE immutable fleet generation: the catalog, and the
// gateway identity registry built from the same agents. It publishes through
// ONE atomic pointer (RuntimeHolder) — catalog and registry can never be
// observed from different generations. A request or run captures the
// snapshot once at entry and uses it through evidence.
type RuntimeSnapshot struct {
	// Generation is the scan digest of the activated set.
	Generation string
	BuiltAt    time.Time
	// Registry is the gateway identity registry for this generation (nil in
	// keyless modes — plain serve without a minted key, quickstart).
	Registry *gateway.IdentityRegistry
	Scan     ScanMeta

	agents  map[string]*RuntimeAgent
	ordered []*RuntimeAgent
}

// NewRuntimeSnapshot builds one generation from a valid scan and the registry
// constructed from the same agents. The scan must be the one the registry was
// built from — the snapshot is the invariant that keeps them paired.
func NewRuntimeSnapshot(scan *ScanResult, registry *gateway.IdentityRegistry, builtAt time.Time) *RuntimeSnapshot {
	s := &RuntimeSnapshot{
		Generation: scan.Digest,
		BuiltAt:    builtAt,
		Registry:   registry,
		Scan:       ScanMeta{Source: scan.Source, Issues: append([]FleetIssue(nil), scan.Issues...)},
		agents:     make(map[string]*RuntimeAgent, len(scan.Agents)),
	}
	for i := range scan.Agents {
		ra := &RuntimeAgent{CatalogAgent: scan.Agents[i]}
		s.agents[ra.Name] = ra
		s.ordered = append(s.ordered, ra)
	}
	return s
}

// Get resolves one agent by name. Nil-safe (a nil snapshot resolves nothing —
// fail closed).
func (s *RuntimeSnapshot) Get(name string) (*RuntimeAgent, bool) {
	if s == nil {
		return nil, false
	}
	a, ok := s.agents[name]
	return a, ok
}

// List returns the agents in discovery order. Callers must not mutate the
// returned agents; the slice itself is a copy.
func (s *RuntimeSnapshot) List() []*RuntimeAgent {
	if s == nil {
		return nil
	}
	return append([]*RuntimeAgent(nil), s.ordered...)
}

// Len reports the number of agents in this generation. Nil-safe.
func (s *RuntimeSnapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.ordered)
}

// RuntimeHolder is the ONE atomic publication point for the current fleet
// generation (mirrors gateway.RegistryHolder, which becomes a view over this
// snapshot's Registry). Reload (#269) builds a complete new snapshot off to
// the side and publishes it here with one pointer store; in-flight work
// finishes on the snapshot it captured at entry.
type RuntimeHolder struct {
	p atomic.Pointer[RuntimeSnapshot]
}

// NewRuntimeHolder wraps an initial snapshot (nil is valid: quickstart and
// keyless plain serve run without a catalog; every read then resolves against
// the nil snapshot, which fails closed).
func NewRuntimeHolder(initial *RuntimeSnapshot) *RuntimeHolder {
	h := &RuntimeHolder{}
	h.p.Store(initial)
	return h
}

// Current returns the generation to use for this operation. Callers must not
// retain it across requests — re-read on each use so a reload is picked up.
// Safe on a nil holder.
func (h *RuntimeHolder) Current() *RuntimeSnapshot {
	if h == nil {
		return nil
	}
	return h.p.Load()
}

// Swap atomically replaces the generation. Safe on a nil holder (no-op).
func (h *RuntimeHolder) Swap(next *RuntimeSnapshot) {
	if h == nil {
		return
	}
	h.p.Store(next)
}

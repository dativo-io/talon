package agentcatalog

import (
	"sync/atomic"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
)

// RuntimeAgent is one agent as every execution surface resolves it (#267):
// the catalog identity plus the compiled runtime bundle. A native run
// captures ONE RuntimeAgent at entry and uses its Engine/Classifier/Router
// through completion, so agent A's config can never execute under agent B's
// engine, scanner, or routing. Bundles are immutable after build; shared
// process infrastructure (provider clients, vault, stores) lives outside.
type RuntimeAgent struct {
	CatalogAgent

	// Engine is this agent's compiled OPA engine (built once per generation
	// by BuildBundle — never per run).
	Engine *policy.Engine
	// Classifier is this agent's policy-aware PII scanner, including
	// semantic enrichment when the policy enables it.
	Classifier classifier.Facade
	// Router carries this agent's routing rules + cost limits over the
	// SHARED provider clients.
	Router *llm.Router
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

// NewRuntimeSnapshot builds one generation from a valid scan, the compiled
// bundles, and the registry — all constructed from the SAME agents. The
// snapshot is the invariant that keeps catalog, bundles, and registry paired:
// one atomic pointer publishes them together, never separately.
func NewRuntimeSnapshot(scan *ScanResult, agents []*RuntimeAgent, registry *gateway.IdentityRegistry, builtAt time.Time) *RuntimeSnapshot {
	s := &RuntimeSnapshot{
		Generation: scan.Digest,
		BuiltAt:    builtAt,
		Registry:   registry,
		Scan:       ScanMeta{Source: scan.Source, Issues: append([]FleetIssue(nil), scan.Issues...)},
		agents:     make(map[string]*RuntimeAgent, len(agents)),
	}
	for _, ra := range agents {
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

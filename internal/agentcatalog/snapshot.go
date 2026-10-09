package agentcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/dativo-io/talon/internal/action"
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
	// Actions is this agent's compiled trusted action catalog (#427):
	// explicit definitions plus the definitions discovered from its trusted
	// MCP sources at generation build, immutable afterwards. The invariant:
	// no actions declared → nil; explicit definitions only → compiled in
	// every build, no SourceDiscoverer needed; MCP sources configured →
	// SourceDiscoverer required, the generation fails closed without one.
	// A nil catalog resolves nothing.
	Actions *action.Catalog
	// Approvals is the approval-relevant policy compiled with the catalog
	// (same generation, same agent file).
	Approvals *action.ApprovalPolicy
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
	// Generation identifies the activated set: the scan digest of the
	// agent files, combined with every discovered action-catalog digest
	// when any agent binds to a trusted MCP source (#427) — the same files
	// with changed upstream facts are a different generation.
	Generation string
	// ScanDigest is the digest of the scanned agent files alone (the
	// reloader's change detector for configuration edits).
	ScanDigest string
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
		ScanDigest: scan.Digest,
		BuiltAt:    builtAt,
		Registry:   registry,
		Scan:       ScanMeta{Source: scan.Source, Issues: append([]FleetIssue(nil), scan.Issues...)},
		agents:     make(map[string]*RuntimeAgent, len(agents)),
	}
	for _, ra := range agents {
		s.agents[ra.Name] = ra
		s.ordered = append(s.ordered, ra)
	}
	s.Generation = generationID(scan.Digest, s.ordered)
	return s
}

// generationID folds the discovered action catalogs into the generation
// identity. Without any discovered source the generation IS the scan
// digest (explicit catalogs are a function of the scanned bytes), so
// existing consumers keep their invariant.
func generationID(scanDigest string, agents []*RuntimeAgent) string {
	h := sha256.New()
	fmt.Fprintf(h, "scan\x00%s\n", scanDigest)
	discovered := false
	for _, ra := range agents {
		if ra.Actions == nil || len(ra.Actions.Sources()) == 0 {
			continue
		}
		discovered = true
		fmt.Fprintf(h, "actions\x00%s\x00%s\n", ra.Name, ra.Actions.Digest)
	}
	if !discovered {
		return scanDigest
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ActionRefreshAt reports the earliest instant any agent's discovered
// action source goes stale by its own freshness hint. ok is false when no
// agent of this generation binds to a discovered source.
func (s *RuntimeSnapshot) ActionRefreshAt() (at time.Time, ok bool) {
	if s == nil {
		return time.Time{}, false
	}
	for _, ra := range s.ordered {
		if t, has := ra.Actions.RefreshAt(); has && (!ok || t.Before(at)) {
			at, ok = t, true
		}
	}
	return at, ok
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

// registryView adapts the runtime holder into the gateway's RegistrySource:
// gateway and server authentication read the registry of the CURRENT
// generation — the same snapshot native execution resolves bundles from.
// There is no independently swappable registry pointer (#267 review): one
// Swap on the runtime holder moves authentication, caps, metrics scope, and
// execution together.
type registryView struct {
	h *RuntimeHolder
}

func (v registryView) Current() *gateway.IdentityRegistry {
	if snap := v.h.Current(); snap != nil {
		return snap.Registry
	}
	return nil
}

// RegistrySource returns the gateway-facing view over this holder's current
// generation.
func (h *RuntimeHolder) RegistrySource() gateway.RegistrySource {
	return registryView{h: h}
}

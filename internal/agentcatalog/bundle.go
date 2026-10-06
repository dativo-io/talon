package agentcatalog

import (
	"context"
	"fmt"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/scanner"
)

// BundleDeps is the SHARED process infrastructure a runtime bundle is
// compiled over: the operator config (scanner engine selection, sovereignty)
// and the provider clients (operator-level credentials, one client per
// provider, shared by every agent's router). Everything per-agent lives in
// the bundle itself.
type BundleDeps struct {
	Config    *config.Config
	Providers map[string]llm.Provider
	// Sources discovers the trusted MCP action sources of an agent so its
	// action catalog can be compiled INTO the generation (#427). This is
	// the one action-catalog build seam of runtime composition: nil means
	// this process builds no action catalogs (native-only CLI runs), and
	// every RuntimeAgent.Actions stays nil. serve always sets it.
	Sources SourceDiscoverer
}

// SourceDiscoverer produces the credential-free snapshots of every trusted
// source an agent configures (all-or-nothing). internal/action/mcpsource
// is the implementation; tests use fakes.
type SourceDiscoverer interface {
	DiscoverSources(ctx context.Context, tenantID, agentID string, cfg *policy.ActionsConfig) (map[string]*action.SourceSnapshot, error)
}

// BuildBundle compiles one agent's runtime bundle (#267): the OPA engine
// (the expensive Rego compile — done once per agent per generation, never
// per run), the policy-aware PII scanner (including semantic enrichment when
// the policy enables it; external engines derive their entity set from THIS
// agent's policy), and the router (this agent's routing rules + cost limits
// over the shared provider clients). A native run captures one bundle at
// entry and uses it through completion, so agent A's config can never
// execute under agent B's engine, scanner, or routing.
//
// Note for external scanner engines: each bundle build runs the engine's
// startup health probe, so a fleet of N agents probes N times at
// startup/reload — the price of per-agent entity derivation.
func BuildBundle(ctx context.Context, ca CatalogAgent, deps BundleDeps) (*RuntimeAgent, error) {
	engine, err := policy.NewEngine(ctx, ca.Policy)
	if err != nil {
		return nil, fmt.Errorf("agent %q (%s): compiling policy engine: %w", ca.Name, ca.Path, err)
	}
	var cls classifier.Facade
	cls, err = scanner.Build(ctx, deps.Config, ca.Policy, engine)
	if err != nil {
		return nil, fmt.Errorf("agent %q (%s): building PII scanner: %w", ca.Name, ca.Path, err)
	}
	router := llm.NewRouter(ca.Policy.Policies.ModelRouting, deps.Providers, ca.Policy.Policies.CostLimits)
	ra := &RuntimeAgent{
		CatalogAgent: ca,
		Engine:       engine,
		Classifier:   cls,
		Router:       router,
	}
	if err := buildActionCatalog(ctx, ca, deps, ra); err != nil {
		return nil, err
	}
	return ra, nil
}

// buildActionCatalog compiles the agent's trusted action catalog into the
// bundle: discover every configured source (network, bounded), then compile
// explicit and discovered definitions with the Talon overlay, then the
// approval-relevant policy. Any failure rejects the whole generation — a
// partial catalog never activates, and a reload keeps last-known-good.
func buildActionCatalog(ctx context.Context, ca CatalogAgent, deps BundleDeps, ra *RuntimeAgent) error {
	if deps.Sources == nil || ca.Policy == nil || ca.Policy.Actions == nil || len(ca.Policy.Actions.Definitions) == 0 {
		return nil
	}
	tenant := ca.TenantID
	if tenant == "" {
		tenant = "default"
	}
	var snapshots map[string]*action.SourceSnapshot
	if len(ca.Policy.Actions.Sources) > 0 {
		var err error
		snapshots, err = deps.Sources.DiscoverSources(ctx, tenant, ca.Name, ca.Policy.Actions)
		if err != nil {
			return fmt.Errorf("agent %q (%s): discovering action sources: %w", ca.Name, ca.Path, err)
		}
	}
	cat, err := action.CompileCatalog(ca.Policy.Actions, snapshots)
	if err != nil {
		return fmt.Errorf("agent %q (%s): action catalog: %w", ca.Name, ca.Path, err)
	}
	ap, err := action.CompileApprovalPolicy(ca.Policy)
	if err != nil {
		return fmt.Errorf("agent %q (%s): action approval policy: %w", ca.Name, ca.Path, err)
	}
	ra.Actions, ra.Approvals = cat, ap
	return nil
}

// BuildRuntimeAgents compiles the whole scanned set, all-or-nothing: one
// agent whose bundle fails to compile rejects the generation (the same
// fail-closed contract as the scan itself — a partially compiled fleet never
// activates).
func BuildRuntimeAgents(ctx context.Context, scan *ScanResult, deps BundleDeps) ([]*RuntimeAgent, error) {
	agents := make([]*RuntimeAgent, 0, len(scan.Agents))
	for i := range scan.Agents {
		ra, err := BuildBundle(ctx, scan.Agents[i], deps)
		if err != nil {
			return nil, err
		}
		agents = append(agents, ra)
	}
	return agents, nil
}

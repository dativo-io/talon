package server

import (
	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/gateway"
)

// The fleet endpoint resolves caps and deny-all from a SPECIFIC captured
// snapshot, never the live holder (#270 review round 3): handleAgentsFleet takes
// ONE coherent FleetView (snapshot + reload state under the reloader lock), so
// every field it returns — generation, membership, policy digest, caps, and the
// BLOCKED deny-all decision — must derive from that SAME snapshot. The
// holder-backed lookup (agentCapsLookup) stays for /v1/costs/budget, which does
// not label its response with an earlier fleet generation.

// snapshotAgentOverride resolves an agent's policy override from the given
// snapshot (matched by tenant+name, or the sole agent when agentID is empty).
// It reads each agent's OWN policy, so it resolves keyless native agents too.
// Ambiguity or absence → (nil, false).
func snapshotAgentOverride(snap *agentcatalog.RuntimeSnapshot, tenantID, agentID string) (*gateway.PolicyOverride, bool) {
	if snap == nil {
		return nil, false
	}
	var match *agentcatalog.RuntimeAgent
	for _, ra := range snap.List() {
		t := ra.TenantID
		if t == "" {
			t = "default"
		}
		if t != tenantID {
			continue
		}
		if agentID != "" {
			if ra.Name == agentID {
				match = ra
				break
			}
			continue
		}
		if match != nil {
			return nil, false // ambiguous
		}
		match = ra
	}
	if match == nil {
		return nil, false
	}
	return agentbridge.LoadedAgentFromPolicy(match.Policy, match.Path).Override, true
}

// fleetCapsFor builds a CapLookup bound to ONE snapshot: effective binding caps
// from each agent's own policy in `snap` + the org baseline. Closing over the
// captured snapshot keeps the fleet endpoint's caps on the same generation as
// its membership. Uses the same ResolveEffectivePolicy → BindingCap path
// enforcement and /v1/costs/budget use.
func fleetCapsFor(snap *agentcatalog.RuntimeSnapshot, org gateway.OrganizationPolicy) fleet.CapLookup {
	return func(tenantID, agentID string) (float64, float64, bool) {
		override, ok := snapshotAgentOverride(snap, tenantID, agentID)
		if !ok {
			return 0, 0, false
		}
		eff := gateway.ResolveEffectivePolicy(org, gateway.ProviderConfig{}, override)
		daily, monthly := eff.BindingDailyCap(), eff.BindingMonthlyCap()
		return daily, monthly, daily > 0 || monthly > 0
	}
}

// fleetDenyAllForSnapshot builds the deny-all predicate bound to ONE snapshot:
// whether an agent's effective policy in `snap` denies ALL new work over the org
// baseline + configured providers. Snapshot-bound for the same coherence reason
// as fleetCapsFor.
func fleetDenyAllForSnapshot(snap *agentcatalog.RuntimeSnapshot, org gateway.OrganizationPolicy, providers map[string]gateway.ProviderConfig) func(tenantID, agentID string) bool {
	return func(tenantID, agentID string) bool {
		override, ok := snapshotAgentOverride(snap, tenantID, agentID)
		if !ok {
			return false
		}
		return !gateway.AgentCanAcceptWork(org, override, providers)
	}
}

package effective

import (
	"context"
	"errors"
	"os"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// ActionConfigs is the action configuration of every use case as the
// CURRENT FILES compile it: the effective action policy (the one compiler,
// action.CompileEffectiveActionPolicy, composed with the company policy of
// the gateway config) and the catalog of explicitly defined actions.
//
// It is what a reader without a running process can say about "the
// configuration now" (the Operations Console comparing an approval with
// it). It is never presented as what a process enforces: each config says
// whether every running `talon serve` is proven to have loaded exactly
// these files (action.CurrentFilesConfirmed, runtimestatus.ProveActionPolicy)
// or not (action.CurrentFiles), and a config that cannot be compiled is
// unavailable, not empty.
type ActionConfigs struct {
	byKey map[string]action.CurrentConfig
	// all is set when nothing could be read at all.
	all *action.CurrentConfig
}

// For returns the configuration of one use case.
func (c *ActionConfigs) For(tenant, name string) action.CurrentConfig {
	if c.all != nil {
		return *c.all
	}
	if tenant == "" {
		tenant = "default"
	}
	if cfg, ok := c.byKey[tenant+"\x00"+name]; ok {
		return cfg
	}
	return action.CurrentConfig{Basis: action.CurrentFiles, Unavailable: "no agent file defines this AI use case in this tenant (removed or renamed), so there is no current configuration to compare with"}
}

// BuildActionConfigs scans the agent files once and compiles every use
// case's action configuration. in.Name and in.Tenant are not used.
func BuildActionConfigs(ctx context.Context, in Inputs) *ActionConfigs {
	unavailable := func(why string) *ActionConfigs {
		return &ActionConfigs{all: &action.CurrentConfig{Basis: action.CurrentFiles, Unavailable: why}}
	}
	scan, err := fleetview.Scan(ctx, in.AgentsDir, in.DefaultPolicy)
	if err != nil {
		return unavailable("the agent files cannot be read: " + err.Error())
	}
	var baseline gateway.OrganizationPolicy
	gwDigest := ""
	if in.GatewayConfig != "" {
		gw, err := gateway.LoadGatewayConfig(in.GatewayConfig)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			// Never compare with the use case's own rules alone when the
			// company layer could not be read.
			return unavailable("the gateway config cannot be loaded, so the company action policy is unknown")
		default:
			baseline, gwDigest = gw.OrganizationPolicy, fileDigest(in.GatewayConfig)
		}
	}
	out := &ActionConfigs{byKey: map[string]action.CurrentConfig{}}
	for i := range scan.Agents {
		a := scan.Agents[i]
		tenant := a.TenantID
		if tenant == "" {
			tenant = "default"
		}
		out.byKey[tenant+"\x00"+a.Name] = actionConfigOf(in, a.Name, tenant, a.PolicyDigest, gwDigest, func() (*action.ApprovalPolicy, func(string) (*action.Definition, bool), string) {
			ap, err := action.CompileEffectiveActionPolicy(a.Policy, baseline.CompanyActionPolicy(in.GatewayConfig))
			if err != nil {
				return nil, nil, "the effective action policy does not compile from the current files"
			}
			if err := checkAgainstDeclaredCatalog(a.Policy, ap); err != nil {
				return nil, nil, "the effective action policy is refused at load from the current files"
			}
			cat, err := action.CompileCatalog(a.Policy.Actions, nil)
			var undiscovered *action.SourceNotDiscoveredError
			switch {
			case errors.As(err, &undiscovered):
				// Actions discovered from MCP sources: their definitions
				// exist only in a process that ran discovery.
				return ap, func(string) (*action.Definition, bool) { return nil, false }, ""
			case err != nil:
				return nil, nil, "the action catalog does not compile from the current files"
			}
			return ap, action.CatalogDefinitions(cat), ""
		})
	}
	return out
}

func actionConfigOf(in Inputs, name, tenant, agentDigest, gwDigest string, compile func() (*action.ApprovalPolicy, func(string) (*action.Definition, bool), string)) action.CurrentConfig {
	ap, defs, why := compile()
	if why != "" {
		return action.CurrentConfig{Basis: action.CurrentFiles, Unavailable: why}
	}
	proof := proveBoundary(in, func(v runtimestatus.View) runtimestatus.Loaded {
		return runtimestatus.ProveActionPolicy(v, in.RuntimeReadable, name, tenant, agentDigest, gwDigest)
	})
	cfg := action.CurrentConfig{Basis: action.CurrentFiles, Policy: ap, Definition: defs}
	if proof.State == runtimestatus.BoundaryProven {
		cfg.Basis = action.CurrentFilesConfirmed
		cfg.Note = "compiled from the current configuration files; " + proof.Reason
	} else {
		cfg.Note = "compiled from the current configuration files; not proven to be what a running process enforces (" + proof.Reason + ")"
	}
	return cfg
}

// Package fleetview projects the attention queue (fleet.AgentRow) from the
// agent configuration on disk plus the shared evidence and session stores:
// the view `talon agents` shows when no Talon server answers, and the view the
// operations console shows until the runtime probe (#538) supplies the
// running process's generation. One function serves both so the two cannot
// disagree (#535).
//
// It sits above internal/fleet (a leaf read model) and internal/agentcatalog
// (the scanner), which is why it is its own package: agentcatalog imports
// agentbridge, so neither of those may host it.
package fleetview

import (
	"context"
	"fmt"
	"time"

	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/gateway"
)

// Scan reads the agent configuration from agentsDir when set, else from the
// single defaultPolicy file. A nil result means no configuration exists; the
// error from the scanner is folded into the result's issues where the scanner
// does so itself, and returned otherwise only when nothing could be read.
func Scan(ctx context.Context, agentsDir, defaultPolicy string) (*agentcatalog.ScanResult, error) {
	var scan *agentcatalog.ScanResult
	if agentsDir != "" {
		scan, _ = agentcatalog.DiscoverAgents(ctx, agentsDir)
	} else {
		scan, _ = agentcatalog.Source{File: defaultPolicy}.Scan(ctx)
	}
	if scan == nil {
		return nil, fmt.Errorf("no agent config found (set agents_dir or %s)", defaultPolicy)
	}
	return scan, nil
}

// Inputs is everything the offline projection reads. Org and Providers come
// from the gateway config (zero values when there is none: an agent-only
// view); Currency from the active pricing table; Evidence and Sessions are
// the shared stores (read-only connections are fine).
type Inputs struct {
	Scan      *agentcatalog.ScanResult
	Org       gateway.OrganizationPolicy
	Providers map[string]gateway.ProviderConfig
	Tenant    string // "" = every tenant
	Currency  string
	Evidence  fleet.EvidenceSource
	Sessions  fleet.SessionSource
	Now       time.Time
}

// Result is the projected attention queue plus the scanner's per-path issues
// (never-valid files are issues, not agent rows).
type Result struct {
	Rows   []fleet.AgentRow
	Issues []agentcatalog.FleetIssue
	// Caps is the effective daily/monthly cap per agent name, as resolved by
	// gateway.ResolveEffectivePolicy over the organization baseline and the
	// agent's override — the same computation enforcement gates on. Exposed
	// so a budget view can label its denominator with the same source.
	Caps map[string]Caps
}

// Caps is one agent's binding caps; zero means uncapped for that period.
type Caps struct {
	Daily   float64
	Monthly float64
}

// ProjectOffline builds the attention queue from in. Every row's health,
// caps, counters and WHY come from fleet.Project — the same function the
// server's /v1/agents/fleet uses — over fleet.AssembleStatuses memberships
// derived from the scan.
func ProjectOffline(ctx context.Context, in Inputs) (*Result, error) {
	if in.Scan == nil {
		return nil, fmt.Errorf("fleetview: scan result is required")
	}
	if in.Evidence == nil || in.Sessions == nil {
		return nil, fmt.Errorf("fleetview: evidence and session sources are required")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	members := make([]fleet.Membership, 0, len(in.Scan.Agents))
	caps := make(map[string]Caps, len(in.Scan.Agents))
	for i := range in.Scan.Agents {
		a := &in.Scan.Agents[i]
		t := a.TenantID
		if t == "" {
			t = "default"
		}
		if in.Tenant != "" && t != in.Tenant {
			continue
		}
		override := agentbridge.LoadedAgentFromPolicy(a.Policy, a.Path).Override
		eff := gateway.ResolveEffectivePolicy(in.Org, gateway.ProviderConfig{}, override)
		caps[a.Name] = Caps{Daily: eff.BindingDailyCap(), Monthly: eff.BindingMonthlyCap()}
		members = append(members, fleet.Membership{
			Name: a.Name, TenantID: t, Enabled: a.Enabled,
			ConfigPath: a.Path, PolicyDigest: a.PolicyDigest,
			PolicyDenyAll: !gateway.AgentCanAcceptWork(in.Org, override, in.Providers),
			UseCase:       agentbridge.FleetUseCase(a.Policy),
		})
	}

	lookup := fleet.CapLookup(func(_, agentID string) (float64, float64, bool) {
		c, ok := caps[agentID]
		return c.Daily, c.Monthly, ok && (c.Daily > 0 || c.Monthly > 0)
	})
	statuses := fleet.AssembleStatuses(members, lookup, in.Currency)
	rows, err := fleet.Project(ctx, in.Evidence, in.Sessions, statuses, fleet.DefaultThresholds(), now.UTC())
	if err != nil {
		return nil, err
	}
	return &Result{Rows: rows, Issues: append([]agentcatalog.FleetIssue(nil), in.Scan.Issues...), Caps: caps}, nil
}

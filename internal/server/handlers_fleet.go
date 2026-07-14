package server

import (
	"context"
	"net/http"
	"time"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/fleet"
)

// WithFleetStatus wires ONE coherent runtime-status read into GET
// /v1/agents/fleet (#269): the RUNNING server is the operational source of
// truth for fleet state — generation, membership, enabled flags, and the most
// recent reload rejection. viewFn captures the active snapshot AND the reload
// state under the same synchronization boundary (Reloader.View), so the
// endpoint can never report a generation that was rolled back mid-read
// (#269 review). Pass a viewFn that returns a nil-Reload FleetView when the
// reload loop is disabled.
func WithFleetStatus(viewFn func() agentcatalog.FleetView) Option {
	return func(s *Server) {
		s.fleetView = viewFn
	}
}

// WithFleetCurrency sets the ISO-4217 unit the attention queue's COST column and
// budget caps render in (#270), resolved from the pricing table at serve time.
func WithFleetCurrency(code string) Option {
	return func(s *Server) {
		s.fleetCurrency = code
	}
}

// WithFleetDenyAll injects the deny-all predicate: whether an agent's ACTIVE
// effective policy denies ALL new work (agent-wide, persistent → BLOCKED, #270),
// evaluated from the effective policy + configured destinations by serve.
func WithFleetDenyAll(fn func(tenantID, agentID string) bool) Option {
	return func(s *Server) {
		s.fleetDenyAll = fn
	}
}

// fleetStatusResponse is the runtime-state contract for GET /v1/agents/fleet.
// The Agents field is the projected attention-queue view (STATE/HEALTH/COST/WHY,
// #270), computed by fleet.Project — the SAME code path the `talon agents` CLI
// uses, so the two can never disagree.
type fleetStatusResponse struct {
	Generation  string                    `json:"generation"`
	ActivatedAt time.Time                 `json:"activated_at"`
	Source      string                    `json:"source"`
	Agents      []fleet.AgentRow          `json:"agents"`
	FleetIssues []agentcatalog.FleetIssue `json:"fleet_issues"`
	// Reload is present when the periodic reload loop is running.
	Reload *agentcatalog.ReloadState `json:"reload,omitempty"`
}

// emptySessionSource stands in when no session store is wired, so the projection
// simply sees zero failed sessions rather than panicking on a nil store.
type emptySessionSource struct{}

func (emptySessionSource) FailedSessionCountsByAgent(_ context.Context, _ string, _ time.Time) (map[string]int, error) {
	return map[string]int{}, nil
}

// handleAgentsFleet (admin) reports the ACTIVE runtime generation as the
// operator attention queue. Snapshot and reload state come from ONE atomic read
// (#269 review), so a rolled-back activation can never appear as active. The
// per-agent health/COST/WHY is projected via fleet.Project (#270) — the ONE code
// path shared with the CLI. Never-valid files appear ONLY under fleet_issues (by
// path) — a broken file is a configuration problem, not a synthesized agent row
// (#267 review).
func (s *Server) handleAgentsFleet(w http.ResponseWriter, r *http.Request) {
	if s.fleetView == nil || s.evidenceStore == nil {
		writeError(w, http.StatusServiceUnavailable, "no_fleet", "fleet status is not available in this serve mode")
		return
	}
	view := s.fleetView()
	snap := view.Snapshot
	if snap == nil {
		writeError(w, http.StatusServiceUnavailable, "no_fleet", "no runtime catalog is active (keyless/quickstart mode)")
		return
	}

	members := membershipFromView(view, s.fleetDenyAll)
	statuses := fleet.AssembleStatuses(members, s.agentCapsLookup, s.fleetCurrency)

	var sessions fleet.SessionSource = emptySessionSource{}
	if s.sessionStore != nil {
		sessions = s.sessionStore
	}
	rows, err := fleet.Project(r.Context(), s.evidenceStore, sessions, statuses, fleet.DefaultThresholds(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "fleet_projection_failed", err.Error())
		return
	}

	issues := make([]agentcatalog.FleetIssue, 0, len(snap.Scan.Issues))
	issues = append(issues, snap.Scan.Issues...)
	resp := fleetStatusResponse{
		Generation:  snap.Generation,
		ActivatedAt: snap.BuiltAt,
		Source:      snap.Scan.Source,
		Agents:      rows,
		FleetIssues: issues,
	}
	// The reload state was captured atomically with the snapshot above, so
	// active_generation / rejected describe the SAME instant — a rolled-back
	// generation is never reported active. The reload object is present ONLY
	// when the periodic reload loop is running (an active reloader always has a
	// non-empty ActiveGeneration); with reload disabled the field is omitted.
	if view.Reload.ActiveGeneration != "" {
		rl := view.Reload
		resp.Reload = &rl
		// A rejected scan's per-path issues surface here too: the ACTIVE
		// generation is clean by construction, but the operator must see what
		// the last scan refused.
		resp.FleetIssues = append(resp.FleetIssues, rl.Issues...)
	}
	writeJSON(w, http.StatusOK, resp)
}

// membershipFromView projects the active snapshot into fleet.Membership rows,
// marking an agent ConfigRejected when the reloader's most recent scan refused
// this agent's current on-disk config (matched by attributed agent name, else by
// config path) while last-known-good keeps serving (#269) — a needs-attention
// signal, distinct from a never-valid file (which stays a fleet issue by path).
func membershipFromView(view agentcatalog.FleetView, denyAll func(tenantID, agentID string) bool) []fleet.Membership {
	rejectedByName := map[string]string{}
	rejectedByPath := map[string]string{}
	if view.Reload.Rejected {
		for _, iss := range view.Reload.Issues {
			if iss.Agent != "" {
				rejectedByName[iss.Agent] = iss.Reason
			}
			rejectedByPath[iss.Path] = iss.Reason
		}
	}
	snap := view.Snapshot
	members := make([]fleet.Membership, 0, snap.Len())
	for _, ra := range snap.List() {
		tenant := ra.TenantID
		if tenant == "" {
			tenant = "default"
		}
		rejected, reason := false, ""
		if r, ok := rejectedByName[ra.Name]; ok {
			rejected, reason = true, r
		} else if r, ok := rejectedByPath[ra.Path]; ok {
			rejected, reason = true, r
		}
		members = append(members, fleet.Membership{
			Name:           ra.Name,
			TenantID:       tenant,
			Enabled:        ra.Enabled,
			ConfigPath:     ra.Path,
			PolicyDigest:   ra.PolicyDigest,
			ConfigRejected: rejected,
			ConfigError:    reason,
			PolicyDenyAll:  denyAll != nil && denyAll(tenant, ra.Name),
		})
	}
	return members
}

package server

import (
	"net/http"
	"time"

	"github.com/dativo-io/talon/internal/agentcatalog"
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

// fleetAgentStatus is one agent's runtime membership row.
type fleetAgentStatus struct {
	Name         string `json:"name"`
	TenantID     string `json:"tenant_id"`
	Enabled      bool   `json:"enabled"`
	ConfigPath   string `json:"config_path"`
	PolicyDigest string `json:"policy_digest"`
}

// fleetStatusResponse is the runtime-state contract for GET /v1/agents/fleet.
type fleetStatusResponse struct {
	Generation  string                    `json:"generation"`
	ActivatedAt time.Time                 `json:"activated_at"`
	Source      string                    `json:"source"`
	Agents      []fleetAgentStatus        `json:"agents"`
	FleetIssues []agentcatalog.FleetIssue `json:"fleet_issues"`
	// Reload is present when the periodic reload loop is running.
	Reload *agentcatalog.ReloadState `json:"reload,omitempty"`
}

// handleAgentsFleet (admin) reports the ACTIVE runtime generation. Snapshot
// and reload state come from ONE atomic read (#269 review), so a rolled-back
// activation can never appear as active. Never-valid files appear ONLY under
// fleet_issues (by path, agent unknown) — a broken file is a configuration
// problem, not a synthesized agent row (#267 review).
func (s *Server) handleAgentsFleet(w http.ResponseWriter, r *http.Request) {
	if s.fleetView == nil {
		writeError(w, http.StatusServiceUnavailable, "no_fleet", "fleet status is not available in this serve mode")
		return
	}
	view := s.fleetView()
	snap := view.Snapshot
	if snap == nil {
		writeError(w, http.StatusServiceUnavailable, "no_fleet", "no runtime catalog is active (keyless/quickstart mode)")
		return
	}
	issues := make([]agentcatalog.FleetIssue, 0, len(snap.Scan.Issues))
	issues = append(issues, snap.Scan.Issues...)
	resp := fleetStatusResponse{
		Generation:  snap.Generation,
		ActivatedAt: snap.BuiltAt,
		Source:      snap.Scan.Source,
		Agents:      make([]fleetAgentStatus, 0, snap.Len()),
		FleetIssues: issues,
	}
	for _, ra := range snap.List() {
		tenant := ra.TenantID
		if tenant == "" {
			tenant = "default"
		}
		resp.Agents = append(resp.Agents, fleetAgentStatus{
			Name: ra.Name, TenantID: tenant, Enabled: ra.Enabled,
			ConfigPath: ra.Path, PolicyDigest: ra.PolicyDigest,
		})
	}
	// The reload state was captured atomically with the snapshot above.
	// active_generation / rejected there always describe the SAME instant as
	// the snapshot, so a rolled-back generation is never reported active.
	rl := view.Reload
	resp.Reload = &rl
	// A rejected scan's per-path issues surface here too: the ACTIVE
	// generation is clean by construction, but the operator must see what the
	// last scan refused.
	resp.FleetIssues = append(resp.FleetIssues, rl.Issues...)
	writeJSON(w, http.StatusOK, resp)
}

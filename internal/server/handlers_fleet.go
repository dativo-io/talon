package server

import (
	"net/http"
	"time"

	"github.com/dativo-io/talon/internal/agentcatalog"
)

// WithFleetStatus wires the runtime-catalog holder and the reloader's state
// into GET /v1/agents/fleet (#269): the RUNNING server is the operational
// source of truth for fleet state — generation, membership, enabled flags,
// and the most recent reload rejection with its per-path causes. reloadState
// may be nil (reload disabled): the endpoint then reports the boot
// generation with no rejection info.
func WithFleetStatus(holder *agentcatalog.RuntimeHolder, reloadState func() agentcatalog.ReloadState) Option {
	return func(s *Server) {
		s.fleetHolder = holder
		s.fleetReloadState = reloadState
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

// handleAgentsFleet (admin) reports the ACTIVE runtime generation. Never-valid
// files appear ONLY under fleet_issues (by path, agent unknown) — a broken
// file is a configuration problem, not a synthesized agent row (#267 review).
func (s *Server) handleAgentsFleet(w http.ResponseWriter, r *http.Request) {
	snap := s.fleetHolder.Current()
	if snap == nil {
		writeError(w, http.StatusServiceUnavailable, "no_fleet", "no runtime catalog is active (keyless/quickstart mode)")
		return
	}
	resp := fleetStatusResponse{
		Generation:  snap.Generation,
		ActivatedAt: snap.BuiltAt,
		Source:      snap.Scan.Source,
		Agents:      make([]fleetAgentStatus, 0, snap.Len()),
		FleetIssues: append([]agentcatalog.FleetIssue(nil), snap.Scan.Issues...),
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
	if s.fleetReloadState != nil {
		st := s.fleetReloadState()
		resp.Reload = &st
		// A rejected scan's per-path issues surface here too: the ACTIVE
		// generation is clean by construction, but the operator must see what
		// the last scan refused.
		resp.FleetIssues = append(resp.FleetIssues, st.Issues...)
	}
	writeJSON(w, http.StatusOK, resp)
}

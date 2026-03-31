package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agent"
)

// handleOverridesList returns all active overrides.
// GET /v1/overrides — admin-only.
func (s *Server) handleOverridesList(w http.ResponseWriter, r *http.Request) {
	store := s.overrideStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "override store not available"})
		return
	}
	writeJSON(w, http.StatusOK, store.ListAll())
}

// handleOverrideGet returns overrides for a specific tenant.
// GET /v1/overrides/{tenant_id} — admin-only.
func (s *Server) handleOverrideGet(w http.ResponseWriter, r *http.Request) {
	store := s.overrideStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "override store not available"})
		return
	}
	tenantID := chi.URLParam(r, "tenant_id")
	ov := store.Get(tenantID)
	if ov == nil {
		writeJSON(w, http.StatusOK, map[string]string{"tenant_id": tenantID, "status": "no overrides"})
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

// handleTenantLockdown activates lockdown mode for a tenant.
// POST /v1/overrides/{tenant_id}/lockdown — admin-only.
func (s *Server) handleTenantLockdown(w http.ResponseWriter, r *http.Request) {
	store := s.overrideStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "override store not available"})
		return
	}
	tenantID := chi.URLParam(r, "tenant_id")
	store.SetLockdown(tenantID, true, "admin_api")

	reg := s.runRegistry()
	killed := 0
	if reg != nil {
		killed = reg.KillAllForTenant(tenantID)
	}
	if s.activeRunTracker != nil {
		s.activeRunTracker.KillAllForTenant(tenantID)
	}
	log.Warn().Str("tenant_id", tenantID).Int("runs_killed", killed).Msg("tenant_lockdown_activated")
	s.recordControlPlaneAction(r.Context(), tenantID, "tenant_lockdown", "admin_api",
		fmt.Sprintf("runs_killed=%d", killed))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id":   tenantID,
		"lockdown":    true,
		"runs_killed": killed,
	})
}

// handleTenantUnlock lifts lockdown for a tenant.
// DELETE /v1/overrides/{tenant_id}/lockdown — admin-only.
func (s *Server) handleTenantUnlock(w http.ResponseWriter, r *http.Request) {
	store := s.overrideStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "override store not available"})
		return
	}
	tenantID := chi.URLParam(r, "tenant_id")
	store.SetLockdown(tenantID, false, "")
	log.Info().Str("tenant_id", tenantID).Msg("tenant_lockdown_lifted")
	s.recordControlPlaneAction(r.Context(), tenantID, "tenant_unlock", "admin_api", "lockdown lifted")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id": tenantID,
		"lockdown":  false,
	})
}

type disableToolsRequest struct {
	Tools  []string `json:"tools"`
	Reason string   `json:"reason"`
}

// handleToolsDisable disables specific tools for a tenant via override.
// POST /v1/overrides/{tenant_id}/tools/disable — admin-only.
func (s *Server) handleToolsDisable(w http.ResponseWriter, r *http.Request) {
	store := s.overrideStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "override store not available"})
		return
	}
	tenantID := chi.URLParam(r, "tenant_id")
	var req disableToolsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if len(req.Tools) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tools list required"})
		return
	}
	store.DisableTools(tenantID, req.Tools, req.Reason)
	log.Warn().Str("tenant_id", tenantID).Strs("tools", req.Tools).Str("reason", req.Reason).Msg("tools_disabled_by_override")
	s.recordControlPlaneAction(r.Context(), tenantID, "tools_disable", "admin_api",
		fmt.Sprintf("tools=%v reason=%s", req.Tools, req.Reason))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id":      tenantID,
		"disabled_tools": store.DisabledToolsFor(tenantID),
		"reason":         req.Reason,
	})
}

type enableToolsRequest struct {
	Tools []string `json:"tools"`
}

// handleToolsEnable re-enables previously disabled tools for a tenant.
// POST /v1/overrides/{tenant_id}/tools/enable — admin-only.
func (s *Server) handleToolsEnable(w http.ResponseWriter, r *http.Request) {
	store := s.overrideStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "override store not available"})
		return
	}
	tenantID := chi.URLParam(r, "tenant_id")
	var req enableToolsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if len(req.Tools) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tools list required"})
		return
	}
	store.EnableTools(tenantID, req.Tools)
	log.Info().Str("tenant_id", tenantID).Strs("tools", req.Tools).Msg("tools_enabled_by_override")
	s.recordControlPlaneAction(r.Context(), tenantID, "tools_enable", "admin_api",
		fmt.Sprintf("tools=%v", req.Tools))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id":      tenantID,
		"disabled_tools": store.DisabledToolsFor(tenantID),
	})
}

type policyOverrideRequest struct {
	MaxCostPerRun *float64 `json:"max_cost_per_run,omitempty"`
	MaxToolCalls  *int     `json:"max_tool_calls,omitempty"`
}

// handlePolicyOverride sets stricter policy caps for a tenant.
// POST /v1/overrides/{tenant_id}/policy — admin-only.
func (s *Server) handlePolicyOverride(w http.ResponseWriter, r *http.Request) {
	store := s.overrideStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "override store not available"})
		return
	}
	tenantID := chi.URLParam(r, "tenant_id")
	var req policyOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	store.SetPolicyOverride(tenantID, req.MaxCostPerRun, req.MaxToolCalls)
	log.Info().Str("tenant_id", tenantID).Interface("max_cost_per_run", req.MaxCostPerRun).Interface("max_tool_calls", req.MaxToolCalls).Msg("policy_override_set")
	s.recordControlPlaneAction(r.Context(), tenantID, "policy_override", "admin_api",
		fmt.Sprintf("max_cost_per_run=%v max_tool_calls=%v", req.MaxCostPerRun, req.MaxToolCalls))
	writeJSON(w, http.StatusOK, store.Get(tenantID))
}

// handleOverrideClear removes all overrides for a tenant.
// DELETE /v1/overrides/{tenant_id} — admin-only.
func (s *Server) handleOverrideClear(w http.ResponseWriter, r *http.Request) {
	store := s.overrideStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "override store not available"})
		return
	}
	tenantID := chi.URLParam(r, "tenant_id")
	store.ClearOverride(tenantID)
	log.Info().Str("tenant_id", tenantID).Msg("overrides_cleared")
	writeJSON(w, http.StatusOK, map[string]string{"tenant_id": tenantID, "status": "cleared"})
}

// overrideStore returns the OverrideStore from the runner.
func (s *Server) overrideStore() *agent.OverrideStore {
	if s.overrideStoreRef != nil {
		return s.overrideStoreRef
	}
	if s.runner != nil {
		return s.runner.OverrideStoreRef()
	}
	return nil
}

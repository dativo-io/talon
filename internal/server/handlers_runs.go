package server

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agent"
)

// handleRunsList returns all active (non-terminal) runs from the RunRegistry.
// GET /v1/runs?tenant_id=X — admin-only.
func (s *Server) handleRunsList(w http.ResponseWriter, r *http.Request) {
	reg := s.runRegistry()
	if reg == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "run registry not available"})
		return
	}
	tenantFilter := r.URL.Query().Get("tenant_id")
	runs := reg.List()
	if tenantFilter != "" {
		filtered := runs[:0]
		for i := range runs {
			if runs[i].TenantID == tenantFilter {
				filtered = append(filtered, runs[i])
			}
		}
		runs = filtered
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].StartedAt.Before(runs[j].StartedAt) })
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"runs":  runs,
		"count": len(runs),
	})
}

// handleRunGet returns the state of a single run.
// GET /v1/runs/{id} — admin-only.
func (s *Server) handleRunGet(w http.ResponseWriter, r *http.Request) {
	reg := s.runRegistry()
	if reg == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "run registry not available"})
		return
	}
	id := chi.URLParam(r, "id")
	rs := reg.Get(id)
	if rs == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run not found"})
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

// handleRunKill cancels a specific run by correlation ID.
// POST /v1/runs/{id}/kill — admin-only.
func (s *Server) handleRunKill(w http.ResponseWriter, r *http.Request) {
	reg := s.runRegistry()
	if reg == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "run registry not available"})
		return
	}
	id := chi.URLParam(r, "id")
	killed := reg.Kill(id)
	if s.activeRunTracker != nil {
		s.activeRunTracker.Kill(id)
	}
	if !killed {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run not found or already terminal"})
		return
	}
	log.Warn().Str("correlation_id", id).Msg("run_killed_by_admin")
	s.recordControlPlaneAction(r.Context(), "", "operator_kill", "admin_api", "run="+id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "terminated", "correlation_id": id})
}

// handleRunKillAll cancels all runs for a tenant.
// POST /v1/runs/kill-all?tenant_id=X — admin-only.
func (s *Server) handleRunKillAll(w http.ResponseWriter, r *http.Request) {
	reg := s.runRegistry()
	if reg == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "run registry not available"})
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id query parameter required"})
		return
	}
	killed := reg.KillAllForTenant(tenantID)
	if s.activeRunTracker != nil {
		s.activeRunTracker.KillAllForTenant(tenantID)
	}
	log.Warn().Str("tenant_id", tenantID).Int("killed", killed).Msg("runs_killed_by_admin_for_tenant")
	s.recordControlPlaneAction(r.Context(), tenantID, "operator_kill_all", "admin_api",
		fmt.Sprintf("killed=%d", killed))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "terminated",
		"tenant_id": tenantID,
		"killed":    killed,
	})
}

// handleRunPause sends a pause signal to a running run.
// POST /v1/runs/{id}/pause — admin-only.
func (s *Server) handleRunPause(w http.ResponseWriter, r *http.Request) {
	reg := s.runRegistry()
	if reg == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "run registry not available"})
		return
	}
	id := chi.URLParam(r, "id")
	paused := reg.Pause(id)
	if !paused {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run not found or not in running state"})
		return
	}
	log.Info().Str("correlation_id", id).Msg("run_paused_by_admin")
	s.recordControlPlaneAction(r.Context(), "", "operator_pause", "admin_api", "run="+id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused", "correlation_id": id})
}

// handleRunResume unpauses a paused run.
// POST /v1/runs/{id}/resume — admin-only.
func (s *Server) handleRunResume(w http.ResponseWriter, r *http.Request) {
	reg := s.runRegistry()
	if reg == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "run registry not available"})
		return
	}
	id := chi.URLParam(r, "id")
	resumed := reg.Resume(id)
	if !resumed {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run not found or not in paused state"})
		return
	}
	log.Info().Str("correlation_id", id).Msg("run_resumed_by_admin")
	s.recordControlPlaneAction(r.Context(), "", "operator_resume", "admin_api", "run="+id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "running", "correlation_id": id})
}

// runRegistry returns the RunRegistry from the runner, or the server-level fallback.
func (s *Server) runRegistry() *agent.RunRegistry {
	if s.runRegistryRef != nil {
		return s.runRegistryRef
	}
	if s.runner != nil {
		return s.runner.RunRegistryRef()
	}
	return nil
}

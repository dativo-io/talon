// Package server provides HTTP API handlers; this file adds CoPaw-specific dashboard and stats.
package server

import (
	"net/http"
	"time"
)

// handleCoPawStats returns per-CoPaw-instance request count, cost, and policy summary.
// Query: tenant_id (optional), agent_id (optional, default copaw-main).
func (s *Server) handleCoPawStats(w http.ResponseWriter, r *http.Request) {
	if s.evidenceStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "ok",
			"agents": []interface{}{},
		})
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		agentID = "copaw-main"
	}
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	countToday, _ := s.evidenceStore.CountInRange(r.Context(), tenantID, agentID, dayStart, dayEnd)
	costToday, _ := s.evidenceStore.CostTotal(r.Context(), tenantID, agentID, dayStart, dayEnd)
	costMonth, _ := s.evidenceStore.CostTotal(r.Context(), tenantID, agentID, monthStart, monthEnd)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "ok",
		"tenant_id":      tenantID,
		"agent_id":       agentID,
		"requests_today": countToday,
		"cost_today":     costToday,
		"cost_month":     costMonth,
	})
}

// handleCoPawAlerts returns recent policy denials and PII detections for CoPaw callers.
// Query: tenant_id (optional), agent_id (optional, default copaw-main).
func (s *Server) handleCoPawAlerts(w http.ResponseWriter, r *http.Request) {
	if s.evidenceStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "ok",
			"alerts": []interface{}{},
		})
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		agentID = "copaw-main"
	}
	limit := 20
	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC()

	list, err := s.evidenceStore.List(r.Context(), tenantID, agentID, from, to, limit*2)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	var alerts []map[string]interface{}
	for i := range list {
		ev := &list[i]
		denied := !ev.PolicyDecision.Allowed
		piiDetected := len(ev.Classification.PIIDetected) > 0
		if denied || piiDetected {
			alerts = append(alerts, map[string]interface{}{
				"id":            ev.ID,
				"timestamp":     ev.Timestamp,
				"agent_id":      ev.AgentID,
				"policy_denied": denied,
				"pii_detected":  piiDetected,
				"model":         ev.Execution.ModelUsed,
			})
			if len(alerts) >= limit {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"tenant_id": tenantID,
		"agent_id":  agentID,
		"alerts":    alerts,
	})
}

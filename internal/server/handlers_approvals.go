package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agent"
)

// handleToolApprovalsList returns all pending tool approval requests.
// GET /v1/tool-approvals — admin-only.
func (s *Server) handleToolApprovalsList(w http.ResponseWriter, r *http.Request) {
	store := s.toolApprovalStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tool approval store not available"})
		return
	}
	pending := store.ListPending()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending": pending,
		"count":   len(pending),
	})
}

// handleToolApprovalGet returns a specific tool approval request.
// GET /v1/tool-approvals/{id} — admin-only.
func (s *Server) handleToolApprovalGet(w http.ResponseWriter, r *http.Request) {
	store := s.toolApprovalStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tool approval store not available"})
		return
	}
	id := chi.URLParam(r, "id")
	req := store.Get(id)
	if req == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval request not found"})
		return
	}
	writeJSON(w, http.StatusOK, req)
}

type approvalDecisionRequest struct {
	Decision string `json:"decision"` // "approve" or "deny"
	Reason   string `json:"reason,omitempty"`
}

// handleToolApprovalDecide approves or denies a pending tool execution.
// POST /v1/tool-approvals/{id}/decide — admin-only.
func (s *Server) handleToolApprovalDecide(w http.ResponseWriter, r *http.Request) {
	store := s.toolApprovalStore()
	if store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tool approval store not available"})
		return
	}
	id := chi.URLParam(r, "id")
	var req approvalDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	switch req.Decision {
	case "approve":
		if ok := store.Approve(id, "admin_api", req.Reason); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval request not found or not pending"})
			return
		}
		log.Info().Str("approval_id", id).Msg("tool_approval_approved")
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "approved"})
	case "deny":
		if ok := store.Deny(id, "admin_api", req.Reason); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval request not found or not pending"})
			return
		}
		log.Info().Str("approval_id", id).Msg("tool_approval_denied")
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "denied"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decision must be 'approve' or 'deny'"})
	}
}

// toolApprovalStore returns the ToolApprovalStore from the runner.
func (s *Server) toolApprovalStore() *agent.ToolApprovalStore {
	if s.toolApprovalStoreRef != nil {
		return s.toolApprovalStoreRef
	}
	if s.runner != nil {
		return s.runner.ToolApprovalStoreRef()
	}
	return nil
}

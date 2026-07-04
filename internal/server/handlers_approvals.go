package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/policy"
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
	Decision    string                     `json:"decision"` // "approve" or "deny"
	Reason      string                     `json:"reason,omitempty"`
	Remediation *approvalRemediationConfig `json:"remediation,omitempty"`
}

type approvalRemediationConfig struct {
	Mode string `json:"mode,omitempty"` // "re_redact_rescan"
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
		remediationMode := ""
		remediationStatus := ""
		var remediatedArgs map[string]any
		if req.Remediation != nil && strings.TrimSpace(req.Remediation.Mode) != "" {
			pending := store.Get(id)
			if pending == nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval request not found or not pending"})
				return
			}
			remediationMode = strings.TrimSpace(req.Remediation.Mode)
			remediated, err := s.remediateApprovalArguments(r.Context(), pending, remediationMode)
			if err != nil {
				s.recordControlPlaneAction(r.Context(), "", "tool_approval_remediation_failed", "admin_api",
					fmt.Sprintf("approval_id=%s remediation_mode=%s error=%s", id, remediationMode, err.Error()))
				writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
				return
			}
			remediationStatus = "applied"
			remediatedArgs = remediated
		}
		if ok := store.ApproveWithRemediation(id, "admin_api", req.Reason, remediationMode, remediationStatus, remediatedArgs); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval request not found or not pending"})
			return
		}
		log.Info().Str("approval_id", id).Msg("tool_approval_approved")
		s.recordControlPlaneAction(r.Context(), "", "tool_approval_approved", "admin_api",
			fmt.Sprintf("approval_id=%s reason=%s remediation_mode=%s remediation_status=%s", id, req.Reason, remediationMode, remediationStatus))
		resp := map[string]string{"id": id, "status": "approved"}
		if remediationMode != "" {
			resp["remediation_mode"] = remediationMode
			resp["remediation_status"] = remediationStatus
		}
		writeJSON(w, http.StatusOK, resp)
	case "deny":
		if ok := store.Deny(id, "admin_api", req.Reason); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval request not found or not pending"})
			return
		}
		log.Info().Str("approval_id", id).Msg("tool_approval_denied")
		s.recordControlPlaneAction(r.Context(), "", "tool_approval_denied", "admin_api",
			fmt.Sprintf("approval_id=%s reason=%s", id, req.Reason))
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "denied"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decision must be 'approve' or 'deny'"})
	}
}

func (s *Server) remediateApprovalArguments(ctx context.Context, req *agent.ToolApprovalRequest, mode string) (map[string]any, error) {
	if mode != "re_redact_rescan" {
		return nil, fmt.Errorf("unsupported remediation mode %q", mode)
	}
	scanner, err := s.toolApprovalRemediationScanner(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing remediation scanner: %w", err)
	}
	rawArgs, err := json.Marshal(req.Arguments)
	if err != nil {
		return nil, fmt.Errorf("encoding approval arguments: %w", err)
	}
	redacted, redactErr := scanner.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), string(rawArgs))
	if redactErr != nil {
		return nil, fmt.Errorf("remediation failed: PII scanner unavailable (fail-closed): %w", redactErr)
	}
	if verifyErr := scanner.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), redacted); verifyErr != nil {
		types := classifier.ResidualTypes(verifyErr)
		if len(types) == 0 {
			return nil, fmt.Errorf("remediation failed: recognized PII remains after re-redact/re-scan")
		}
		return nil, fmt.Errorf("remediation failed: recognized PII remains after re-redact/re-scan (types: %s)", strings.Join(types, ", "))
	}
	if !json.Valid([]byte(redacted)) {
		return nil, fmt.Errorf("remediation failed: redacted arguments are not valid JSON")
	}
	var remediated map[string]any
	if err := json.Unmarshal([]byte(redacted), &remediated); err != nil {
		return nil, fmt.Errorf("decoding remediated arguments: %w", err)
	}
	return remediated, nil
}

func (s *Server) toolApprovalRemediationScanner(ctx context.Context) (classifier.Facade, error) {
	// When an external scanner engine is configured it is authoritative:
	// building a per-policy regex scanner here would silently bypass the
	// operator's engine choice.
	if s.classifier != nil {
		if _, isBuiltin := s.classifier.(*classifier.Scanner); !isBuiltin {
			return s.classifier, nil
		}
	}
	if s.policy == nil {
		return nil, fmt.Errorf("policy is required for remediation")
	}
	engine := s.policyEngine
	if engine == nil {
		var err error
		engine, err = policy.NewEngine(ctx, s.policy)
		if err != nil {
			return nil, err
		}
	}
	scanner, err := policy.NewPIIScannerForPolicyWithEnrichment(ctx, s.policy, "", engine)
	if err != nil {
		return nil, err
	}
	return scanner, nil
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

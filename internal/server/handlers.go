package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/drift"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/session"
)

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func reasoningFromRequestHeaderOrBody(headerValue, bodyValue string) string {
	if headerValue != "" {
		return headerValue
	}
	return bodyValue
}

func (s *Server) resolveApproverFromRequest(ctx context.Context, r *http.Request) (*approver.Record, error) {
	key := bearerToken(r)
	if key == "" || !strings.HasPrefix(key, "talon_appr_") {
		return nil, nil
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	store, err := approver.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return nil, err
	}
	defer store.Close()
	rec, err := store.Resolve(ctx, key)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *Server) approverRoleAllowed(role string) bool {
	if s.policy == nil || s.policy.Compliance == nil || s.policy.Compliance.PlanReview == nil {
		return true
	}
	chain := s.policy.Compliance.PlanReview.ApprovalChain
	if len(chain) == 0 {
		return true
	}
	for _, lvl := range chain {
		if lvl.Role == role {
			return true
		}
	}
	return false
}

func (s *Server) verifyAgentRequestSignature(ctx context.Context, r *http.Request, tenantID, agentID, prompt string) (bool, error) {
	sigHex := strings.TrimSpace(r.Header.Get("X-Talon-Agent-Signature"))
	ts := strings.TrimSpace(r.Header.Get("X-Talon-Agent-Timestamp"))
	if sigHex == "" || ts == "" {
		return false, nil
	}
	if s.secretsStore == nil {
		return false, errors.New("agent signature provided but secrets store is not configured")
	}
	secretName := "agent-signing-" + agentID
	sec, err := s.secretsStore.Get(ctx, secretName, tenantID, agentID)
	if err != nil {
		return false, err
	}
	mac := hmac.New(sha256.New, sec.Value)
	_, _ = mac.Write([]byte(tenantID + "|" + agentID + "|" + prompt + "|" + ts))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(sigHex))), nil
}

// openAIErrorBody is the OpenAI API error response shape so SDKs can parse error.message.
type openAIErrorBody struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type,omitempty"`
		Code    string `json:"code,omitempty"`
	} `json:"error"`
}

// writeOpenAIError writes a JSON error in OpenAI format: {"error": {"message": "...", "type": "...", "code": "..."}}.
// Use only for OpenAI-compatible endpoints (e.g. /v1/chat/completions).
func writeOpenAIError(w http.ResponseWriter, status int, code, typeStr, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := openAIErrorBody{}
	body.Error.Message = message
	body.Error.Type = typeStr
	body.Error.Code = code
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status": "ok",
		"uptime": time.Since(s.startTime).String(),
	}
	if r.URL.Query().Get("detail") == "true" {
		components := map[string]string{
			"evidence_store": "ok",
			"policy_engine":  "ok",
		}
		if s.memoryStore == nil {
			components["memory_store"] = "disabled"
		} else {
			components["memory_store"] = "ok"
		}
		if s.mcpProxy == nil {
			components["mcp_proxy"] = "disabled"
		} else {
			components["mcp_proxy"] = "ok"
		}
		if s.planReviewStore == nil {
			components["plan_review"] = "disabled"
		} else {
			components["plan_review"] = "ok"
		}
		resp["components"] = components
	}
	writeJSON(w, http.StatusOK, resp)
}

type agentRunRequest struct {
	TenantID       string `json:"tenant_id"`
	AgentID        string `json:"agent_id"`
	AgentName      string `json:"agent_name"`
	Prompt         string `json:"prompt"`
	AgentReasoning string `json:"_talon_reasoning"`
	SessionID      string `json:"_talon_session_id"`
	DryRun         bool   `json:"dry_run"`
}

func (s *Server) handleAgentRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var req agentRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = req.TenantID
	}
	if tenantID == "" {
		tenantID = "default"
	}
	agentName := req.AgentName
	if agentName == "" {
		agentName = req.AgentID
	}
	if agentName == "" {
		agentName = "default"
	}
	if req.Prompt == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "prompt is required")
		return
	}
	runReq := &agent.RunRequest{
		TenantID:       tenantID,
		AgentName:      agentName,
		Prompt:         req.Prompt,
		AgentReasoning: reasoningFromRequestHeaderOrBody(r.Header.Get("X-Talon-Reasoning"), req.AgentReasoning),
		SessionID:      reasoningFromRequestHeaderOrBody(r.Header.Get("X-Talon-Session-ID"), req.SessionID),
		InvocationType: "api",
		PolicyPath:     s.policyPath,
		DryRun:         req.DryRun,
	}
	if verified, err := s.verifyAgentRequestSignature(r.Context(), r, tenantID, agentName, req.Prompt); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
		return
	} else if verified {
		runReq.AgentVerified = true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	resp, err := s.runner.Run(ctx, runReq)
	if err != nil {
		log.Error().Err(err).Str("tenant_id", tenantID).Str("agent_name", agentName).Msg("agent_run_error")
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if runReq.SessionID != "" {
		w.Header().Set("X-Talon-Session-ID", runReq.SessionID)
	}
	if !resp.PolicyAllow {
		writeError(w, http.StatusForbidden, "policy_denied", resp.DenyReason)
		return
	}
	if resp.PlanPending != "" {
		writeJSON(w, http.StatusAccepted, map[string]string{
			"plan_pending": resp.PlanPending,
			"message":      "Execution pending human review",
			"session_id":   runReq.SessionID,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"response":      resp.Response,
		"evidence_id":   resp.EvidenceID,
		"cost":          resp.Cost,
		"duration_ms":   resp.DurationMS,
		"model_used":    resp.ModelUsed,
		"tools_called":  resp.ToolsCalled,
		"input_tokens":  resp.InputTokens,
		"output_tokens": resp.OutputTokens,
		"session_id":    runReq.SessionID,
	})
}

//nolint:gocyclo // handler branches on request validation and response shaping
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "POST required")
		return
	}
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		AgentID        string `json:"agent_id"`
		TenantID       string `json:"tenant_id"`
		AgentReasoning string `json:"_talon_reasoning"`
		SessionID      string `json:"_talon_session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_json", "invalid_request_error", "invalid JSON: "+err.Error())
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = req.TenantID
	}
	if tenantID == "" {
		tenantID = r.Header.Get("X-Talon-Tenant")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	agentName := req.AgentID
	if agentName == "" {
		agentName = r.Header.Get("X-Talon-Agent")
	}
	if agentName == "" {
		agentName = "default"
	}
	var prompt string
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" && req.Messages[i].Content != "" {
			prompt = req.Messages[i].Content
			break
		}
	}
	if prompt == "" {
		for _, m := range req.Messages {
			if m.Content != "" {
				prompt = m.Content
				break
			}
		}
	}
	if prompt == "" {
		writeOpenAIError(w, http.StatusBadRequest, "messages_required", "invalid_request_error", "no user message content in messages")
		return
	}
	runReq := &agent.RunRequest{
		TenantID:       tenantID,
		AgentName:      agentName,
		Prompt:         prompt,
		AgentReasoning: reasoningFromRequestHeaderOrBody(r.Header.Get("X-Talon-Reasoning"), req.AgentReasoning),
		SessionID:      reasoningFromRequestHeaderOrBody(r.Header.Get("X-Talon-Session-ID"), req.SessionID),
		InvocationType: "http",
		PolicyPath:     s.policyPath,
	}
	if verified, err := s.verifyAgentRequestSignature(r.Context(), r, tenantID, agentName, prompt); err != nil {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid_signature", "invalid_request_error", err.Error())
		return
	} else if verified {
		runReq.AgentVerified = true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	resp, err := s.runner.Run(ctx, runReq)
	if err != nil {
		log.Error().Err(err).Str("tenant_id", tenantID).Msg("chat_completions_run_error")
		writeOpenAIError(w, http.StatusInternalServerError, "run_failed", "internal_error", err.Error())
		return
	}
	if runReq.SessionID != "" {
		w.Header().Set("X-Talon-Session-ID", runReq.SessionID)
	}
	if !resp.PolicyAllow {
		writeOpenAIError(w, http.StatusForbidden, "policy_denied", "policy_denied", resp.DenyReason)
		return
	}
	if resp.PlanPending != "" {
		writeOpenAIError(w, http.StatusAccepted, "plan_pending", "plan_pending", "plan pending human review: "+resp.PlanPending)
		return
	}
	model := resp.ModelUsed
	if model == "" {
		model = req.Model
	}
	if model == "" {
		model = "talon"
	}
	id := "chatcmpl-" + resp.EvidenceID
	if len(id) > 32 {
		id = id[:32]
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":      id,
		"object":  "chat.completion",
		"created": time.Now().UTC().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{{
			"index":         0,
			"message":       map[string]string{"role": "assistant", "content": resp.Response},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{
			"prompt_tokens":     resp.InputTokens,
			"completion_tokens": resp.OutputTokens,
			"total_tokens":      resp.InputTokens + resp.OutputTokens,
		},
	})
}

func (s *Server) handleEvidenceList(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := r.URL.Query().Get("agent_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	var from, to time.Time
	if f := r.URL.Query().Get("from"); f != "" {
		from, _ = time.Parse(time.RFC3339, f)
	}
	if t := r.URL.Query().Get("to"); t != "" {
		to, _ = time.Parse(time.RFC3339, t)
	}
	allowed := r.URL.Query().Get("allowed") // "true", "false", "1", "0" or empty
	model := r.URL.Query().Get("model")     // exact match on execution.model_used
	entries, err := s.evidenceStore.ListIndex(r.Context(), tenantID, agentID, from, to, limit, "", allowed, model)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"layer":   "index",
		"entries": entries,
		"hint":    "use GET /v1/evidence/timeline?around=<id> or GET /v1/evidence/<id> for more",
	})
}

func (s *Server) handleEvidenceTimeline(w http.ResponseWriter, r *http.Request) {
	around := r.URL.Query().Get("around")
	if around == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "around query parameter is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	// Resolve target to enforce tenant isolation; Timeline uses target.TenantID for before/after.
	target, err := s.evidenceStore.Get(r.Context(), around)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if target.TenantID != tenantID {
		writeError(w, http.StatusNotFound, "not_found", "evidence not found")
		return
	}
	before, _ := strconv.Atoi(r.URL.Query().Get("before"))
	if before <= 0 {
		before = 3
	}
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	if after <= 0 {
		after = 3
	}
	entries, err := s.evidenceStore.Timeline(r.Context(), around, before, after)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"layer":   "timeline",
		"around":  around,
		"before":  before,
		"after":   after,
		"entries": entries,
		"hint":    "use GET /v1/evidence/<id> for full detail",
	})
}

func (s *Server) handleEvidenceGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	ev, err := s.evidenceStore.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if ev.TenantID != tenantID {
		writeError(w, http.StatusNotFound, "not_found", "evidence not found")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// handleEvidenceTrace returns the full evidence record plus step evidence (request → policy → model → tools → response) for trace detail view.
func (s *Server) handleEvidenceTrace(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	ev, err := s.evidenceStore.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if ev.TenantID != tenantID {
		writeError(w, http.StatusNotFound, "not_found", "evidence not found")
		return
	}
	steps, _ := s.evidenceStore.ListStepsByCorrelationID(r.Context(), ev.CorrelationID)
	if steps == nil {
		steps = []evidence.StepEvidence{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"evidence": ev,
		"steps":    steps,
	})
}

func (s *Server) handleEvidenceVerify(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	ev, err := s.evidenceStore.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if ev.TenantID != tenantID {
		writeError(w, http.StatusNotFound, "not_found", "evidence not found")
		return
	}
	valid := s.evidenceStore.VerifyRecord(ev)
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "valid": valid})
}

type evidenceExportRequest struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	From     string `json:"from"`
	To       string `json:"to"`
	Limit    int    `json:"limit"`
	Format   string `json:"format"` // csv | json
}

func (s *Server) handleEvidenceExport(w http.ResponseWriter, r *http.Request) {
	var req evidenceExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = req.TenantID
	}
	if tenantID == "" {
		tenantID = "default"
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 1000
	}
	var from, to time.Time
	if req.From != "" {
		from, _ = time.Parse(time.RFC3339, req.From)
	}
	if req.To != "" {
		to, _ = time.Parse(time.RFC3339, req.To)
	}
	format := req.Format
	if format == "" {
		format = "json"
	}
	if format != "csv" && format != "json" {
		writeError(w, http.StatusBadRequest, "invalid_request", "format must be csv or json")
		return
	}
	list, err := s.evidenceStore.List(r.Context(), tenantID, req.AgentID, from, to, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	records := make([]evidence.ExportRecord, len(list))
	for i := range list {
		records[i] = evidence.ToExportRecord(&list[i])
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "timestamp", "tenant_id", "agent_id", "invocation_type", "allowed", "cost", "model_used", "duration_ms", "has_error", "input_tier", "output_tier", "pii_detected", "pii_redacted", "policy_reasons", "tools_called", "input_hash", "output_hash", "primary_explanation_code", "primary_explanation_reason", "primary_version_identity"})
		for i := range records {
			rec := &records[i]
			pii := rec.PIIDetectedCSV()
			reasons := rec.PolicyReasonsCSV()
			tools := rec.ToolsCalledCSV()
			_ = cw.Write([]string{
				rec.ID, rec.Timestamp.Format(time.RFC3339), rec.TenantID, rec.AgentID, rec.InvocationType,
				strconv.FormatBool(rec.Allowed), strconv.FormatFloat(rec.Cost, 'f', -1, 64), rec.ModelUsed,
				strconv.FormatInt(rec.DurationMS, 10), strconv.FormatBool(rec.HasError),
				strconv.Itoa(rec.InputTier), strconv.Itoa(rec.OutputTier), pii, strconv.FormatBool(rec.PIIRedacted),
				reasons, tools, rec.InputHash, rec.OutputHash, rec.PrimaryExplanationCode, rec.PrimaryExplanationReason, rec.PrimaryVersionIdentity,
			})
		}
		cw.Flush()
		return
	}
	writeJSON(w, http.StatusOK, records)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	resp := map[string]interface{}{
		"status": "ok", "evidence_count_today": 0, "cost_today": 0.0, "monthly": 0.0, "active_runs": 0,
		"pending_memory_reviews": 0, "blocked_count": 0, "error_rate": 0.0, "enforcement_mode": "", "tenant_id": tenantID,
	}
	if s.evidenceStore != nil {
		if n, err := s.evidenceStore.CountInRange(r.Context(), tenantID, "", dayStart, dayEnd); err == nil {
			resp["evidence_count_today"] = n
		}
		if cost, err := s.evidenceStore.CostTotal(r.Context(), tenantID, "", dayStart, dayEnd); err == nil {
			resp["cost_today"] = cost
		}
		if cost, err := s.evidenceStore.CostTotal(r.Context(), tenantID, "", monthStart, monthEnd); err == nil {
			resp["monthly"] = cost
		}
		if blocked, err := s.evidenceStore.CountDeniedInRange(r.Context(), tenantID, "", dayStart, dayEnd); err == nil {
			resp["blocked_count"] = blocked
		}
	}
	if s.memoryStore != nil {
		if n, err := s.memoryStore.CountPendingReviewForTenant(r.Context(), tenantID); err == nil {
			resp["pending_memory_reviews"] = n
		}
	}
	if s.metricsCollector != nil {
		snap := s.metricsCollector.Snapshot(r.Context())
		resp["error_rate"] = snap.Summary.ErrorRate
		resp["enforcement_mode"] = snap.EnforcementMode
	}
	if s.activeRunTracker != nil {
		resp["active_runs"] = s.activeRunTracker.Count(tenantID)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCosts(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	daily, _ := s.evidenceStore.CostTotal(r.Context(), tenantID, "", dayStart, dayEnd)
	monthly, _ := s.evidenceStore.CostTotal(r.Context(), tenantID, "", monthStart, monthEnd)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id": tenantID,
		"daily":     daily,
		"monthly":   monthly,
	})
}

func (s *Server) handleCostsBudget(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	dailyUsed, _ := s.evidenceStore.CostTotal(r.Context(), tenantID, "", dayStart, dayEnd)
	monthlyUsed, _ := s.evidenceStore.CostTotal(r.Context(), tenantID, "", monthStart, monthEnd)
	out := map[string]interface{}{
		"tenant_id":    tenantID,
		"daily_used":   dailyUsed,
		"monthly_used": monthlyUsed,
	}
	if s.policy != nil && s.policy.Policies.CostLimits != nil {
		out["daily_limit"] = s.policy.Policies.CostLimits.Daily
		out["monthly_limit"] = s.policy.Policies.CostLimits.Monthly
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCostsReport returns aggregate spend for a time range (for trends/summary). Query params: from, to (RFC3339), tenant_id, agent_id.
func (s *Server) handleCostsReport(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := r.URL.Query().Get("agent_id")
	var from, to time.Time
	if f := r.URL.Query().Get("from"); f != "" {
		from, _ = time.Parse(time.RFC3339, f)
	}
	if t := r.URL.Query().Get("to"); t != "" {
		to, _ = time.Parse(time.RFC3339, t)
	}
	if from.IsZero() {
		from = time.Now().UTC().AddDate(0, 0, -30) // default last 30 days
	}
	if to.IsZero() {
		to = time.Now().UTC()
	}
	total := 0.0
	if s.evidenceStore != nil {
		total, _ = s.evidenceStore.CostTotal(r.Context(), tenantID, agentID, from, to)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id": tenantID,
		"agent_id":  agentID,
		"from":      from.Format(time.RFC3339),
		"to":        to.Format(time.RFC3339),
		"total_eur": total,
	})
}

func (s *Server) handleSecretsList(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	list, err := s.secretsStore.List(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"secrets": list})
}

func (s *Server) handleSecretsAudit(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	secretName := r.URL.Query().Get("secret_name")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	list, err := s.secretsStore.AuditLog(r.Context(), tenantID, secretName, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"audit": list})
}

func (s *Server) handleMemoryList(w http.ResponseWriter, r *http.Request) {
	if s.memoryStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "memory store is disabled")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "agent_id query is required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	entries, err := s.memoryStore.ListIndex(r.Context(), tenantID, agentID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries})
}

func (s *Server) handleMemoryAsOf(w http.ResponseWriter, r *http.Request) {
	if s.memoryStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "memory store is disabled")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := r.URL.Query().Get("agent_id")
	asOfStr := r.URL.Query().Get("as_of")
	if agentID == "" || asOfStr == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "agent_id and as_of (RFC3339) are required")
		return
	}
	asOf, err := time.Parse(time.RFC3339, asOfStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "as_of must be RFC3339: "+err.Error())
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	entries, err := s.memoryStore.AsOf(r.Context(), tenantID, agentID, asOf, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries})
}

func (s *Server) handleMemorySearch(w http.ResponseWriter, r *http.Request) {
	if s.memoryStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "memory store is disabled")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := r.URL.Query().Get("agent_id")
	q := r.URL.Query().Get("q")
	if agentID == "" || q == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "agent_id and q are required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	entries, err := s.memoryStore.Search(r.Context(), tenantID, agentID, q, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries})
}

func (s *Server) handleMemoryGet(w http.ResponseWriter, r *http.Request) {
	if s.memoryStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "memory store is disabled")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	entry, err := s.memoryStore.Get(r.Context(), tenantID, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) handleMemoryReview(w http.ResponseWriter, r *http.Request) {
	if s.memoryStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "memory store is disabled")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := chi.URLParam(r, "agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "agent_id is required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	entries, err := s.memoryStore.ListPendingReview(r.Context(), tenantID, agentID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries})
}

func (s *Server) handleMemoryApprove(w http.ResponseWriter, r *http.Request) {
	if s.memoryStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "memory store is disabled")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := chi.URLParam(r, "agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "agent_id is required")
		return
	}
	var req struct {
		EntryID    string `json:"entry_id"`
		ReviewedBy string `json:"reviewed_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	if req.EntryID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "entry_id is required")
		return
	}
	err := s.memoryStore.UpdateReviewStatus(r.Context(), tenantID, agentID, req.EntryID, "approved")
	if err != nil {
		if errors.Is(err, memory.ErrEntryNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "memory entry not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handleTriggersList(w http.ResponseWriter, r *http.Request) {
	names := []string{}
	if s.policy != nil && s.policy.Triggers != nil {
		for _, w := range s.policy.Triggers.Webhooks {
			names = append(names, w.Name)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"triggers": names})
}

func (s *Server) handleTriggerHistory(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	invocationType := "webhook:" + name
	entries, err := s.evidenceStore.ListIndex(r.Context(), tenantID, "", time.Time{}, time.Time{}, 50, invocationType, "", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if entries == nil {
		entries = []evidence.Index{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries})
}

func (s *Server) handlePlansPending(w http.ResponseWriter, r *http.Request) {
	if s.planReviewStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "plan review is disabled")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	plans, err := s.planReviewStore.GetPending(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"plans": plans})
}

// handleDenialsByReason returns denial counts by reason (policy_deny, attachment_block, tool_filtered, pii_block) for the dashboard Governance widget.
func (s *Server) handleDenialsByReason(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	var from, to time.Time
	if f := r.URL.Query().Get("from"); f != "" {
		from, _ = time.Parse(time.RFC3339, f)
	}
	if t := r.URL.Query().Get("to"); t != "" {
		to, _ = time.Parse(time.RFC3339, t)
	}
	if s.evidenceStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"total": 0, "by_reason": map[string]int{}})
		return
	}
	total, byReason, err := s.evidenceStore.DenialsByReason(r.Context(), tenantID, from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"total": total, "by_reason": byReason})
}

// handleGovernanceAlerts returns recent tool_filtered and attachment_injection events for the Governance widget.
//
//nolint:dupl // similar to handleReviewHistory but different store and response
func (s *Server) handleGovernanceAlerts(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	if s.evidenceStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"alerts": []interface{}{}})
		return
	}
	alerts, err := s.evidenceStore.ListGovernanceAlerts(r.Context(), tenantID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"alerts": alerts})
}

// handleAuditPack returns a JSON audit pack (date range, evidence summary, plan stats, memory reviews, cost) for one-click export.
func (s *Server) handleAuditPack(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	from, to := dayStart, dayEnd
	if f := r.URL.Query().Get("from"); f != "" {
		from, _ = time.Parse(time.RFC3339, f)
	}
	if t := r.URL.Query().Get("to"); t != "" {
		to, _ = time.Parse(time.RFC3339, t)
	}
	out := map[string]interface{}{
		"tenant_id":              tenantID,
		"from":                   from.Format(time.RFC3339),
		"to":                     to.Format(time.RFC3339),
		"generated_at":           time.Now().UTC().Format(time.RFC3339),
		"evidence_count":         0,
		"cost_eur":               0.0,
		"pending_plans":          0,
		"pending_memory_reviews": 0,
	}
	if s.evidenceStore != nil {
		n, _ := s.evidenceStore.CountInRange(r.Context(), tenantID, "", from, to)
		out["evidence_count"] = n
		cost, _ := s.evidenceStore.CostTotal(r.Context(), tenantID, "", from, to)
		out["cost_eur"] = cost
	}
	if s.planReviewStore != nil {
		pending, _ := s.planReviewStore.GetPending(r.Context(), tenantID)
		out["pending_plans"] = len(pending)
	}
	if s.memoryStore != nil {
		n, _ := s.memoryStore.CountPendingReviewForTenant(r.Context(), tenantID)
		out["pending_memory_reviews"] = n
	}
	w.Header().Set("Content-Disposition", `attachment; filename="talon-audit-pack.json"`)
	writeJSON(w, http.StatusOK, out)
}

// handleReviewHistory returns recent plan review history (who, when, approve/reject) for the dashboard.
//
//nolint:dupl // similar to handleGovernanceAlerts but different store and response
func (s *Server) handleReviewHistory(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	if s.planReviewStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"reviews": []interface{}{}})
		return
	}
	reviews, err := s.planReviewStore.ListReviewed(r.Context(), tenantID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if reviews == nil {
		reviews = []agent.ReviewHistoryEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"reviews": reviews})
}

// handleTenantsSummary returns tenant and agent aggregates for the unified dashboard Tenants & Agents tab.
// Response: { tenants: [{ tenant_id, request_volume, spend_today, spend_month, denials, pending_plans }], agents: [{ tenant_id, agent_id, requests, cost_eur, blocked, last_run }] }.
func (s *Server) handleTenantsSummary(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	var tenants []evidence.TenantSummary
	if s.evidenceStore != nil {
		var err error
		tenants, err = s.evidenceStore.TenantsSummary(r.Context(), dayStart, dayEnd, monthStart, monthEnd, tenantID)
		if err != nil {
			log.Warn().Err(err).Msg("tenants summary")
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}

	pendingByTenant := make(map[string]int)
	if s.planReviewStore != nil {
		pending, err := s.planReviewStore.GetPending(r.Context(), "")
		if err == nil {
			for _, p := range pending {
				if p != nil {
					pendingByTenant[p.TenantID]++
				}
			}
		}
	}

	tenantResp := make([]map[string]interface{}, 0, len(tenants))
	for _, t := range tenants {
		tenantResp = append(tenantResp, map[string]interface{}{
			"tenant_id":      t.TenantID,
			"request_volume": t.RequestVolume,
			"spend_today":    t.SpendToday,
			"spend_month":    t.SpendMonth,
			"denials":        t.Denials,
			"pending_plans":  pendingByTenant[t.TenantID],
		})
	}

	var agents []evidence.AgentSummary
	if s.evidenceStore != nil {
		var err error
		agents, err = s.evidenceStore.AgentsSummary(r.Context(), monthStart, monthEnd, tenantID)
		if err != nil {
			log.Warn().Err(err).Msg("agents summary")
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenants": tenantResp,
		"agents":  agents,
	})
}

// handleAgentHealth returns per-agent risk-oriented health rows for fleet operations.
func (s *Server) handleAgentHealth(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	if s.evidenceStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"agents": []interface{}{}})
		return
	}
	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	rows, err := s.evidenceStore.AgentHealthSummary(r.Context(), from, now, tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"agents": rows})
}

func (s *Server) handleDriftSignals(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	if s.evidenceStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"agents": []interface{}{}})
		return
	}
	analyzer := drift.NewAnalyzer(s.evidenceStore)
	rows, err := analyzer.ComputeSignals(r.Context(), tenantID, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	for _, row := range rows {
		for _, sig := range row.Signals {
			drift.RecordSignal(r.Context(), row.AgentID, sig)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"agents": rows})
}

func (s *Server) handlePlanGet(w http.ResponseWriter, r *http.Request) {
	if s.planReviewStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "plan review is disabled")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	plan, err := s.planReviewStore.Get(r.Context(), id, tenantID)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "plan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handlePlanApprove(w http.ResponseWriter, r *http.Request) {
	if s.planReviewStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "plan review is disabled")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	var req struct {
		ReviewedBy string `json:"reviewed_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	if rec, err := s.resolveApproverFromRequest(r.Context(), r); err == nil && rec != nil {
		if !s.approverRoleAllowed(rec.Role) {
			writeError(w, http.StatusForbidden, "forbidden", "approver role not allowed by policy approval_chain")
			return
		}
		req.ReviewedBy = rec.Name
	}
	plan, err := s.planReviewStore.Get(r.Context(), id, tenantID)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "plan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	err = s.planReviewStore.Approve(r.Context(), id, tenantID, req.ReviewedBy)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "plan not found")
			return
		}
		if errors.Is(err, agent.ErrPlanNotPending) {
			writeError(w, http.StatusConflict, "conflict", "plan is not pending")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.recordPlanReviewEvidence(r.Context(), plan, "plan_approved", req.ReviewedBy, "", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handlePlanReject(w http.ResponseWriter, r *http.Request) {
	if s.planReviewStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "plan review is disabled")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	var req struct {
		ReviewedBy string `json:"reviewed_by"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	if rec, err := s.resolveApproverFromRequest(r.Context(), r); err == nil && rec != nil {
		if !s.approverRoleAllowed(rec.Role) {
			writeError(w, http.StatusForbidden, "forbidden", "approver role not allowed by policy approval_chain")
			return
		}
		req.ReviewedBy = rec.Name
	}
	plan, err := s.planReviewStore.Get(r.Context(), id, tenantID)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "plan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	err = s.planReviewStore.Reject(r.Context(), id, tenantID, req.ReviewedBy, req.Reason)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "plan not found")
			return
		}
		if errors.Is(err, agent.ErrPlanNotPending) {
			writeError(w, http.StatusConflict, "conflict", "plan is not pending")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.recordPlanReviewEvidence(r.Context(), plan, "plan_rejected", req.ReviewedBy, req.Reason, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

func (s *Server) handlePlanModify(w http.ResponseWriter, r *http.Request) {
	if s.planReviewStore == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "plan review is disabled")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "default"
	}
	var req struct {
		ReviewedBy  string             `json:"reviewed_by"`
		Annotations []agent.Annotation `json:"annotations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	if rec, err := s.resolveApproverFromRequest(r.Context(), r); err == nil && rec != nil {
		if !s.approverRoleAllowed(rec.Role) {
			writeError(w, http.StatusForbidden, "forbidden", "approver role not allowed by policy approval_chain")
			return
		}
		req.ReviewedBy = rec.Name
	}
	plan, err := s.planReviewStore.Get(r.Context(), id, tenantID)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "plan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	err = s.planReviewStore.Modify(r.Context(), id, tenantID, req.ReviewedBy, req.Annotations)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "plan not found")
			return
		}
		if errors.Is(err, agent.ErrPlanNotPending) {
			writeError(w, http.StatusConflict, "conflict", "plan is not pending")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.recordPlanReviewEvidence(r.Context(), plan, "plan_modified", req.ReviewedBy, "", req.Annotations)
	writeJSON(w, http.StatusOK, map[string]string{"status": "modified"})
}

func (s *Server) recordPlanReviewEvidence(ctx context.Context, plan *agent.ExecutionPlan, eventType, reviewedBy, reason string, annotations []agent.Annotation) {
	if s.evidenceStore == nil || plan == nil {
		return
	}
	gen := evidence.NewGenerator(s.evidenceStore)
	if _, err := gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  plan.CorrelationID,
		SessionID:      plan.SessionID,
		TenantID:       plan.TenantID,
		AgentID:        plan.AgentID,
		InvocationType: "plan_review",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  eventType,
			Reasons: []string{"human_oversight"},
		},
		Classification:        evidence.Classification{},
		InputPrompt:           eventType + ":" + plan.ID,
		OutputResponse:        reviewedBy,
		Compliance:            evidence.Compliance{},
		ModelRoutingRationale: "plan_review",
		PlanReview: &evidence.PlanReviewEvent{
			PlanID:          plan.ID,
			EventType:       eventType,
			ReviewedBy:      reviewedBy,
			PreviousStatus:  string(plan.Status),
			Reason:          reason,
			AnnotationCount: len(annotations),
		},
	}); err != nil {
		log.Warn().Err(err).Str("plan_id", plan.ID).Msg("recording_plan_review_evidence")
	}
}

func (s *Server) handlePoliciesList(w http.ResponseWriter, r *http.Request) {
	if s.policy == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"policies": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":   s.policy.Agent,
		"version": s.policy.VersionTag,
		"hash":    s.policy.Hash,
	})
}

func (s *Server) handlePoliciesEvaluate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Input map[string]interface{} `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	if s.policyEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "disabled", "policy engine not available")
		return
	}
	decision, err := s.policyEngine.Evaluate(r.Context(), req.Input)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if s.dashboardHTML == "" {
		writeError(w, http.StatusNotFound, "not_found", "dashboard not configured")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: dashboard HTML is embedded at build time (web.DashboardHTML), not user-controlled
	_, _ = w.Write([]byte(s.dashboardHTML))
}

func (s *Server) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	if s.sessionStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session store not available"})
		return
	}
	id := chi.URLParam(r, "id")
	sess, err := s.sessionStore.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) handleSessionList(w http.ResponseWriter, r *http.Request) {
	if s.sessionStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session store not available"})
		return
	}
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = "default"
	}
	status := session.Status(r.URL.Query().Get("status"))
	sessions, err := s.sessionStore.ListByTenant(r.Context(), tenantID, status)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleSessionComplete(w http.ResponseWriter, r *http.Request) {
	if s.sessionStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session store not available"})
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.sessionStore.Complete(r.Context(), id, 0, 0); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "completed", "session_id": id})
}

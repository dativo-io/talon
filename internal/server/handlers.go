package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/memory"
)

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
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
	TenantID  string `json:"tenant_id"`
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Prompt    string `json:"prompt"`
	DryRun    bool   `json:"dry_run"`
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
		InvocationType: "api",
		PolicyPath:     s.policyPath,
		DryRun:         req.DryRun,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	resp, err := s.runner.Run(ctx, runReq)
	if err != nil {
		log.Error().Err(err).Str("tenant_id", tenantID).Str("agent_name", agentName).Msg("agent_run_error")
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if !resp.PolicyAllow {
		writeError(w, http.StatusForbidden, "policy_denied", resp.DenyReason)
		return
	}
	if resp.PlanPending != "" {
		writeJSON(w, http.StatusAccepted, map[string]string{
			"plan_pending": resp.PlanPending,
			"message":      "Execution pending human review",
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
	})
}

//nolint:gocyclo // handler branches on request validation and response shaping
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		AgentID  string `json:"agent_id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
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
		writeError(w, http.StatusBadRequest, "invalid_request", "no user message content in messages")
		return
	}
	runReq := &agent.RunRequest{
		TenantID:       tenantID,
		AgentName:      agentName,
		Prompt:         prompt,
		InvocationType: "http",
		PolicyPath:     s.policyPath,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	resp, err := s.runner.Run(ctx, runReq)
	if err != nil {
		log.Error().Err(err).Str("tenant_id", tenantID).Msg("chat_completions_run_error")
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if !resp.PolicyAllow {
		writeError(w, http.StatusForbidden, "policy_denied", resp.DenyReason)
		return
	}
	if resp.PlanPending != "" {
		writeJSON(w, http.StatusAccepted, map[string]string{
			"error":   "plan_pending",
			"message": "plan pending human review: " + resp.PlanPending,
		})
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
	entries, err := s.evidenceStore.ListIndex(r.Context(), tenantID, agentID, from, to, limit)
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
	ev, err := s.evidenceStore.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) handleEvidenceVerify(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	valid, err := s.evidenceStore.Verify(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
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
		_ = cw.Write([]string{"id", "timestamp", "tenant_id", "agent_id", "invocation_type", "allowed", "cost", "model_used", "duration_ms", "has_error", "input_tier", "output_tier", "pii_detected", "pii_redacted", "policy_reasons", "tools_called", "input_hash", "output_hash"})
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
				reasons, tools, rec.InputHash, rec.OutputHash,
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
	resp := map[string]interface{}{"status": "ok", "evidence_count_today": 0, "cost_today": 0.0, "monthly": 0.0, "active_runs": 0}
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
	secretName := r.URL.Query().Get("secret_name")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	list, err := s.secretsStore.AuditLog(r.Context(), secretName, limit)
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
	entries, err := s.evidenceStore.ListIndex(r.Context(), tenantID, "", time.Time{}, time.Time{}, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	filtered := make([]evidence.Index, 0)
	for i := range entries {
		if entries[i].InvocationType == invocationType {
			filtered = append(filtered, entries[i])
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": filtered})
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
	plan, err := s.planReviewStore.Get(r.Context(), id)
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
	var req struct {
		ReviewedBy string `json:"reviewed_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	err := s.planReviewStore.Approve(r.Context(), id, req.ReviewedBy)
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
	var req struct {
		ReviewedBy string `json:"reviewed_by"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	err := s.planReviewStore.Reject(r.Context(), id, req.ReviewedBy, req.Reason)
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
	var req struct {
		ReviewedBy  string             `json:"reviewed_by"`
		Annotations []agent.Annotation `json:"annotations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON: "+err.Error())
		return
	}
	err := s.planReviewStore.Modify(r.Context(), id, req.ReviewedBy, req.Annotations)
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "modified"})
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

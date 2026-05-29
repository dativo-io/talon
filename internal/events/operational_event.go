package events

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
)

// OperationalEvent is the stable, minimal runtime projection used by UI/API/CLI.
type OperationalEvent struct {
	EventID        string    `json:"event_id"`
	EvidenceID     string    `json:"evidence_id"`
	CorrelationID  string    `json:"correlation_id,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	TenantID       string    `json:"tenant_id"`
	Caller         string    `json:"caller,omitempty"`
	AgentID        string    `json:"agent_id,omitempty"`
	InvocationType string    `json:"invocation_type,omitempty"`
	Decision       string    `json:"decision"`
	Allowed        bool      `json:"allowed"`
	ReasonCode     string    `json:"reason_code,omitempty"`
	ReasonText     string    `json:"reason_text,omitempty"`
	SuggestedFix   string    `json:"suggested_fix,omitempty"`
	CostEUR        float64   `json:"cost_eur"`
	Model          string    `json:"model,omitempty"`
	DurationMS     int64     `json:"duration_ms"`
	HasError       bool      `json:"has_error"`
	PIIDetected    []string  `json:"pii_detected,omitempty"`
	ToolsFiltered  []string  `json:"tools_filtered,omitempty"`
	CacheHit       bool      `json:"cache_hit,omitempty"`
	CostSaved      float64   `json:"cost_saved,omitempty"`
	PrimaryCode    string    `json:"primary_explanation_code,omitempty"`
	PrimaryReason  string    `json:"primary_explanation_reason,omitempty"`
}

// EventIDFromEvidence creates a deterministic monotonic id: unixMilli-evidenceID.
func EventIDFromEvidence(ts time.Time, evidenceID string) string {
	return fmt.Sprintf("%d-%s", ts.UTC().UnixMilli(), evidenceID)
}

// FromEvidence projects an evidence record into an operational event.
func FromEvidence(ev *evidence.Evidence) OperationalEvent {
	out := OperationalEvent{
		EventID:        EventIDFromEvidence(ev.Timestamp, ev.ID),
		EvidenceID:     ev.ID,
		CorrelationID:  ev.CorrelationID,
		Timestamp:      ev.Timestamp.UTC(),
		TenantID:       ev.TenantID,
		Caller:         firstNonEmpty(ev.RequestSourceID, ev.AgentID),
		AgentID:        ev.AgentID,
		InvocationType: ev.InvocationType,
		Allowed:        ev.PolicyDecision.Allowed,
		CostEUR:        ev.Execution.Cost,
		Model:          ev.Execution.ModelUsed,
		DurationMS:     ev.Execution.DurationMS,
		HasError:       ev.Execution.Error != "",
		PIIDetected:    append([]string(nil), ev.Classification.PIIDetected...),
		CacheHit:       ev.CacheHit,
		CostSaved:      ev.CostSaved,
	}
	if ev.ToolGovernance != nil {
		out.ToolsFiltered = append([]string(nil), ev.ToolGovernance.ToolsFiltered...)
	}
	out.Decision, out.ReasonCode, out.ReasonText, out.SuggestedFix = decisionFields(ev)
	if decision, code, text, fix, ok := decisionFromExplanation(ev); ok {
		out.Decision, out.ReasonCode, out.ReasonText, out.SuggestedFix = decision, code, text, fix
	}
	out.PrimaryCode, out.PrimaryReason = primaryExplanation(ev)
	if out.ReasonCode == "" {
		out.ReasonCode = out.PrimaryCode
	}
	if out.ReasonText == "" {
		out.ReasonText = out.PrimaryReason
	}
	out.ReasonText = sanitizeReasonText(out.ReasonText)
	out.PIIDetected = sanitizeSignals(out.PIIDetected)
	out.ToolsFiltered = sanitizeSignals(out.ToolsFiltered)
	return out
}

// SortDesc sorts events newest-first with deterministic tie-break.
func SortDesc(events []OperationalEvent) {
	sort.Slice(events, func(i, j int) bool {
		return LessDesc(events[i], events[j])
	})
}

// LessDesc returns true if a should sort before b.
func LessDesc(a, b OperationalEvent) bool {
	if a.Timestamp.Equal(b.Timestamp) {
		return a.EvidenceID > b.EvidenceID
	}
	return a.Timestamp.After(b.Timestamp)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func primaryExplanation(ev *evidence.Evidence) (code string, reason string) {
	item, ok := explanation.Primary(ev.Explanations)
	if !ok {
		return "", ""
	}
	return item.Code, item.Reason
}

func decisionFromExplanation(ev *evidence.Evidence) (decision, reasonCode, reasonText, suggestedFix string, ok bool) {
	item, ok := explanation.Primary(ev.Explanations)
	if !ok {
		return "", "", "", "", false
	}
	reasonCode = item.Code
	reasonText = item.Reason
	suggestedFix = item.Fix

	hasFilteredTools := ev.ToolGovernance != nil && len(ev.ToolGovernance.ToolsFiltered) > 0
	hasRedaction := ev.Classification.PIIRedacted || ev.Classification.OutputPIIDetected

	switch item.Decision {
	case explanation.DecisionFailure:
		decision = "error"
	case explanation.DecisionDeny:
		decision = "blocked"
	case explanation.DecisionFilter:
		decision = projectedAllowDecision(hasFilteredTools, true)
	case explanation.DecisionModify:
		decision = projectedAllowDecision(hasFilteredTools, hasRedaction)
	default:
		decision = projectedAllowDecision(hasFilteredTools, hasRedaction)
	}

	return decision, reasonCode, reasonText, suggestedFix, true
}

func projectedAllowDecision(hasFilteredTools bool, hasRedaction bool) string {
	switch {
	case hasFilteredTools:
		return "filtered_tool"
	case hasRedaction:
		return "redacted"
	default:
		return "allowed"
	}
}

func decisionFields(ev *evidence.Evidence) (decision, reasonCode, reasonText, suggestedFix string) {
	if ev.Execution.Error != "" {
		return "error", "EXECUTION_ERROR", "Execution failed", ""
	}
	if !ev.PolicyDecision.Allowed {
		code, text := codeFromReasons(ev.PolicyDecision.Reasons)
		fix := fixFromCode(code)
		return "blocked", code, text, fix
	}
	if ev.Classification.PIIRedacted || ev.Classification.OutputPIIDetected {
		return "redacted", "PII_REDACTED", "PII was redacted by policy", ""
	}
	if ev.ToolGovernance != nil && len(ev.ToolGovernance.ToolsFiltered) > 0 {
		return "filtered_tool", "TOOL_FILTERED", "Request tools were filtered by policy", ""
	}
	return "allowed", "ALLOWED", "Request allowed", ""
}

func codeFromReasons(reasons []string) (code string, text string) {
	if len(reasons) == 0 {
		return "POLICY_DENIED", "Request denied by policy"
	}
	raw := strings.TrimSpace(reasons[0])
	if raw == "" {
		return "POLICY_DENIED", "Request denied by policy"
	}
	upper := strings.ToUpper(raw)
	switch {
	case strings.Contains(upper, "IBAN"):
		return "PII_IBAN", raw
	case strings.Contains(upper, "PII"):
		return "PII_DETECTED", raw
	case strings.Contains(upper, "BUDGET"):
		return "BUDGET_EXCEEDED", raw
	case strings.Contains(upper, "MODEL"):
		return "POLICY_MODEL_DENIED", raw
	default:
		return "POLICY_DENIED", raw
	}
}

func fixFromCode(code string) string {
	switch code {
	case "PII_IBAN", "PII_DETECTED":
		return "Mask or remove sensitive data before sending the request."
	case "POLICY_MODEL_DENIED":
		return "Use a model allowed by current policy tier."
	case "BUDGET_EXCEEDED":
		return "Reduce request volume or update budget limits."
	default:
		return ""
	}
}

func sanitizeReasonText(in string) string {
	s := strings.Join(strings.Fields(strings.TrimSpace(in)), " ")
	if len(s) > 220 {
		return s[:220]
	}
	return s
}

func sanitizeSignals(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

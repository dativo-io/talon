// Package evidence provides export-oriented records for audit trail (CSV/JSON).
// ExportRecord includes classification and audit-trail fields for compliance exports.
package evidence

import (
	"strings"
	"time"
)

// ExportRecord is a single evidence record with all fields needed for compliance export.
// Used by `talon audit export --format csv|json`. Backward-compatible: original index
// columns first, then classification and audit-trail fields at the end.
type ExportRecord struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	TenantID       string    `json:"tenant_id"`
	AgentID        string    `json:"agent_id"`
	InvocationType string    `json:"invocation_type"`
	Allowed        bool      `json:"allowed"`
	Cost           float64   `json:"cost"`
	ModelUsed      string    `json:"model_used"`
	DurationMS     int64     `json:"duration_ms"`
	HasError       bool      `json:"has_error"`
	// Classification (enriched export)
	InputTier     int      `json:"input_tier"`
	OutputTier    int      `json:"output_tier"`
	PIIDetected   []string `json:"pii_detected,omitempty"`
	PIIRedacted   bool     `json:"pii_redacted"`
	PolicyReasons []string `json:"policy_reasons,omitempty"`
	ToolsCalled   []string `json:"tools_called,omitempty"`
	InputHash     string   `json:"input_hash,omitempty"`
	OutputHash    string   `json:"output_hash,omitempty"`
}

// ToExportRecord builds an ExportRecord from a full Evidence.
// Used when exporting from store.List() (single SQL scan of evidence_json).
func ToExportRecord(e *Evidence) ExportRecord {
	rec := ExportRecord{
		ID:             e.ID,
		Timestamp:      e.Timestamp,
		TenantID:       e.TenantID,
		AgentID:        e.AgentID,
		InvocationType: e.InvocationType,
		Allowed:        e.PolicyDecision.Allowed,
		Cost:           e.Execution.Cost,
		ModelUsed:      e.Execution.ModelUsed,
		DurationMS:     e.Execution.DurationMS,
		HasError:       e.Execution.Error != "",
		InputTier:      e.Classification.InputTier,
		OutputTier:     e.Classification.OutputTier,
		PIIDetected:    append([]string(nil), e.Classification.PIIDetected...),
		PIIRedacted:    e.Classification.PIIRedacted,
		InputHash:      e.AuditTrail.InputHash,
		OutputHash:     e.AuditTrail.OutputHash,
	}
	if len(e.PolicyDecision.Reasons) > 0 {
		rec.PolicyReasons = append([]string(nil), e.PolicyDecision.Reasons...)
	}
	if len(e.Execution.ToolsCalled) > 0 {
		rec.ToolsCalled = append([]string(nil), e.Execution.ToolsCalled...)
	}
	return rec
}

// PIIDetectedCSV returns comma-separated PII types for CSV export.
func (r *ExportRecord) PIIDetectedCSV() string {
	return strings.Join(r.PIIDetected, ",")
}

// PolicyReasonsCSV returns comma-separated policy reasons for CSV export.
func (r *ExportRecord) PolicyReasonsCSV() string {
	return strings.Join(r.PolicyReasons, ",")
}

// ToolsCalledCSV returns comma-separated tool names for CSV export.
func (r *ExportRecord) ToolsCalledCSV() string {
	return strings.Join(r.ToolsCalled, ",")
}

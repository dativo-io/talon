// Package evidence provides export-oriented records for audit trail (CSV/JSON/NDJSON).
// ExportRecord includes classification, shadow violation, and audit-trail fields for compliance exports.
package evidence

import (
	"strings"
	"time"
)

// ExportRecord is a single evidence record with all fields needed for compliance export.
// Used by `talon audit export --format csv|json|ndjson`. Backward-compatible: original index
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
	// Shadow mode fields
	ObservationModeOverride bool     `json:"observation_mode_override"`
	ShadowViolationTypes    []string `json:"shadow_violation_types,omitempty"`
}

// ExportMetadata wraps JSON export with context about the export run.
type ExportMetadata struct {
	GeneratedAt  time.Time    `json:"generated_at"`
	TalonVersion string       `json:"talon_version"`
	Filter       ExportFilter `json:"filter"`
	TotalRecords int          `json:"total_records"`
}

// ExportFilter describes the filter criteria used during export.
type ExportFilter struct {
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Tenant string `json:"tenant,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Caller string `json:"caller,omitempty"`
}

// ExportEnvelope wraps records with metadata for --format json.
type ExportEnvelope struct {
	ExportMetadata ExportMetadata `json:"export_metadata"`
	Records        []ExportRecord `json:"records"`
}

// ToExportRecord builds an ExportRecord from a full Evidence.
// Used when exporting from store.List() (single SQL scan of evidence_json).
func ToExportRecord(e *Evidence) ExportRecord {
	rec := ExportRecord{
		ID:                      e.ID,
		Timestamp:               e.Timestamp,
		TenantID:                e.TenantID,
		AgentID:                 e.AgentID,
		InvocationType:          e.InvocationType,
		Allowed:                 e.PolicyDecision.Allowed,
		Cost:                    e.Execution.Cost,
		ModelUsed:               e.Execution.ModelUsed,
		DurationMS:              e.Execution.DurationMS,
		HasError:                e.Execution.Error != "",
		InputTier:               e.Classification.InputTier,
		OutputTier:              e.Classification.OutputTier,
		PIIDetected:             append([]string(nil), e.Classification.PIIDetected...),
		PIIRedacted:             e.Classification.PIIRedacted,
		InputHash:               e.AuditTrail.InputHash,
		OutputHash:              e.AuditTrail.OutputHash,
		ObservationModeOverride: e.ObservationModeOverride,
	}
	if len(e.PolicyDecision.Reasons) > 0 {
		rec.PolicyReasons = append([]string(nil), e.PolicyDecision.Reasons...)
	}
	if len(e.Execution.ToolsCalled) > 0 {
		rec.ToolsCalled = append([]string(nil), e.Execution.ToolsCalled...)
	}
	for _, sv := range e.ShadowViolations {
		rec.ShadowViolationTypes = append(rec.ShadowViolationTypes, sv.Type)
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

// ShadowViolationTypesCSV returns comma-separated shadow violation types for CSV export.
func (r *ExportRecord) ShadowViolationTypesCSV() string {
	return strings.Join(r.ShadowViolationTypes, ",")
}

// Package evidence provides export-oriented records for audit trail (CSV/JSON/NDJSON).
// ExportRecord includes classification, shadow violation, and audit-trail fields for compliance exports.
package evidence

import (
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/explanation"
)

// ExportRecord is a single evidence record with all fields needed for compliance export.
// Used by `talon audit export --format csv|json|ndjson`. Backward-compatible: original index
// columns first, then classification and audit-trail fields at the end.
type ExportRecord struct {
	ID             string    `json:"id"`
	SessionID      string    `json:"session_id,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	TenantID       string    `json:"tenant_id"`
	AgentID        string    `json:"agent_id"`
	InvocationType string    `json:"invocation_type"`
	Allowed        bool      `json:"allowed"`
	Cost           float64   `json:"cost"`
	ModelUsed      string    `json:"model_used"`
	Provider       string    `json:"provider,omitempty"`
	InputTokens    int       `json:"input_tokens,omitempty"`
	OutputTokens   int       `json:"output_tokens,omitempty"`
	PolicyAction   string    `json:"policy_action,omitempty"`
	DurationMS     int64     `json:"duration_ms"`
	HasError       bool      `json:"has_error"`
	// Classification (enriched export)
	InputTier        int      `json:"input_tier"`
	OutputTier       int      `json:"output_tier"`
	PIIDetected      []string `json:"pii_detected,omitempty"`
	PIIRedacted      bool     `json:"pii_redacted"`
	InputPIIRedacted bool     `json:"input_pii_redacted,omitempty"`
	PolicyReasons    []string `json:"policy_reasons,omitempty"`
	ToolsCalled      []string `json:"tools_called,omitempty"`
	InputHash        string   `json:"input_hash,omitempty"`
	OutputHash       string   `json:"output_hash,omitempty"`
	// Shadow mode fields
	ObservationModeOverride bool     `json:"observation_mode_override"`
	ShadowViolationTypes    []string `json:"shadow_violation_types,omitempty"`
	// Semantic cache (audit export)
	CacheHit                 bool     `json:"cache_hit,omitempty"`
	CacheEntryID             string   `json:"cache_entry_id,omitempty"`
	CacheSimilarity          float64  `json:"cache_similarity,omitempty"`
	CostSaved                float64  `json:"cost_saved,omitempty"`
	UpstreamAuthMode         string   `json:"upstream_auth_mode,omitempty"`
	UpstreamKeySource        string   `json:"upstream_key_source,omitempty"`
	UpstreamKeyFingerprint   string   `json:"upstream_key_fingerprint,omitempty"`
	GatewayAnnotations       []string `json:"gateway_annotations,omitempty"`
	PrimaryExplanationCode   string   `json:"primary_explanation_code,omitempty"`
	PrimaryExplanationReason string   `json:"primary_explanation_reason,omitempty"`
	PrimaryVersionIdentity   string   `json:"primary_version_identity,omitempty"`
	// Data-flow summary (trailing, backward-compatible): deduped+sorted
	// destinations ("kind:name"), regions, and classified entity types.
	FlowDestinations []string `json:"flow_destinations,omitempty"`
	FlowRegions      []string `json:"flow_regions,omitempty"`
	FlowEntityTypes  []string `json:"flow_entity_types,omitempty"`
	// Scanner engine attribution (trailing, backward-compatible): which PII
	// scan engine produced the classification, and the typed failure kind
	// when a scanner failure drove a fail-closed block (#181).
	ScannerEngine  string `json:"scanner_engine,omitempty"`
	ScannerType    string `json:"scanner_type,omitempty"`
	ScannerVersion string `json:"scanner_version,omitempty"`
	ScannerFailure string `json:"scanner_failure,omitempty"`
	// Tool-content observation (trailing, backward-compatible): the
	// evidence-only PII scan of tool-related request content (#212).
	// Scanned is a pointer so "scanned": false (scanner error — content went
	// out unscanned) survives omitempty; nil = scan not performed.
	ToolContentScanned     *bool    `json:"tool_content_scanned,omitempty"`
	ToolContentHasPII      bool     `json:"tool_content_has_pii,omitempty"`
	ToolContentEntityTypes []string `json:"tool_content_entity_types,omitempty"`
	ToolContentEntityCount int      `json:"tool_content_entity_count,omitempty"`
	// Orchestration identity (trailing, backward-compatible): client-asserted
	// session/subagent attribution observed by the gateway (#194, spec 1.6).
	// session_id itself is already a first-class column above.
	OrchAgentID       string `json:"orch_agent_id,omitempty"`
	OrchParentAgentID string `json:"orch_parent_agent_id,omitempty"`
	OrchClient        string `json:"orch_client,omitempty"`
	OrchSessionSource string `json:"orch_session_source,omitempty"`
}

// ExportMetadata wraps JSON export with context about the export run.
type ExportMetadata struct {
	GeneratedAt  time.Time    `json:"generated_at"`
	TalonVersion string       `json:"talon_version"`
	Filter       ExportFilter `json:"filter"`
	TotalRecords int          `json:"total_records"`
	Algorithm    string       `json:"algorithm,omitempty"`
	Signed       bool         `json:"signed,omitempty"`
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
		SessionID:               e.SessionID,
		Timestamp:               e.Timestamp,
		TenantID:                e.TenantID,
		AgentID:                 e.AgentID,
		InvocationType:          e.InvocationType,
		Allowed:                 e.PolicyDecision.Allowed,
		Cost:                    e.Execution.Cost,
		ModelUsed:               e.Execution.ModelUsed,
		InputTokens:             e.Execution.Tokens.Input,
		OutputTokens:            e.Execution.Tokens.Output,
		PolicyAction:            e.PolicyDecision.Action,
		DurationMS:              e.Execution.DurationMS,
		HasError:                e.Execution.Error != "",
		InputTier:               e.Classification.InputTier,
		OutputTier:              e.Classification.OutputTier,
		PIIDetected:             append([]string(nil), e.Classification.PIIDetected...),
		PIIRedacted:             e.Classification.PIIRedacted,
		InputPIIRedacted:        e.Classification.InputPIIRedacted,
		InputHash:               e.AuditTrail.InputHash,
		OutputHash:              e.AuditTrail.OutputHash,
		ObservationModeOverride: e.ObservationModeOverride,
		CacheHit:                e.CacheHit,
		CacheEntryID:            e.CacheEntryID,
		CacheSimilarity:         e.CacheSimilarity,
		CostSaved:               e.CostSaved,
		UpstreamAuthMode:        e.UpstreamAuthMode,
		UpstreamKeySource:       e.UpstreamKeySource,
		UpstreamKeyFingerprint:  e.UpstreamKeyFingerprint,
		GatewayAnnotations:      append([]string(nil), e.GatewayAnnotations...),
	}
	if len(e.PolicyDecision.Reasons) > 0 {
		rec.PolicyReasons = append([]string(nil), e.PolicyDecision.Reasons...)
	}
	if e.RoutingDecision != nil {
		rec.Provider = e.RoutingDecision.SelectedProvider
	}
	if len(e.Execution.ToolsCalled) > 0 {
		rec.ToolsCalled = append([]string(nil), e.Execution.ToolsCalled...)
	}
	if primary, ok := explanation.Primary(e.Explanations); ok {
		rec.PrimaryExplanationCode = primary.Code
		rec.PrimaryExplanationReason = primary.Reason
		rec.PrimaryVersionIdentity = primary.VersionIdentity
	}
	for _, sv := range e.ShadowViolations {
		rec.ShadowViolationTypes = append(rec.ShadowViolationTypes, sv.Type)
	}
	if e.DataFlow != nil {
		destSet := make(map[string]struct{})
		regionSet := make(map[string]struct{})
		typeSet := make(map[string]struct{})
		for i := range e.DataFlow.Items {
			item := &e.DataFlow.Items[i]
			destSet[item.Destination.Kind+":"+item.Destination.Name] = struct{}{}
			if item.Destination.Region != "" {
				regionSet[item.Destination.Region] = struct{}{}
			}
			for _, t := range item.EntityTypes {
				typeSet[t] = struct{}{}
			}
		}
		rec.FlowDestinations = sortedSetKeys(destSet)
		rec.FlowRegions = sortedSetKeys(regionSet)
		rec.FlowEntityTypes = sortedSetKeys(typeSet)
	}
	if s := e.Classification.Scanner; s != nil {
		rec.ScannerEngine = s.Engine
		rec.ScannerType = s.Type
		rec.ScannerVersion = s.Version
		rec.ScannerFailure = s.Failure
	}
	if tc := e.Classification.ToolContent; tc != nil {
		scanned := tc.Scanned
		rec.ToolContentScanned = &scanned
		rec.ToolContentHasPII = tc.HasPII
		rec.ToolContentEntityTypes = tc.EntityTypes
		rec.ToolContentEntityCount = tc.EntityCount
	}
	if o := e.Orchestration; o != nil {
		rec.OrchAgentID = o.AgentID
		rec.OrchParentAgentID = o.ParentAgentID
		rec.OrchClient = o.Client
		rec.OrchSessionSource = o.SessionSource
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

// GatewayAnnotationsCSV returns comma-separated gateway annotations for CSV export.
func (r *ExportRecord) GatewayAnnotationsCSV() string {
	return strings.Join(r.GatewayAnnotations, ",")
}

// FlowDestinationsCSV returns comma-separated data-flow destinations for CSV export.
func (r *ExportRecord) FlowDestinationsCSV() string {
	return strings.Join(r.FlowDestinations, ",")
}

// FlowRegionsCSV returns comma-separated data-flow regions for CSV export.
func (r *ExportRecord) FlowRegionsCSV() string {
	return strings.Join(r.FlowRegions, ",")
}

// FlowEntityTypesCSV returns comma-separated data-flow entity types for CSV export.
func (r *ExportRecord) FlowEntityTypesCSV() string {
	return strings.Join(r.FlowEntityTypes, ",")
}

package gateway

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/dativo-io/talon/internal/evidence"
)

// RecordGatewayEvidenceParams holds all inputs for a gateway evidence record.
type RecordGatewayEvidenceParams struct {
	CorrelationID           string
	TenantID                string
	CallerName              string
	Team                    string
	Provider                string
	Model                   string
	PolicyAllowed           bool
	PolicyReasons           []string
	PolicyVersion           string
	ObservationModeOverride bool
	InputTier               int
	PIIDetected             []string
	PIIRedacted             bool
	OutputPIIDetected       bool
	OutputPIITypes          []string
	Cost                    float64
	InputTokens             int
	OutputTokens            int
	DurationMS              int64
	Error                   string
	SecretsAccessed         []string // secret names only; never real keys
	AttachmentScan          *evidence.AttachmentScan
	ToolsRequested          []string
	ToolsFiltered           []string
	ToolsForwarded          []string
}

// RecordGatewayEvidence creates and stores a signed evidence record for a gateway request.
// Never logs or stores real provider API keys.
func RecordGatewayEvidence(ctx context.Context, store *evidence.Store, params RecordGatewayEvidenceParams) error {
	var toolGov *evidence.ToolGovernance
	if len(params.ToolsRequested) > 0 {
		toolGov = &evidence.ToolGovernance{
			ToolsRequested: params.ToolsRequested,
			ToolsFiltered:  params.ToolsFiltered,
			ToolsForwarded: params.ToolsForwarded,
		}
	}

	ev := &evidence.Evidence{
		ID:              "gw_" + uuid.New().String()[:12],
		CorrelationID:   params.CorrelationID,
		Timestamp:       time.Now(),
		TenantID:        params.TenantID,
		AgentID:         params.CallerName,
		InvocationType:  "gateway",
		RequestSourceID: params.CallerName,
		PolicyDecision: evidence.PolicyDecision{
			Allowed:       params.PolicyAllowed,
			Action:        "allow",
			Reasons:       params.PolicyReasons,
			PolicyVersion: params.PolicyVersion,
		},
		Classification: evidence.Classification{
			InputTier:         params.InputTier,
			OutputTier:        params.InputTier,
			PIIDetected:       params.PIIDetected,
			PIIRedacted:       params.PIIRedacted,
			OutputPIIDetected: params.OutputPIIDetected,
			OutputPIITypes:    params.OutputPIITypes,
		},
		Execution: evidence.Execution{
			ModelUsed:  params.Model,
			Cost:       params.Cost,
			Tokens:     evidence.TokenUsage{Input: params.InputTokens, Output: params.OutputTokens},
			DurationMS: params.DurationMS,
			Error:      params.Error,
		},
		SecretsAccessed:         params.SecretsAccessed,
		AttachmentScan:          params.AttachmentScan,
		ToolGovernance:          toolGov,
		ObservationModeOverride: params.ObservationModeOverride,
		AuditTrail:              evidence.AuditTrail{},
		Compliance:              evidence.Compliance{},
	}
	if !params.PolicyAllowed {
		ev.PolicyDecision.Action = "deny"
	}
	return store.Store(ctx, ev)
}

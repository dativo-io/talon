package evidence

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToExportRecord(t *testing.T) {
	ev := &Evidence{
		ID:             "req_1",
		Timestamp:      time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC),
		TenantID:       "default",
		AgentID:        "bot",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{
			Allowed:       false,
			Action:        "deny",
			Reasons:       []string{"budget_exceeded"},
			PolicyVersion: "v1",
		},
		Classification: Classification{
			InputTier:   2,
			OutputTier:  0,
			PIIDetected: []string{"EMAIL_ADDRESS", "PHONE_NUMBER"},
			PIIRedacted: true,
		},
		Execution: Execution{
			ModelUsed:   "gpt-4o-mini",
			Cost:        0.001,
			DurationMS:  100,
			Error:       "rate limit",
			ToolsCalled: []string{"mcp_search", "mcp_fetch"},
			Tokens:      TokenUsage{Input: 10, Output: 20},
		},
		AuditTrail: AuditTrail{
			InputHash:  "sha256:abc",
			OutputHash: "sha256:def",
		},
	}

	rec := ToExportRecord(ev)

	assert.Equal(t, "req_1", rec.ID)
	assert.Equal(t, "default", rec.TenantID)
	assert.Equal(t, "bot", rec.AgentID)
	assert.False(t, rec.Allowed)
	assert.Equal(t, 2, rec.InputTier)
	assert.Equal(t, 0, rec.OutputTier)
	assert.Equal(t, []string{"EMAIL_ADDRESS", "PHONE_NUMBER"}, rec.PIIDetected)
	assert.True(t, rec.PIIRedacted)
	assert.Equal(t, []string{"budget_exceeded"}, rec.PolicyReasons)
	assert.Equal(t, []string{"mcp_search", "mcp_fetch"}, rec.ToolsCalled)
	assert.Equal(t, "sha256:abc", rec.InputHash)
	assert.Equal(t, "sha256:def", rec.OutputHash)
	assert.True(t, rec.HasError)
}

func TestExportRecord_PIIDetectedCSV(t *testing.T) {
	rec := ExportRecord{PIIDetected: []string{"EMAIL_ADDRESS", "PHONE_NUMBER"}}
	assert.Equal(t, "EMAIL_ADDRESS,PHONE_NUMBER", rec.PIIDetectedCSV())
	rec.PIIDetected = nil
	assert.Equal(t, "", rec.PIIDetectedCSV())
}

func TestExportRecord_PolicyReasonsCSV(t *testing.T) {
	rec := ExportRecord{PolicyReasons: []string{"reason1", "reason2"}}
	assert.Equal(t, "reason1,reason2", rec.PolicyReasonsCSV())
	rec.PolicyReasons = nil
	assert.Equal(t, "", rec.PolicyReasonsCSV())
}

func TestExportRecord_ToolsCalledCSV(t *testing.T) {
	rec := ExportRecord{ToolsCalled: []string{"tool_a", "tool_b"}}
	assert.Equal(t, "tool_a,tool_b", rec.ToolsCalledCSV())
	rec.ToolsCalled = nil
	assert.Equal(t, "", rec.ToolsCalledCSV())
}

func TestToExportRecord_EmptyOptionalSlices(t *testing.T) {
	ev := &Evidence{
		ID:             "req_2",
		Timestamp:      time.Now(),
		TenantID:       "t",
		AgentID:        "a",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true},
		Classification: Classification{InputTier: 0, OutputTier: 0},
		Execution:      Execution{},
		AuditTrail:     AuditTrail{},
	}
	rec := ToExportRecord(ev)
	// When source slices are nil/empty, PIIDetected may be nil; PolicyReasons/ToolsCalled only set when len > 0
	assert.Len(t, rec.PIIDetected, 0)
	assert.Len(t, rec.PolicyReasons, 0)
	assert.Len(t, rec.ToolsCalled, 0)
}

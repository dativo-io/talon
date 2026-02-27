package evidence

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToExportRecord_ShadowViolationFields(t *testing.T) {
	ev := &Evidence{
		ID: "test_001", Timestamp: time.Now(), TenantID: "t1", AgentID: "a1",
		InvocationType:          "gateway",
		PolicyDecision:          PolicyDecision{Allowed: true, Action: "allow"},
		Execution:               Execution{ModelUsed: "gpt-4o", Cost: 0.01},
		ObservationModeOverride: true,
		ShadowViolations: []ShadowViolation{
			{Type: "pii_block", Detail: "PII detected: EMAIL", Action: "block"},
			{Type: "rate_limit", Detail: "Rate limit exceeded", Action: "block"},
		},
	}

	rec := ToExportRecord(ev)
	assert.True(t, rec.ObservationModeOverride)
	assert.Equal(t, []string{"pii_block", "rate_limit"}, rec.ShadowViolationTypes)
	assert.Equal(t, "pii_block,rate_limit", rec.ShadowViolationTypesCSV())
}

func TestToExportRecord_NoShadowViolations(t *testing.T) {
	ev := &Evidence{
		ID: "test_002", Timestamp: time.Now(), TenantID: "t1", AgentID: "a1",
		InvocationType: "gateway",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		Execution:      Execution{ModelUsed: "gpt-4o"},
	}

	rec := ToExportRecord(ev)
	assert.False(t, rec.ObservationModeOverride)
	assert.Empty(t, rec.ShadowViolationTypes)
	assert.Equal(t, "", rec.ShadowViolationTypesCSV())
}

func TestToExportRecord_BackwardCompatible(t *testing.T) {
	ev := &Evidence{
		ID: "test_003", Timestamp: time.Now(), TenantID: "t1", AgentID: "a1",
		InvocationType: "cli",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow", Reasons: []string{"budget ok"}},
		Classification: Classification{InputTier: 1, PIIDetected: []string{"email"}, PIIRedacted: true},
		Execution:      Execution{ModelUsed: "gpt-4o", Cost: 0.05, DurationMS: 1234, Error: "timeout", ToolsCalled: []string{"web_search"}},
		AuditTrail:     AuditTrail{InputHash: "abc123", OutputHash: "def456"},
	}

	rec := ToExportRecord(ev)
	assert.Equal(t, "test_003", rec.ID)
	assert.Equal(t, "t1", rec.TenantID)
	assert.True(t, rec.Allowed)
	assert.Equal(t, 0.05, rec.Cost)
	assert.True(t, rec.HasError)
	assert.Equal(t, []string{"email"}, rec.PIIDetected)
	assert.Equal(t, []string{"budget ok"}, rec.PolicyReasons)
	assert.Equal(t, []string{"web_search"}, rec.ToolsCalled)
	assert.Equal(t, "abc123", rec.InputHash)
}

func TestExportRecord_JSONRoundTrip(t *testing.T) {
	rec := ExportRecord{
		ID: "test_004", Timestamp: time.Now().UTC(), TenantID: "t1", AgentID: "a1",
		InvocationType: "gateway", Allowed: true, Cost: 0.02, ModelUsed: "gpt-4o",
		ObservationModeOverride: true,
		ShadowViolationTypes:    []string{"pii_block"},
	}

	data, err := json.Marshal(rec)
	require.NoError(t, err)

	var decoded ExportRecord
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, rec.ID, decoded.ID)
	assert.True(t, decoded.ObservationModeOverride)
	assert.Equal(t, []string{"pii_block"}, decoded.ShadowViolationTypes)
}

func TestExportEnvelope_JSONRoundTrip(t *testing.T) {
	envelope := ExportEnvelope{
		ExportMetadata: ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: "0.9.0",
			Filter:       ExportFilter{From: "2026-02-01", Tenant: "acme"},
			TotalRecords: 2,
		},
		Records: []ExportRecord{
			{ID: "r1", Allowed: true},
			{ID: "r2", Allowed: false, ObservationModeOverride: true, ShadowViolationTypes: []string{"policy_deny"}},
		},
	}

	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	var decoded ExportEnvelope
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "0.9.0", decoded.ExportMetadata.TalonVersion)
	assert.Equal(t, 2, decoded.ExportMetadata.TotalRecords)
	assert.Len(t, decoded.Records, 2)
	assert.True(t, decoded.Records[1].ObservationModeOverride)
}

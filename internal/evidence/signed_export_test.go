package evidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyExport_ValidSignedJSON(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_signed_ok",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "hello",
		OutputResponse: "world",
	})
	require.NoError(t, err)

	envelope := SignedExportEnvelope{
		ExportMetadata: ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: "test",
			TotalRecords: 1,
			Algorithm:    SignedExportAlgorithm,
			Signed:       true,
		},
		Records: []Evidence{*ev},
	}
	payload, err := json.Marshal(envelope)
	require.NoError(t, err)

	report, verifyErr := store.VerifyExport(payload)
	require.NoError(t, verifyErr)
	assert.Equal(t, 1, report.Total)
	assert.Equal(t, 1, report.Valid)
	assert.False(t, report.HasFailures())
}

func TestVerifyExport_TamperedRecordFails(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_signed_tamper",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "hello",
		OutputResponse: "world",
		Cost:           0.1,
	})
	require.NoError(t, err)

	tampered := *ev
	tampered.Execution.Cost = 42.0
	envelope := SignedExportEnvelope{
		ExportMetadata: ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: "test",
			TotalRecords: 1,
			Algorithm:    SignedExportAlgorithm,
			Signed:       true,
		},
		Records: []Evidence{tampered},
	}
	payload, err := json.Marshal(envelope)
	require.NoError(t, err)

	report, verifyErr := store.VerifyExport(payload)
	require.NoError(t, verifyErr)
	assert.Equal(t, 1, report.Total)
	assert.Equal(t, 1, report.Invalid)
	assert.True(t, report.HasFailures())
	assert.Equal(t, "all signatures failed; check TALON_SIGNING_KEY", report.Hint)
}

func TestVerifyExport_MissingSignature(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_signed_missing",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "hello",
		OutputResponse: "world",
	})
	require.NoError(t, err)
	ev.Signature = ""

	envelope := SignedExportEnvelope{
		ExportMetadata: ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: "test",
			TotalRecords: 1,
			Algorithm:    SignedExportAlgorithm,
			Signed:       true,
		},
		Records: []Evidence{*ev},
	}
	payload, err := json.Marshal(envelope)
	require.NoError(t, err)

	report, verifyErr := store.VerifyExport(payload)
	require.NoError(t, verifyErr)
	assert.Equal(t, 1, report.Total)
	assert.Equal(t, 1, report.MissingSignature)
	assert.True(t, report.HasFailures())
}

func TestVerifyExport_UnsupportedReducedEnvelope(t *testing.T) {
	store := newTestStore(t)
	envelope := ExportEnvelope{
		ExportMetadata: ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: "test",
			TotalRecords: 1,
		},
		Records: []ExportRecord{{ID: "rec_1"}},
	}
	payload, err := json.Marshal(envelope)
	require.NoError(t, err)

	report, verifyErr := store.VerifyExport(payload)
	require.Error(t, verifyErr)
	assert.Equal(t, 1, report.Unsupported)
	assert.True(t, report.HasFailures())
}

func TestVerifyExport_EmptySignedJSON(t *testing.T) {
	store := newTestStore(t)

	envelope := SignedExportEnvelope{
		ExportMetadata: ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: "test",
			TotalRecords: 0,
			Algorithm:    SignedExportAlgorithm,
			Signed:       true,
		},
		Records: []Evidence{},
	}
	payload, err := json.MarshalIndent(envelope, "", "  ")
	require.NoError(t, err)

	report, verifyErr := store.VerifyExport(payload)
	require.NoError(t, verifyErr)
	assert.Equal(t, 0, report.Total)
	assert.Equal(t, 0, report.Valid)
	assert.False(t, report.HasFailures(), "empty signed export should not report failures")
}

func TestVerifyExport_SignedNDJSONMixed(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_signed_ndjson",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "hello",
		OutputResponse: "world",
	})
	require.NoError(t, err)
	validLine, err := json.Marshal(ev)
	require.NoError(t, err)

	payload := append(validLine, []byte("\n{bad json}\n")...)
	report, verifyErr := store.VerifyExport(payload)
	require.NoError(t, verifyErr)
	assert.Equal(t, 2, report.Total)
	assert.Equal(t, 1, report.Valid)
	assert.Equal(t, 1, report.Unparseable)
	assert.True(t, report.HasFailures())
}

func TestSignedExportEnvelope_ContainsSignatures(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)
	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_signed_export_contains_sig",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "hello",
		OutputResponse: "world",
	})
	require.NoError(t, err)

	list, err := store.List(ctx, "acme", "agent", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, list)
	for i := range list {
		assert.NotEmpty(t, list[i].Signature)
	}
}

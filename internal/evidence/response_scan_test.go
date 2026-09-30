package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadPreResponseScanFixtures returns signed gateway records captured on the
// code that preceded #476: a `warn` response with detected PII, non-streaming
// and streaming. They carry output_pii_detected without response_scan and are
// the compatibility contract for the additive spec 1.10 field: they must keep
// verifying byte-for-byte, and the projection helpers must still tell an
// observation from a redaction from their signed data-flow disposition.
func loadPreResponseScanFixtures(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "pre_response_scan", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, paths, "pre-#476 fixtures missing")
	sort.Strings(paths)
	out := make(map[string][]byte, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		out[filepath.Base(p)] = bytes.TrimSpace(b)
	}
	return out
}

func TestPreResponseScanFixtures_RoundTripAndVerify(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "e.db"), legacyPostureSigningKey)
	require.NoError(t, err)
	defer store.Close()

	for name, raw := range loadPreResponseScanFixtures(t) {
		t.Run(name, func(t *testing.T) {
			var ev Evidence
			require.NoError(t, json.Unmarshal(raw, &ev))
			require.NotEmpty(t, ev.Signature)
			assert.Nil(t, ev.Classification.ResponseScan, "historical records carry no response_scan")
			assert.True(t, ev.Classification.OutputPIIDetected)

			again, err := json.Marshal(&ev)
			require.NoError(t, err)
			assert.Equal(t, string(raw), string(again), "canonical bytes drifted: the additive field must be omitted when absent")
			assert.True(t, store.VerifyRecord(&ev), "historical record must still verify")

			// The signed data-flow disposition (surfaced) tells the projection
			// this was an observation, not a redaction, even without the
			// 1.10 field.
			assert.True(t, ev.Classification.ResponsePIIObserved(ev.DataFlow))
			assert.False(t, ev.Classification.ResponsePIIRedacted(ev.DataFlow))
		})
	}
}

func TestPreResponseScanFixtures_SignedExportVerifies(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "e.db"), legacyPostureSigningKey)
	require.NoError(t, err)
	defer store.Close()

	var ndjson bytes.Buffer
	fixtures := loadPreResponseScanFixtures(t)
	for _, raw := range fixtures {
		ndjson.Write(raw)
		ndjson.WriteByte('\n')
	}
	report, err := store.VerifyExport(ndjson.Bytes())
	require.NoError(t, err)
	assert.Equal(t, len(fixtures), report.Valid)
	assert.Zero(t, report.Invalid)
}

// A record carrying response_scan signs, round-trips through the canonical
// form with the field appended after tool_content, and verifies; a copy with
// the field stripped no longer verifies (the field is part of the signed
// payload).
func TestResponseScan_SignedFieldRoundTrip(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "e.db"), legacyPostureSigningKey)
	require.NoError(t, err)
	defer store.Close()

	for _, rs := range []*ResponseScan{
		{Action: "warn", Enforcement: ResponseScanEnforcementPostDelivery, Streamed: true, Status: ResponseScanStatusComplete, BytesObserved: 512, CaptureLimit: 4 << 20},
		{Action: "warn", Enforcement: ResponseScanEnforcementPostDelivery, Streamed: true, Status: ResponseScanStatusIncomplete, IncompleteReason: ResponseScanIncompleteCaptureLimitExceeded, BytesObserved: 4 << 20, CaptureLimit: 4 << 20},
		{Action: "redact", Enforcement: ResponseScanEnforcementPreventive, Streamed: true, Status: ResponseScanStatusComplete},
		{Action: "block", Enforcement: ResponseScanEnforcementPreventive, Status: ResponseScanStatusIncomplete, IncompleteReason: ResponseScanIncompleteScannerUnavailable},
	} {
		t.Run(rs.Action+"_"+rs.Status, func(t *testing.T) {
			ev := &Evidence{
				ID: "gw_rs_" + rs.Action + rs.Status, CorrelationID: "corr", TenantID: "t", AgentID: "a", InvocationType: "gateway",
				PolicyDecision: PolicyDecision{Allowed: rs.Action != "block", Action: "allow"},
				Classification: Classification{
					OutputPIIDetected: rs.Status == ResponseScanStatusComplete, OutputPIITypes: []string{"email"},
					ToolContent: &ToolContentScan{Scanned: true}, ResponseScan: rs,
				},
				Execution: Execution{ModelUsed: "m"},
			}
			require.NoError(t, store.Store(t.Context(), ev))
			raw, err := json.Marshal(ev)
			require.NoError(t, err)
			// Append rule: response_scan follows tool_content inside classification.
			tc := bytes.Index(raw, []byte(`"tool_content":`))
			rsIdx := bytes.Index(raw, []byte(`"response_scan":`))
			require.Positive(t, tc)
			assert.Greater(t, rsIdx, tc, "response_scan must be serialized after tool_content (spec §2 append rule)")

			var back Evidence
			require.NoError(t, json.Unmarshal(raw, &back))
			assert.True(t, store.VerifyRecord(&back))
			assert.Equal(t, rs, back.Classification.ResponseScan)

			stripped := back
			stripped.Classification.ResponseScan = nil
			assert.False(t, store.VerifyRecord(&stripped), "removing the response_scan facts must break the signature")
		})
	}
}

func TestClassification_ResponsePIIHelpers(t *testing.T) {
	surfaced := &DataFlow{Items: []DataFlowItem{{Source: FlowSourceResponse, Disposition: FlowDispositionSurfaced}}}
	redacted := &DataFlow{Items: []DataFlowItem{{Source: FlowSourceResponse, Disposition: FlowDispositionRedacted}}}
	cases := []struct {
		name               string
		c                  Classification
		df                 *DataFlow
		redactedWant, obsW bool
	}{
		{"no output pii", Classification{}, surfaced, false, false},
		{"1.10 post-delivery warn", Classification{OutputPIIDetected: true, ResponseScan: &ResponseScan{Action: "warn", Enforcement: ResponseScanEnforcementPostDelivery}}, redacted, false, true},
		{"1.10 non-stream warn", Classification{OutputPIIDetected: true, ResponseScan: &ResponseScan{Action: "warn", Enforcement: ResponseScanEnforcementObservation}}, nil, false, true},
		{"1.10 preventive redact", Classification{OutputPIIDetected: true, ResponseScan: &ResponseScan{Action: "redact", Enforcement: ResponseScanEnforcementPreventive}}, surfaced, true, false},
		{"1.10 preventive block", Classification{OutputPIIDetected: true, ResponseScan: &ResponseScan{Action: "block", Enforcement: ResponseScanEnforcementPreventive}}, nil, false, false},
		{"pre-1.10 surfaced", Classification{OutputPIIDetected: true}, surfaced, false, true},
		{"pre-1.10 redacted", Classification{OutputPIIDetected: true}, redacted, true, false},
		{"pre-1.10 no data flow", Classification{OutputPIIDetected: true}, nil, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.redactedWant, tc.c.ResponsePIIRedacted(tc.df), "redacted")
			assert.Equal(t, tc.obsW, tc.c.ResponsePIIObserved(tc.df), "observed")
		})
	}
}

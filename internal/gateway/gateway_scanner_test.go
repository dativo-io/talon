package gateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/classifier/presidio"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
)

const scannerTestEmail = "kai.nova@example.com"

// failingExternalScanner returns an adapter bound to a mock engine whose
// /analyze always fails in the given mode.
func failingExternalScanner(t *testing.T, mode string) *adapter.HTTPAdapter {
	t.Helper()
	srv := testutil.NewFailingScannerServer(t, mode)
	a, err := adapter.New(adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL, Name: "failing-engine"})
	require.NoError(t, err)
	return a
}

// emailDetectingExternalScanner returns an adapter bound to a Presidio-shaped
// mock that reports every occurrence of scannerTestEmail (rune offsets, no
// offset_encoding field — stock Presidio behavior).
func emailDetectingExternalScanner(t *testing.T) *adapter.HTTPAdapter {
	t.Helper()
	srv := testutil.NewPresidioMockServer(t, func(text string) []presidio.RecognizerResult {
		var results []presidio.RecognizerResult
		for idx := strings.Index(text, scannerTestEmail); idx >= 0; {
			// Mock reports rune offsets like stock Presidio; test text is ASCII
			// so byte==rune, but the adapter still runs the conversion path.
			results = append(results, presidio.RecognizerResult{
				EntityType: "EMAIL_ADDRESS",
				Start:      idx,
				End:        idx + len(scannerTestEmail),
				Score:      1.0,
			})
			next := strings.Index(text[idx+1:], scannerTestEmail)
			if next < 0 {
				break
			}
			idx += 1 + next
		}
		return results
	})
	a, err := adapter.New(adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL, Name: "presidio-test", EngineVersion: "2.2.x"})
	require.NoError(t, err)
	return a
}

func latestGatewayEvidence(t *testing.T, evStore *evidence.Store) evidence.Evidence {
	t.Helper()
	records, err := evStore.List(context.Background(), "test-tenant", "", time.Now().Add(-time.Minute), time.Now().Add(time.Minute), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records, "expected gateway evidence to be recorded")
	return records[0]
}

func TestExternalScannerFailClosed_EnforceBlocksRequest(t *testing.T) {
	upstreamHit := false
	gw, _, evStore := setupGatewayWithClassifier(t, "block", ModeEnforce,
		func(w http.ResponseWriter, _ *http.Request) {
			upstreamHit = true
			_, _ = w.Write([]byte(`{}`))
		},
		failingExternalScanner(t, testutil.ScannerFailStatus))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)

	assert.Equal(t, http.StatusBadGateway, w.Code, "scanner failure must block fail-closed in enforce mode")
	assert.Contains(t, w.Body.String(), "PII scanner unavailable")
	assert.False(t, upstreamHit, "blocked request must never reach the provider")

	ev := latestGatewayEvidence(t, evStore)
	require.NotNil(t, ev.Classification.Scanner, "evidence must identify the scan engine")
	assert.Equal(t, "failing-engine", ev.Classification.Scanner.Engine)
	assert.Equal(t, "scanner_unavailable", ev.Classification.Scanner.Failure)
	assert.False(t, ev.PolicyDecision.Allowed)
}

func TestExternalScannerFailClosed_TimeoutBlocks(t *testing.T) {
	srv := testutil.NewFailingScannerServer(t, testutil.ScannerFailTimeout)
	a, err := adapter.New(adapter.Config{
		Type: adapter.TypePresidio, Endpoint: srv.URL,
		Timeout: 100 * time.Millisecond,
	})
	require.NoError(t, err)

	gw, _, _ := setupGatewayWithClassifier(t, "block", ModeEnforce,
		func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }, a)

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	assert.Equal(t, http.StatusBadGateway, w.Code, "scanner timeout must block fail-closed")
}

func TestExternalScannerFailClosed_ShadowRecordsViolationAndForwards(t *testing.T) {
	upstreamHit := false
	gw, _, evStore := setupGatewayWithClassifier(t, "block", ModeShadow,
		func(w http.ResponseWriter, _ *http.Request) {
			upstreamHit = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{}}`))
		},
		failingExternalScanner(t, testutil.ScannerFailStatus))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)

	assert.Equal(t, http.StatusOK, w.Code, "shadow mode never blocks")
	assert.True(t, upstreamHit, "shadow mode forwards despite scanner failure")

	ev := latestGatewayEvidence(t, evStore)
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "scanner_unavailable" {
			found = true
		}
	}
	assert.True(t, found, "shadow evidence must record the would-be scanner block, got %+v", ev.ShadowViolations)
}

func TestExternalScanner_DetectionDrivesPIIBlock(t *testing.T) {
	upstreamHit := false
	gw, _, evStore := setupGatewayWithClassifier(t, "block", ModeEnforce,
		func(w http.ResponseWriter, _ *http.Request) {
			upstreamHit = true
			_, _ = w.Write([]byte(`{}`))
		},
		emailDetectingExternalScanner(t))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"mail `+scannerTestEmail+` now"}]}`)

	assert.Equal(t, http.StatusBadRequest, w.Code, "external engine detections must drive the same PII block policy")
	assert.False(t, upstreamHit)

	ev := latestGatewayEvidence(t, evStore)
	assert.Contains(t, ev.Classification.PIIDetected, "email", "canonical entity type from external engine in evidence")
	require.NotNil(t, ev.Classification.Scanner)
	assert.Equal(t, "presidio-test", ev.Classification.Scanner.Engine)
	assert.Equal(t, "2.2.x", ev.Classification.Scanner.Version)
	assert.Equal(t, "presidio", ev.Classification.Scanner.Type)
}

func TestExternalScanner_RedactionFlowsThroughAdapter(t *testing.T) {
	var forwardedBody []byte
	gw, _, _ := setupGatewayWithClassifier(t, "redact", ModeEnforce,
		func(w http.ResponseWriter, r *http.Request) {
			forwardedBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"}}],"usage":{}}`))
		},
		emailDetectingExternalScanner(t))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"mail `+scannerTestEmail+` now"}]}`)

	require.Equal(t, http.StatusOK, w.Code, "redacted request should be forwarded, body: %s", w.Body.String())
	assert.NotContains(t, string(forwardedBody), scannerTestEmail, "raw PII must not reach the provider")
	assert.Contains(t, string(forwardedBody), "[EMAIL]", "external-engine redaction uses byte-exact placeholders")
}

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	assert.Equal(t, "status", ev.Classification.Scanner.Failure,
		"adapter-backed failures record the typed kind, not a generic label")
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

// failOnMarkerScanner fails the scan only when the text contains marker —
// lets a request scan pass while the response scan fails.
func failOnMarkerScanner(t *testing.T, marker string) *adapter.HTTPAdapter {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.Contains(req.Text, marker) {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, err := adapter.New(adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL, Name: "resp-failing-engine"})
	require.NoError(t, err)
	return a
}

func chatUpstreamWithContent(content string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"role": "assistant", "content": content}},
			},
			"usage": map[string]int{},
		})
		_, _ = w.Write(body)
	}
}

func TestExternalScanner_ResponseBlock_NoUpstream200AndEvidenceDenied(t *testing.T) {
	// Upstream answers 200 with PII in the content; action block must NOT
	// surface the upstream 200 and evidence must record a denial.
	gw, _, evStore := setupGatewayWithClassifier(t, "block", ModeEnforce,
		chatUpstreamWithContent("reach me at "+scannerTestEmail),
		emailDetectingExternalScanner(t))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"clean prompt"}]}`)

	assert.Equal(t, http.StatusUnavailableForLegalReasons, w.Code,
		"a blocked response must not masquerade as the upstream 200")
	assert.Contains(t, w.Body.String(), "pii_policy_violation")
	assert.NotContains(t, w.Body.String(), scannerTestEmail)

	ev := latestGatewayEvidence(t, evStore)
	assert.False(t, ev.PolicyDecision.Allowed, "evidence must record the denial, not allowed=true")
	assert.Equal(t, "deny", ev.PolicyDecision.Action)
	assert.Contains(t, ev.PolicyDecision.Reasons, "output_pii_blocked")
	assert.True(t, ev.Classification.OutputPIIDetected)
}

func TestExternalScannerFailClosed_ResponseScanFailure502AndEvidenceDenied(t *testing.T) {
	const marker = "RESPONSE-ONLY-MARKER"
	gw, _, evStore := setupGatewayWithClassifier(t, "block", ModeEnforce,
		chatUpstreamWithContent("content with "+marker),
		failOnMarkerScanner(t, marker))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"clean prompt"}]}`)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "scanner_unavailable")

	ev := latestGatewayEvidence(t, evStore)
	assert.False(t, ev.PolicyDecision.Allowed)
	assert.Contains(t, ev.PolicyDecision.Reasons, "output_scanner_unavailable")
	require.NotNil(t, ev.Classification.Scanner)
	assert.Equal(t, "status", ev.Classification.Scanner.Failure,
		"response-path scanner failures record the typed adapter kind")
}

func TestExternalScanner_ShadowResponsePII_ForwardsAndRecordsViolation(t *testing.T) {
	responseContent := "reach me at " + scannerTestEmail
	gw, _, evStore := setupGatewayWithClassifier(t, "block", ModeShadow,
		chatUpstreamWithContent(responseContent),
		emailDetectingExternalScanner(t))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"clean prompt"}]}`)

	assert.Equal(t, http.StatusOK, w.Code, "shadow never blocks")
	assert.Contains(t, w.Body.String(), scannerTestEmail, "shadow forwards the original response unmodified")

	ev := latestGatewayEvidence(t, evStore)
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "response_pii" {
			found = true
		}
	}
	assert.True(t, found, "shadow evidence must record the would-be response block, got %+v", ev.ShadowViolations)
}

// ibanDetectingExternalScanner reports IBAN_CODE (built-in sensitivity 2)
// for every occurrence of the given IBAN — no wire sensitivity hints.
func ibanDetectingExternalScanner(t *testing.T, iban string) *adapter.HTTPAdapter {
	t.Helper()
	srv := testutil.NewPresidioMockServer(t, func(text string) []presidio.RecognizerResult {
		idx := strings.Index(text, iban)
		if idx < 0 {
			return nil
		}
		return []presidio.RecognizerResult{{
			EntityType: "IBAN_CODE", Start: idx, End: idx + len(iban), Score: 1.0,
		}}
	})
	a, err := adapter.New(adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL, Name: "iban-engine"})
	require.NoError(t, err)
	return a
}

func TestExternalScanner_OutputTierReflectsResponseContent(t *testing.T) {
	// Clean tier-0 prompt; the RESPONSE leaks an IBAN (sensitivity 2).
	// Evidence must record output_tier 2, not a copy of the input tier.
	const iban = "DE89370400440532013000"
	gw, _, evStore := setupGatewayWithClassifier(t, "block", ModeEnforce,
		chatUpstreamWithContent("wire the funds to "+iban),
		ibanDetectingExternalScanner(t, iban))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"clean prompt"}]}`)
	require.Equal(t, http.StatusUnavailableForLegalReasons, w.Code)

	ev := latestGatewayEvidence(t, evStore)
	assert.Equal(t, 0, ev.Classification.InputTier, "prompt was clean")
	assert.Equal(t, 2, ev.Classification.OutputTier,
		"blocked high-risk output must record its own tier, not the input tier")
	assert.True(t, ev.Classification.OutputPIIDetected)
	assert.False(t, ev.PolicyDecision.Allowed)
}

// detectThenFailScanner detects scannerTestEmail in raw text but errors on any
// text containing redaction placeholders — the field-observed failure mode
// where the verify re-scan of "[EMAIL]..." fails while the first two scans
// succeed (e.g. a small model repetition-spiraling on placeholder-only text).
func detectThenFailScanner(t *testing.T) *adapter.HTTPAdapter {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.Contains(req.Text, "[EMAIL]") {
			http.Error(w, "engine spiraled", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		results := []presidio.RecognizerResult{}
		if idx := strings.Index(req.Text, scannerTestEmail); idx >= 0 {
			results = append(results, presidio.RecognizerResult{
				EntityType: "EMAIL_ADDRESS", Start: idx, End: idx + len(scannerTestEmail),
				Score: 1.0, OffsetEncoding: presidio.OffsetEncodingByte,
			})
		}
		_ = json.NewEncoder(w).Encode(results)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, err := adapter.New(adapter.Config{Type: adapter.TypeHTTP, Endpoint: srv.URL, Name: "spiral-engine"})
	require.NoError(t, err)
	return a
}

func TestExternalScannerFailClosed_VerifyScanFailureIsTruthful(t *testing.T) {
	upstreamHit := false
	gw, _, evStore := setupGatewayWithClassifier(t, "redact", ModeEnforce,
		func(w http.ResponseWriter, _ *http.Request) {
			upstreamHit = true
			_, _ = w.Write([]byte(`{}`))
		},
		detectThenFailScanner(t))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"mail `+scannerTestEmail+` now"}]}`)

	assert.Equal(t, http.StatusBadGateway, w.Code,
		"an unverifiable redaction is an engine failure (502), not a policy 400")
	assert.Contains(t, w.Body.String(), "could not be verified")
	assert.False(t, upstreamHit, "unverified redaction must never be forwarded")

	ev := latestGatewayEvidence(t, evStore)
	assert.False(t, ev.PolicyDecision.Allowed)
	assert.Contains(t, ev.PolicyDecision.Reasons, "request redaction verification failed: scanner unavailable",
		"evidence must not claim residual PII when the verify scan itself failed")
	require.NotNil(t, ev.Classification.Scanner)
	assert.Equal(t, "status", ev.Classification.Scanner.Failure,
		"typed failure kind from the verify scan is recorded")
}

package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupOpenClawGateway creates a Gateway wired to a mock upstream that captures
// the forwarded request for inspection.
func setupOpenClawGateway(t *testing.T, piiAction string, upstreamHandler http.HandlerFunc) (*Gateway, *httptest.Server, *evidence.Store) {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	dir := t.TempDir()

	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstream.URL, SecretName: "openai-api-key"},
		},
		Callers: []CallerConfig{
			{
				Name:     "openclaw-main",
				APIKey:   "talon-gw-openclaw-001",
				TenantID: "test-tenant",
				PolicyOverrides: &CallerPolicyOverrides{
					PIIAction:      piiAction,
					MaxDailyCost:   100,
					MaxMonthlyCost: 2000,
					AllowedModels:  []string{"gpt-4o-mini", "gpt-4o"},
				},
			},
		},
		DefaultPolicy: DefaultPolicyConfig{
			DefaultPIIAction: piiAction,
			MaxDailyCost:     100,
			MaxMonthlyCost:   2000,
		},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })

	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-test-REAL-secret-key-1234567890"),
		secrets.ACL{Tenants: []string{"test-tenant"}, Agents: []string{"*"}}))

	cls := classifier.MustNewScanner()

	gw, err := NewGateway(cfg, cls, evStore, secStore, nil, nil)
	require.NoError(t, err)

	return gw, upstream, evStore
}

func makeGatewayRequest(gw *Gateway, body string) *httptest.ResponseRecorder {
	return makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/chat/completions", body)
}

func makeGatewayRequestToPath(gw *Gateway, path, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test"+path,
		bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Task 8: Request-Path PII Handling (Failure Mode 6 — Request Direction)
// ---------------------------------------------------------------------------

func TestGateway_PIIRedactedBeforeForwarding(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"Processed"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)

	requestBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Send report to hans.mueller@example.de with IBAN DE89370400440532013000, phone +34612345678, and VAT ESB12345678"}]}`
	w := makeGatewayRequest(gw, requestBody)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)

	// PII must NOT appear in the forwarded body
	assert.NotContains(t, forwarded, "hans.mueller@example.de",
		"email address must be redacted before forwarding to upstream")
	assert.NotContains(t, forwarded, "DE89370400440532013000",
		"IBAN must be redacted before forwarding to upstream")

	// Non-PII content should be preserved
	assert.Contains(t, forwarded, "Send report to",
		"non-PII content must be preserved in forwarded request")
}

func TestGateway_PIIBlockModePreventsForwarding(t *testing.T) {
	upstreamCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	})

	gw, _, _ := setupOpenClawGateway(t, "block", handler)

	requestBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact hans.mueller@example.de about IBAN DE89370400440532013000"}]}`
	w := makeGatewayRequest(gw, requestBody)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"block mode should return 400 when PII detected")
	assert.False(t, upstreamCalled,
		"upstream must NOT be called when PII is blocked")
	assert.Contains(t, w.Body.String(), "PII",
		"error response should mention PII")
}

func TestGateway_RealAPIKeyNeverExposed(t *testing.T) {
	var capturedAuth string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"Safe"}}],"usage":{"prompt_tokens":2,"completion_tokens":1}}`))
	})

	gw, _, evStore := setupOpenClawGateway(t, "warn", handler)

	requestBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, requestBody)
	require.Equal(t, http.StatusOK, w.Code)

	// Upstream must receive the REAL secret key (injected by gateway)
	assert.True(t, strings.HasPrefix(capturedAuth, "Bearer sk-test-"),
		"upstream should receive the real API key")

	// The response to the caller must NOT leak the key
	responseBody := w.Body.String()
	assert.NotContains(t, responseBody, "sk-test-",
		"response to caller must not contain the real API key")

	// Evidence must NOT contain the real key
	records, err := evStore.List(context.Background(), "test-tenant", "",
		time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	for _, ev := range records {
		assert.NotContains(t, ev.AuditTrail.InputHash, "sk-test-",
			"evidence must not contain the real API key")
	}
}

// ---------------------------------------------------------------------------
// Task 9: Response-Path PII (Failure Mode 6 — Response Direction)
// ---------------------------------------------------------------------------

// Gap F (CLOSED): Response-path PII scanning for non-streaming responses.
func TestGateway_GapF_ResponsePIIRedaction(t *testing.T) {
	upstreamResponse := `{"choices":[{"message":{"content":"The customer email is jan.kowalski@gmail.com"}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}`
	gw, _, evidenceStore := setupOpenClawGateway(t, "redact", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	// Set response_pii_action to redact
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.NotContains(t, respBody, "jan.kowalski@gmail.com", "email should be redacted from response")

	// Evidence should record output PII detection
	evList, err := evidenceStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, evList)
	found := false
	for _, ev := range evList {
		if ev.Classification.OutputPIIDetected {
			found = true
			assert.NotEmpty(t, ev.Classification.OutputPIITypes)
			break
		}
	}
	assert.True(t, found, "evidence should record OutputPIIDetected")
}

// Gap F (CLOSED): Response PII block mode replaces response with safe error.
func TestGateway_GapF_ResponsePIIBlockMode(t *testing.T) {
	upstreamResponse := `{"choices":[{"message":{"content":"IBAN: DE89370400440532013000"}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "block"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"what is my IBAN?"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	assert.NotContains(t, respBody, "DE89370400440532013000", "IBAN should not appear in blocked response")
	assert.Contains(t, respBody, "pii_policy_violation", "should contain policy violation error")
}

// Gap F (CLOSED): Evidence records response PII metadata.
func TestGateway_GapF_EvidenceRecordsResponsePIIMetadataOnly(t *testing.T) {
	upstreamResponse := `{"choices":[{"message":{"content":"Email: user@company.eu"}}],"usage":{"prompt_tokens":5,"completion_tokens":10}}`
	gw, _, evidenceStore := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "warn"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"what is the email?"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Warn mode: PII passes through but evidence records the finding
	assert.Contains(t, rec.Body.String(), "user@company.eu", "warn mode should not redact")

	evList, err := evidenceStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, evList)
	found := false
	for _, ev := range evList {
		if ev.Classification.OutputPIIDetected {
			found = true
			assert.NotEmpty(t, ev.Classification.OutputPIITypes)
		}
	}
	assert.True(t, found, "evidence should record OutputPIIDetected even in warn mode")
}

// ---------------------------------------------------------------------------
// Response PII: false-positive prevention (envelope fields must not be scanned)
// ---------------------------------------------------------------------------

// TestGateway_ResponsePII_TimestampNotFalsePositive verifies that the `created`
// Unix timestamp in the API envelope is NOT flagged as PII. This was the root
// cause of the "national_id redacted" incident with OpenClaw.
func TestGateway_ResponsePII_TimestampNotFalsePositive(t *testing.T) {
	upstreamResponse := `{"id":"chatcmpl-1","object":"chat.completion","created":1772057232,"model":"gpt-4o-mini-2024-07-18","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there! How can I help?"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":5,"total_tokens":14}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.Contains(t, respBody, "1772057232", "created timestamp must NOT be redacted")
	assert.Contains(t, respBody, "chatcmpl-1", "response id must NOT be redacted")
	assert.Contains(t, respBody, `"prompt_tokens"`, "usage fields must NOT be redacted")
	assert.NotContains(t, respBody, "[NATIONAL_ID]", "no false positive national_id in envelope")
}

// TestGateway_ResponsePII_ContentStillRedacted verifies that real PII inside
// the LLM content field is still detected and redacted after the envelope fix.
func TestGateway_ResponsePII_ContentStillRedacted(t *testing.T) {
	upstreamResponse := `{"id":"chatcmpl-2","created":1772057232,"choices":[{"message":{"content":"Contact jan.kowalski@gmail.com for IBAN DE89370400440532013000"}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.NotContains(t, respBody, "jan.kowalski@gmail.com", "email in content must be redacted")
	assert.NotContains(t, respBody, "DE89370400440532013000", "IBAN in content must be redacted")
	assert.Contains(t, respBody, "1772057232", "created timestamp must be preserved")
	assert.Contains(t, respBody, "chatcmpl-2", "response id must be preserved")
}

// TestGateway_ResponsePII_NoPIIInContent_NoFalsePositive confirms that a
// response with no PII in content (but numeric envelope fields) produces
// no PII detection at all.
func TestGateway_ResponsePII_NoPIIInContent_NoFalsePositive(t *testing.T) {
	upstreamResponse := `{"id":"chatcmpl-3","created":1772057232,"choices":[{"message":{"content":"Hello! I am a helpful assistant."}}],"usage":{"prompt_tokens":9,"completion_tokens":8,"total_tokens":17}}`
	gw, _, evidenceStore := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "warn"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Hello! I am a helpful assistant.")

	evList, err := evidenceStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Now().Add(time.Second), 10)
	require.NoError(t, err)
	for _, ev := range evList {
		assert.False(t, ev.Classification.OutputPIIDetected,
			"no PII in content means no output PII should be detected (envelope must not trigger)")
	}
}

// TestScanResponseForPII_Unit tests the scanResponseForPII function directly.
func TestScanResponseForPII_Unit(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name           string
		body           string
		action         string
		wantPII        bool
		wantRedacted   bool
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:        "no_pii_in_content_timestamp_in_envelope",
			body:        `{"id":"chatcmpl-1","created":1772057232,"choices":[{"message":{"content":"Hi there"}}],"usage":{"prompt_tokens":9}}`,
			action:      "redact",
			wantPII:     false,
			mustContain: []string{"1772057232", "chatcmpl-1", "Hi there"},
		},
		{
			name:    "email_in_content_redacted",
			body:    `{"choices":[{"message":{"content":"Email: user@example.com"}}],"usage":{"prompt_tokens":5}}`,
			action:  "redact",
			wantPII: true, wantRedacted: true,
			mustNotContain: []string{"user@example.com"},
			mustContain:    []string{"[EMAIL]"},
		},
		{
			name:        "warn_mode_preserves_body",
			body:        `{"choices":[{"message":{"content":"Email: user@example.com"}}]}`,
			action:      "warn",
			wantPII:     true,
			mustContain: []string{"user@example.com"},
		},
		{
			name:        "allow_skips_scan",
			body:        `{"choices":[{"message":{"content":"Email: user@example.com"}}]}`,
			action:      "allow",
			wantPII:     false,
			mustContain: []string{"user@example.com"},
		},
		{
			name:    "block_mode_replaces_body",
			body:    `{"choices":[{"message":{"content":"IBAN: DE89370400440532013000"}}]}`,
			action:  "block",
			wantPII: true, wantRedacted: true,
			mustNotContain: []string{"DE89370400440532013000"},
			mustContain:    []string{"pii_policy_violation"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, result := scanResponseForPII(ctx, []byte(tt.body), tt.action, scanner)
			assert.Equal(t, tt.wantPII, result.PIIDetected)
			if tt.wantRedacted {
				assert.True(t, result.Redacted)
			}
			outStr := string(out)
			for _, s := range tt.mustContain {
				assert.Contains(t, outStr, s)
			}
			for _, s := range tt.mustNotContain {
				assert.NotContains(t, outStr, s)
			}
		})
	}
}

// TestScanResponseForPII_FalsePositivePrevention is a comprehensive table-driven
// test that checks every API envelope field that could trigger a PII false positive.
//
// Patterns checked against:
//   - \b\d{10}\b variants (AT SVN, SE/DK personnummer) → Unix timestamp "created"
//   - \b\d{9}\b (NL BSN, PT NIF) → could match large token counts
//   - \b\d{11}\b (DE tax ID, PL PESEL) → could match 11-digit numbers
//   - \b\d{12}\b (FR ID card) → could match 12-digit numbers
//   - \b[A-Z]{1,2}\d{6,9}\b (EU passport) → could match model names, IDs
//   - \b[A-Z]{2}\d{2}[A-Z0-9]{...}\b (IBAN) → validated by checksum
//   - IP address patterns → could match version strings
func TestScanResponseForPII_FalsePositivePrevention(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "realistic_openai_full_response",
			body: `{
				"id": "chatcmpl-DDAecAkvDjlDU1enFHTuUgZR0fFkD",
				"object": "chat.completion",
				"created": 1772057232,
				"model": "gpt-4o-mini-2024-07-18",
				"choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello! How can I help you today?"}, "logprobs": null, "finish_reason": "stop"}],
				"usage": {"prompt_tokens": 9, "completion_tokens": 8, "total_tokens": 17, "prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 0}, "completion_tokens_details": {"reasoning_tokens": 0, "audio_tokens": 0, "accepted_prediction_tokens": 0, "rejected_prediction_tokens": 0}},
				"service_tier": "default",
				"system_fingerprint": "fp_373a14eb6f"
			}`,
		},
		{
			name: "timestamp_matches_AT_SVN_pattern",
			body: `{"id":"c-1","created":1740112032,"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`,
		},
		{
			name: "timestamp_matches_SE_personnummer_10digit",
			body: `{"id":"c-2","created":5507131234,"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5}}`,
		},
		{
			name: "large_prompt_tokens_9digits",
			body: `{"id":"c-3","created":1772057232,"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":123456789,"completion_tokens":987654321,"total_tokens":1111111110}}`,
		},
		{
			name: "model_with_digits_gpt4o_20240718",
			body: `{"id":"c-4","created":1772057232,"model":"gpt-4o-mini-2024-07-18","choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5}}`,
		},
		{
			name: "anthropic_response_format",
			body: `{"id":"msg_01XFDUDYJgAACzvnptvVoYEL","type":"message","role":"assistant","content":[{"type":"text","text":"Hello! How can I help?"}],"model":"claude-sonnet-4-20250514","stop_reason":"end_turn","usage":{"input_tokens":25,"output_tokens":150}}`,
		},
		{
			name: "multiple_choices",
			body: `{"id":"c-5","created":1772057232,"choices":[{"index":0,"message":{"content":"Answer A"}},{"index":1,"message":{"content":"Answer B"}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}`,
		},
		{
			name: "system_fingerprint_hex",
			body: `{"id":"c-6","created":1772057232,"system_fingerprint":"fp_44709d6fcb","choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5}}`,
		},
		{
			name: "response_with_annotations_and_refusal",
			body: `{"id":"c-7","created":1772057232,"choices":[{"index":0,"message":{"role":"assistant","content":"I can help with that.","refusal":null,"annotations":[]},"logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":5,"total_tokens":14}}`,
		},
		{
			name: "content_array_multimodal",
			body: `{"id":"c-8","created":1772057232,"choices":[{"message":{"content":[{"type":"text","text":"The image shows a sunset."}]}}],"usage":{"prompt_tokens":100}}`,
		},
		{
			name: "empty_content",
			body: `{"id":"c-9","created":1772057232,"choices":[{"message":{"content":""}}],"usage":{"prompt_tokens":5}}`,
		},
		{
			name: "null_content",
			body: `{"id":"c-10","created":1772057232,"choices":[{"message":{"content":null,"refusal":"I cannot help with that."}}],"usage":{"prompt_tokens":5}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, result := scanResponseForPII(ctx, []byte(tt.body), "redact", scanner)
			assert.False(t, result.PIIDetected,
				"no PII in content → no detection (envelope must not trigger false positive)")
			assert.False(t, result.Redacted, "nothing to redact when no PII in content")
			assert.JSONEq(t, tt.body, string(out),
				"output body must be identical to input when no PII is in content")
		})
	}
}

// TestScanResponseForPII_ContentPII_EnvelopePreserved ensures that when the
// content has real PII, only the content is modified — envelope stays intact.
func TestScanResponseForPII_ContentPII_EnvelopePreserved(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name              string
		body              string
		wantPIITypes      []string
		mustNotContain    []string
		envelopePreserved []string
	}{
		{
			name:              "email_in_openai_content",
			body:              `{"id":"chatcmpl-abc","created":1772057232,"choices":[{"message":{"content":"Please email jan@example.de for details"}}],"usage":{"prompt_tokens":10,"completion_tokens":15}}`,
			wantPIITypes:      []string{"email"},
			mustNotContain:    []string{"jan@example.de"},
			envelopePreserved: []string{"chatcmpl-abc", "1772057232", `"prompt_tokens":10`, `"completion_tokens":15`},
		},
		{
			name:              "iban_in_openai_content",
			body:              `{"id":"chatcmpl-def","created":1772057232,"choices":[{"message":{"content":"Your IBAN is DE89370400440532013000"}}],"usage":{"prompt_tokens":8,"completion_tokens":12}}`,
			wantPIITypes:      []string{"iban"},
			mustNotContain:    []string{"DE89370400440532013000"},
			envelopePreserved: []string{"chatcmpl-def", "1772057232", `"prompt_tokens":8`},
		},
		{
			name:              "email_in_anthropic_content",
			body:              `{"id":"msg_123","type":"message","content":[{"type":"text","text":"Contact user@company.eu for info"}],"usage":{"input_tokens":20,"output_tokens":30}}`,
			wantPIITypes:      []string{"email"},
			mustNotContain:    []string{"user@company.eu"},
			envelopePreserved: []string{"msg_123", `"input_tokens":20`, `"output_tokens":30`},
		},
		{
			name:              "multimodal_content_array_with_pii",
			body:              `{"id":"chatcmpl-mm","created":1772057232,"choices":[{"message":{"content":[{"type":"text","text":"Call +48505977880 for help"}]}}],"usage":{"prompt_tokens":5}}`,
			wantPIITypes:      []string{"phone"},
			mustNotContain:    []string{"+48505977880"},
			envelopePreserved: []string{"chatcmpl-mm", "1772057232"},
		},
		{
			name:              "email_in_responses_api_output",
			body:              `{"id":"resp_abc","output":[{"type":"message","content":[{"type":"output_text","text":"The support email is support@company.eu"}]}],"usage":{"input_tokens":10,"output_tokens":15}}`,
			wantPIITypes:      []string{"email"},
			mustNotContain:    []string{"support@company.eu"},
			envelopePreserved: []string{"resp_abc", `"input_tokens":10`, `"output_tokens":15`},
		},
		{
			name:              "iban_in_responses_api_output",
			body:              `{"id":"resp_def","output":[{"type":"message","content":[{"type":"output_text","text":"Your IBAN is DE89370400440532013000"}]}],"usage":{"input_tokens":8,"output_tokens":12}}`,
			wantPIITypes:      []string{"iban"},
			mustNotContain:    []string{"DE89370400440532013000"},
			envelopePreserved: []string{"resp_def", `"input_tokens":8`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, result := scanResponseForPII(ctx, []byte(tt.body), "redact", scanner)
			assert.True(t, result.PIIDetected, "PII in content should be detected")
			assert.True(t, result.Redacted, "PII in content should be redacted")
			outStr := string(out)
			for _, s := range tt.mustNotContain {
				assert.NotContains(t, outStr, s, "PII must be redacted from content")
			}
			for _, s := range tt.envelopePreserved {
				assert.Contains(t, outStr, s, "envelope field must be preserved")
			}
		})
	}
}

// TestExtractResponseContentText_Unit tests the content extraction function directly.
func TestExtractResponseContentText_Unit(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantText string
	}{
		{
			name:     "openai_string_content",
			body:     `{"choices":[{"message":{"content":"Hello world"}}]}`,
			wantText: "Hello world",
		},
		{
			name:     "openai_array_content",
			body:     `{"choices":[{"message":{"content":[{"type":"text","text":"Part 1"},{"type":"image_url","image_url":{}},{"type":"text","text":" Part 2"}]}}]}`,
			wantText: "Part 1 Part 2",
		},
		{
			name:     "anthropic_content",
			body:     `{"content":[{"type":"text","text":"Anthropic says hello"}]}`,
			wantText: "Anthropic says hello",
		},
		{
			name:     "empty_content",
			body:     `{"choices":[{"message":{"content":""}}]}`,
			wantText: "",
		},
		{
			name:     "null_content",
			body:     `{"choices":[{"message":{"content":null}}]}`,
			wantText: "",
		},
		{
			name:     "no_choices_no_content",
			body:     `{"id":"test","created":123456}`,
			wantText: "",
		},
		{
			name:     "multiple_choices",
			body:     `{"choices":[{"message":{"content":"First"}},{"message":{"content":" Second"}}]}`,
			wantText: "First Second",
		},
		{
			name:     "invalid_json",
			body:     `not json`,
			wantText: "",
		},
		{
			name:     "envelope_numbers_not_extracted",
			body:     `{"id":"c-1","created":1772057232,"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":123456789}}`,
			wantText: "OK",
		},
		{
			name:     "responses_api_output_text",
			body:     `{"id":"resp_1","output":[{"type":"message","content":[{"type":"output_text","text":"Hello from Responses API"}]}]}`,
			wantText: "Hello from Responses API",
		},
		{
			name:     "responses_api_multiple_outputs",
			body:     `{"id":"resp_2","output":[{"type":"message","content":[{"type":"output_text","text":"First part"}]},{"type":"message","content":[{"type":"output_text","text":" Second part"}]}]}`,
			wantText: "First part Second part",
		},
		{
			name:     "responses_api_non_text_output_ignored",
			body:     `{"id":"resp_3","output":[{"type":"function_call","name":"get_weather","arguments":"{}"},{"type":"message","content":[{"type":"output_text","text":"Here is the weather"}]}]}`,
			wantText: "Here is the weather",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResponseContentText([]byte(tt.body))
			assert.Equal(t, tt.wantText, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Upstream error handling (404 / 5xx from provider)
// ---------------------------------------------------------------------------

// TestGateway_Upstream404_ReadableResponse verifies that when the upstream returns
// 404, the client gets a readable JSON body — not raw binary or gzip garbage.
func TestGateway_Upstream404_ReadableResponse(t *testing.T) {
	errorBody := `{"error":{"message":"The model 'gpt-nonexistent' does not exist","type":"invalid_request_error","code":"model_not_found"}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(errorBody))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusNotFound, w.Code, "404 status must be forwarded to client")
	assert.Contains(t, w.Body.String(), "model_not_found",
		"error body must be readable JSON, not binary")
	assert.Contains(t, w.Body.String(), "gpt-nonexistent",
		"original error message must be preserved")
}

// TestGateway_Upstream500_ReadableResponse verifies 500 errors are readable.
func TestGateway_Upstream500_ReadableResponse(t *testing.T) {
	errorBody := `{"error":{"message":"Internal server error","type":"server_error"}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(errorBody))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Internal server error",
		"500 error body must be readable")
}

// TestGateway_Upstream404WithSSEContentType ensures that even if the upstream
// mistakenly sets Content-Type: text/event-stream on a 404, the client still
// gets a readable body (the error path must NOT use streamCopy).
func TestGateway_Upstream404WithSSEContentType(t *testing.T) {
	errorBody := `{"error":{"message":"Not found","type":"not_found"}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(errorBody))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Not found",
		"404 with SSE content-type must still return readable error")
}

// TestGateway_UpstreamError_EvidenceStillRecorded verifies that an upstream
// error (e.g. 404) still generates an evidence record for the audit trail.
func TestGateway_UpstreamError_EvidenceStillRecorded(t *testing.T) {
	gw, _, evStore := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"Not found"}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusNotFound, w.Code)

	records, err := evStore.List(context.Background(), "test-tenant", "",
		time.Time{}, time.Now().Add(time.Second), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records, "evidence must be recorded even when upstream returns an error")
	assert.Equal(t, "openclaw-main", records[0].AgentID)
	assert.Equal(t, "gpt-4o-mini", records[0].Execution.ModelUsed)
}

// TestGateway_PIIRedact_ThenUpstream404 simulates the real-world scenario that
// triggered the "404 + binary" incident: PII in the prompt is redacted, and the
// upstream returns 404 (e.g. wrong model path). The client must get a readable error.
func TestGateway_PIIRedact_ThenUpstream404(t *testing.T) {
	var capturedBody []byte
	gw, _, _ := setupOpenClawGateway(t, "redact", func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"Model not found","type":"invalid_request_error","code":"model_not_found"}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact mike@johnson.com about the project"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusNotFound, w.Code, "404 status must be forwarded")
	assert.Contains(t, w.Body.String(), "Model not found",
		"error body must be readable even when PII was redacted")
	assert.NotContains(t, string(capturedBody), "mike@johnson.com",
		"PII must be redacted before forwarding to upstream")
}

// TestGateway_Upstream429_RateLimitError verifies rate-limit errors from the
// upstream are forwarded cleanly to the client.
func TestGateway_Upstream429_RateLimitError(t *testing.T) {
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-ratelimit-remaining-requests", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"Rate limit reached","type":"rate_limit_error"}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "Rate limit reached")
	assert.Equal(t, "0", w.Header().Get("x-ratelimit-remaining-requests"),
		"rate-limit headers from upstream must be forwarded")
}

// Gap G (CLOSED): SanitizeForEvidence prevents PII in evidence store.
func TestGateway_GapG_EvidenceSanitization(t *testing.T) {
	ctx := context.Background()
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)

	text := "Customer email: jan.kowalski@gmail.com, IBAN: DE89370400440532013000"
	sanitized := evidence.SanitizeForEvidence(ctx, text, scanner)

	assert.NotContains(t, sanitized, "jan.kowalski@gmail.com", "email should be sanitized")
	assert.NotContains(t, sanitized, "DE89370400440532013000", "IBAN should be sanitized")
	assert.NotEmpty(t, sanitized, "sanitized text should not be empty")
}

// ---------------------------------------------------------------------------
// Responses API integration tests — full gateway pipeline
// ---------------------------------------------------------------------------

// responsesAPIUpstream returns a handler that captures the forwarded body/path
// and responds with a valid Responses API JSON payload.
func responsesAPIUpstream(capturedBody *[]byte, capturedPath *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*capturedBody, _ = io.ReadAll(r.Body)
		*capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_ok","output":[{"type":"message","content":[{"type":"output_text","text":"Processed"}]}],"usage":{"input_tokens":10,"output_tokens":5}}`))
	}
}

func TestGateway_ResponsesAPI_RequestPII_StringInput(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	gw, _, _ := setupOpenClawGateway(t, "redact", responsesAPIUpstream(&capturedBody, &capturedPath))

	body := `{"model":"gpt-4o","input":"Send report to hans.mueller@example.de about the project"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.NotContains(t, forwarded, "hans.mueller@example.de",
		"email in Responses API string input must be redacted before forwarding")
	assert.Contains(t, forwarded, "report",
		"non-PII text must be preserved")
	assert.Contains(t, forwarded, `"store":true`,
		"store:true must be injected for Responses API")
	assert.Equal(t, "/v1/responses", capturedPath,
		"request must be routed to /v1/responses")
}

func TestGateway_ResponsesAPI_RequestPII_ArrayContentString(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	gw, _, _ := setupOpenClawGateway(t, "redact", responsesAPIUpstream(&capturedBody, &capturedPath))

	body := `{"model":"gpt-4o","input":[{"role":"user","content":"Contact alice@company.eu please"}]}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.NotContains(t, forwarded, "alice@company.eu",
		"email in Responses API array input content must be redacted")
	assert.Contains(t, forwarded, "Contact",
		"non-PII content must be preserved")
}

func TestGateway_ResponsesAPI_RequestPII_InputTextBlock(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	gw, _, _ := setupOpenClawGateway(t, "redact", responsesAPIUpstream(&capturedBody, &capturedPath))

	body := `{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"Email bob@test.eu now"}]}]}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.NotContains(t, forwarded, "bob@test.eu",
		"email in input_text block must be redacted")
	assert.Contains(t, forwarded, "input_text",
		"block type must be preserved")
}

func TestGateway_ResponsesAPI_ItemReferenceNotCorrupted(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	gw, _, _ := setupOpenClawGateway(t, "redact", responsesAPIUpstream(&capturedBody, &capturedPath))

	body := `{"model":"gpt-4o","input":[{"type":"item_reference","id":"rs_abc123"},{"role":"user","content":"Email alice@test.com"}],"previous_response_id":"rs_prev"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.NotContains(t, forwarded, "alice@test.com",
		"email must be redacted")
	assert.Contains(t, forwarded, "item_reference",
		"item_reference type must be preserved")
	assert.Contains(t, forwarded, "rs_abc123",
		"reference ID must be preserved")
	assert.Contains(t, forwarded, "rs_prev",
		"previous_response_id must be preserved")
	assert.NotContains(t, forwarded, `"content":null`,
		"content:null must NOT be added to items that had no content field")
}

// TestGateway_ResponsesAPI_ResponsePIIRedacted verifies PII in Responses API
// output is detected and redacted before reaching the client.
func TestGateway_ResponsesAPI_ResponsePIIRedacted(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_pii","output":[{"type":"message","content":[{"type":"output_text","text":"The support email is support@company.eu"}]}],"usage":{"input_tokens":10,"output_tokens":15}}`))
	})

	gw, _, evStore := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o","input":"What is the support email?"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	respBody := w.Body.String()
	assert.NotContains(t, respBody, "support@company.eu",
		"email in Responses API output must be redacted")
	assert.Contains(t, respBody, "resp_pii",
		"response ID must be preserved in envelope")
	assert.Contains(t, respBody, "output_text",
		"output_text type must be preserved")

	// Evidence should record output PII detection
	time.Sleep(50 * time.Millisecond)
	list, err := evStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	found := false
	for _, ev := range list {
		if ev.Classification.OutputPIIDetected {
			found = true
			assert.NotEmpty(t, ev.Classification.OutputPIITypes)
		}
	}
	assert.True(t, found, "evidence should record OutputPIIDetected for Responses API")
}

// TestGateway_ResponsesAPI_ResponsePIIBlock verifies PII block mode replaces
// Responses API output with a safe error.
func TestGateway_ResponsesAPI_ResponsePIIBlock(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_block","output":[{"type":"message","content":[{"type":"output_text","text":"Your IBAN is DE89370400440532013000"}]}],"usage":{"input_tokens":10,"output_tokens":15}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "block"

	body := `{"model":"gpt-4o","input":"What is the IBAN?"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)

	assert.NotContains(t, w.Body.String(), "DE89370400440532013000",
		"IBAN must not appear in blocked response")
	assert.Contains(t, w.Body.String(), "PII",
		"block response should mention PII")
}

// TestGateway_ResponsesAPI_NoPIIPassesThrough verifies requests and responses
// without PII pass through unmodified (except store:true injection).
func TestGateway_ResponsesAPI_NoPIIPassesThrough(t *testing.T) {
	expectedOutput := `{"id":"resp_clean","output":[{"type":"message","content":[{"type":"output_text","text":"Greenland has a Premier, not a president."}]}],"usage":{"input_tokens":10,"output_tokens":12}}`

	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedOutput))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o","input":"Who is the president of Greenland?"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	// Request body should have store:true injected but content unchanged
	forwarded := string(capturedBody)
	assert.Contains(t, forwarded, "Who is the president of Greenland",
		"non-PII input must be preserved")
	assert.Contains(t, forwarded, `"store":true`,
		"store:true must be injected")

	// Response should pass through unmodified
	assert.Contains(t, w.Body.String(), "Greenland has a Premier",
		"non-PII response must pass through")
	assert.Contains(t, w.Body.String(), "resp_clean",
		"envelope must be preserved")
}

// TestGateway_ResponsesAPI_BlockRequestPII verifies that block mode rejects
// Responses API requests containing PII before they reach the upstream.
func TestGateway_ResponsesAPI_BlockRequestPII(t *testing.T) {
	upstreamCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	})

	gw, _, _ := setupOpenClawGateway(t, "block", handler)

	body := `{"model":"gpt-4o","input":"Contact hans.mueller@example.de about the report"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"block mode should return 400 when PII detected in Responses API input")
	assert.False(t, upstreamCalled,
		"upstream must NOT be called when PII is blocked")
	assert.Contains(t, w.Body.String(), "PII",
		"error response should mention PII")
}

// TestGateway_ResponsesAPI_StreamingResponsePIIRedacted verifies that when a
// client sends "stream":true, the gateway forces non-streaming so response PII
// scanning still works. This reproduces the bug where OpenClaw sends
// "stream":true and model-generated PII in the response bypasses scanning.
func TestGateway_ResponsesAPI_StreamingResponsePIIRedacted(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_stream","output":[{"type":"message","content":[{"type":"output_text","text":"aurora@stellarsystems.eu"}]}],"usage":{"input_tokens":10,"output_tokens":5}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	// Client sends stream:true (like OpenClaw does)
	body := `{"model":"gpt-4o","input":"Invent a fictional European email","stream":true}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	// Upstream must receive stream:false (forced by gateway for PII scanning)
	assert.Contains(t, string(capturedBody), `"stream":false`,
		"gateway must force stream:false when response PII scanning is enabled")
	assert.NotContains(t, string(capturedBody), `"stream":true`,
		"client's stream:true must be overwritten")

	// Response PII must be redacted
	respBody := w.Body.String()
	assert.NotContains(t, respBody, "aurora@stellarsystems.eu",
		"email in response must be redacted even when client requested streaming")
	assert.Contains(t, respBody, "output_text",
		"response structure must be preserved")
}

// TestGateway_ChatCompletions_StreamingResponsePIIRedacted verifies the same
// fix works for Chat Completions API with stream:true.
func TestGateway_ChatCompletions_StreamingResponsePIIRedacted(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test","choices":[{"message":{"content":"Contact alice@company.eu for details"}}],"usage":{"prompt_tokens":10,"completion_tokens":8}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Invent an email"}],"stream":true}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	// Upstream must receive stream:false
	assert.Contains(t, string(capturedBody), `"stream":false`,
		"gateway must force stream:false for Chat Completions too")

	// Response PII must be redacted
	assert.NotContains(t, w.Body.String(), "alice@company.eu",
		"email in Chat Completions response must be redacted when stream was forced off")
}

// TestGateway_StreamingAllowed_WhenPIIActionAllow verifies that streaming is
// NOT disabled when the response PII action is "allow".
func TestGateway_StreamingAllowed_WhenPIIActionAllow(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_allow","output":[{"type":"message","content":[{"type":"output_text","text":"OK"}]}],"usage":{"input_tokens":5,"output_tokens":2}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "allow", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "allow"

	body := `{"model":"gpt-4o","input":"Hello","stream":true}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	// When PII action is "allow", streaming should be preserved
	assert.Contains(t, string(capturedBody), `"stream":true`,
		"stream:true must be preserved when response PII action is allow")
}

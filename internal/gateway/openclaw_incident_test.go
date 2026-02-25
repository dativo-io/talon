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
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/openai/v1/chat/completions",
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

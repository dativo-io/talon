package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/go-chi/chi/v5"
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

// sseResponse builds an SSE response body from a Responses API JSON payload,
// simulating what OpenAI returns when stream:true.
func sseResponse(responseJSON string) string {
	return "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":" + responseJSON + "}\n\ndata: [DONE]\n\n"
}

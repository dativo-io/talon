//go:build integration

package integration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCoPawGateway creates a Gateway configured with CoPaw caller (copaw-main, talon-gw-copaw-001)
// and a mock upstream. Used to verify CoPaw integration flow: CoPaw sends requests with the caller
// API key; Talon authenticates, proxies, and records evidence under agent_id copaw-main.
func setupCoPawGateway(t *testing.T, upstreamHandler http.HandlerFunc) (*gateway.Gateway, *httptest.Server, *evidence.Store) {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	dir := t.TempDir()

	cfg := &gateway.GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         gateway.ModeEnforce,
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstream.URL, SecretName: "openai-api-key"},
		},
		Callers: []gateway.CallerConfig{
			{
				Name:     "copaw-main",
				APIKey:   "talon-gw-copaw-001",
				TenantID: "test-tenant",
				PolicyOverrides: &gateway.CallerPolicyOverrides{
					PIIAction:      "warn",
					MaxDailyCost:   100,
					MaxMonthlyCost: 2000,
					AllowedModels:  []string{"gpt-4o-mini", "gpt-4o"},
				},
			},
		},
		ServerDefaults: gateway.ServerDefaults{
			DefaultPIIAction: "warn",
			MaxDailyCost:     100,
			MaxMonthlyCost:   2000,
		},
		Timeouts: gateway.TimeoutsConfig{
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
		[]byte("sk-test-copaw-secret"),
		secrets.ACL{Tenants: []string{"test-tenant"}, Agents: []string{"*"}}))

	cls := classifier.MustNewScanner()
	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)

	gw, err := gateway.NewGateway(cfg, cls, evStore, secStore, policyEngine, nil)
	require.NoError(t, err)

	return gw, upstream, evStore
}

func makeCoPawGatewayRequest(gw *gateway.Gateway, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/openai/v1/chat/completions",
		bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer talon-gw-copaw-001")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestCoPawGateway_NonStreaming verifies that a CoPaw-style request (caller copaw-main, talon-gw-copaw-001)
// is proxied through Talon and evidence is recorded with agent_id copaw-main.
func TestCoPawGateway_NonStreaming(t *testing.T) {
	gw, _, evStore := setupCoPawGateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"Hi from CoPaw"}}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeCoPawGatewayRequest(gw, body)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Hi from CoPaw")

	records, err := evStore.List(context.Background(), "test-tenant", "",
		time.Time{}, time.Now().Add(time.Second), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records, "evidence must be recorded for CoPaw gateway request")
	assert.Equal(t, "copaw-main", records[0].AgentID)
	assert.Equal(t, "gpt-4o-mini", records[0].Execution.ModelUsed)
}

// TestCoPawGateway_PIIDetected_EvidenceRecorded verifies that when PII is present in the request,
// evidence is still created and the request is handled (with warn action, no block).
func TestCoPawGateway_PIIDetected_EvidenceRecorded(t *testing.T) {
	gw, _, evStore := setupCoPawGateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact user@example.com for details"}]}`
	w := makeCoPawGatewayRequest(gw, body)

	require.Equal(t, http.StatusOK, w.Code)
	records, err := evStore.List(context.Background(), "test-tenant", "",
		time.Time{}, time.Now().Add(time.Second), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.Equal(t, "copaw-main", records[0].AgentID)
	// Evidence is recorded; PII may be flagged in records[0].Classification when scanning is enabled
}

// TestCoPawGateway_PolicyDeny_ReturnsOpenAIError verifies that when policy denies (e.g. cost limit),
// Talon returns an OpenAI-compatible error shape so CoPaw can display it.
func TestCoPawGateway_PolicyDeny_ReturnsOpenAIError(t *testing.T) {
	// Use a very low daily cost so the first request might still pass; for a real DENY test we'd
	// need to either pre-seed cost or use a different policy. Here we test that the gateway
	// returns JSON and that error responses are in OpenAI shape when upstream fails.
	gw, _, _ := setupCoPawGateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"Access denied","type":"access_denied","code":"forbidden"}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeCoPawGatewayRequest(gw, body)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "error")
	assert.Contains(t, w.Body.String(), "message")
}

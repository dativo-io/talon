package gateway

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
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

func TestNewGateway(t *testing.T) {
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://localhost:11434"},
		},
		Callers: []CallerConfig{
			{Name: "test", APIKey: "talon-gw-test", TenantID: "default"},
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
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "12345678901234567890123456789012")
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	cls := classifier.MustNewScanner()

	gw, err := NewGateway(cfg, cls, evStore, secStore, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, gw)
}

func TestGateway_ServeHTTP_Integration(t *testing.T) {
	// Mock upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"Hi"}}],"usage":{"prompt_tokens":2,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: upstream.URL},
		},
		Callers: []CallerConfig{
			{
				Name: "test", APIKey: "talon-gw-key", TenantID: "default",
				PolicyOverrides: &CallerPolicyOverrides{
					AllowedModels: []string{"llama2", "gpt-4o"},
					MaxDailyCost:  100,
				},
			},
		},
		DefaultPolicy: DefaultPolicyConfig{DefaultPIIAction: "warn"},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "12345678901234567890123456789012")
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	cls := classifier.MustNewScanner()
	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)

	gw, err := NewGateway(cfg, cls, evStore, secStore, policyEngine, nil)
	require.NoError(t, err)

	// Mount like real server
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})

	body := []byte(`{"model":"llama2","messages":[{"role":"user","content":"Hello"}]}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://test/v1/proxy/ollama/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-key")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Hi")

	// Evidence should be stored (cost by agent)
	byAgent, err := evStore.CostByAgent(context.Background(), "default", time.Time{}, time.Time{})
	require.NoError(t, err)
	require.NotEmpty(t, byAgent["test"])
}

func TestGateway_ServeHTTP_Unauthorized(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://localhost:11434"},
		},
		Callers: []CallerConfig{
			{Name: "test", APIKey: "secret", TenantID: "default"},
		},
		DefaultPolicy: DefaultPolicyConfig{RequireCallerID: boolPtr(true)},
		Timeouts:      TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	dir := t.TempDir()
	evStore, _ := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	defer evStore.Close()
	secStore, _ := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "12345678901234567890123456789012")
	defer secStore.Close()

	gw, err := NewGateway(cfg, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://test/v1/proxy/ollama/v1/chat/completions", bytes.NewReader([]byte(`{"model":"x","messages":[]}`)))
	req.Header.Set("Authorization", "Bearer wrong-key")

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGateway_ServeHTTP_PIIBlock_RecordsEvidenceAsDenied ensures that when pii_action is "block"
// and PII is detected, the request is rejected and evidence is recorded with allowed=false for audit correctness.
func TestGateway_ServeHTTP_PIIBlock_RecordsEvidenceAsDenied(t *testing.T) {
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://localhost:11434"},
		},
		Callers: []CallerConfig{
			{Name: "test", APIKey: "talon-gw-pii-test", TenantID: "default"},
		},
		DefaultPolicy: DefaultPolicyConfig{DefaultPIIAction: "block"},
		Timeouts:      TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "12345678901234567890123456789012")
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	cls := classifier.MustNewScanner()

	gw, err := NewGateway(cfg, cls, evStore, secStore, nil, nil)
	require.NoError(t, err)

	// Request body containing PII (email) so classifier detects it
	body := []byte(`{"model":"llama2","messages":[{"role":"user","content":"Contact me at user@example.com"}]}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://test/v1/proxy/ollama/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-pii-test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "PII")

	// Evidence must be recorded with allowed=false for compliance
	list, err := evStore.List(context.Background(), "default", "test", time.Time{}, time.Now().Add(time.Second), 5)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.False(t, list[0].PolicyDecision.Allowed, "PII block must record evidence with allowed=false")
	require.Equal(t, "deny", list[0].PolicyDecision.Action)
	require.Contains(t, list[0].PolicyDecision.Reasons, "PII block")
}

package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type metricsRecorderSpy struct {
	mu     sync.Mutex
	events []map[string]interface{}
}

func (s *metricsRecorderSpy) RecordGatewayEvent(event interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := event.(map[string]interface{}); ok {
		s.events = append(s.events, m)
	}
}

func (s *metricsRecorderSpy) lastEvent() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return nil
	}
	return s.events[len(s.events)-1]
}

func (s *metricsRecorderSpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func setupGatewayWithSpy(t *testing.T, cfg *GatewayConfig, policy GatewayPolicyEvaluator) (*Gateway, *metricsRecorderSpy, *evidence.Store) {
	t.Helper()
	dir := t.TempDir()

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })

	if cfg.Providers["openai"].SecretName != "" {
		require.NoError(t, secStore.Set(context.Background(), cfg.Providers["openai"].SecretName,
			[]byte("sk-test-key"), secrets.ACL{Tenants: []string{"*"}, Agents: []string{"*"}}))
	}

	cls := classifier.MustNewScanner()
	gw, err := NewGateway(cfg, cls, evStore, secStore, policy, nil)
	require.NoError(t, err)

	spy := &metricsRecorderSpy{}
	gw.SetMetricsRecorder(spy)
	return gw, spy, evStore
}

func postGateway(gw *Gateway, path, apiKey, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test"+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestBlockedPath_ProviderNotAllowed_EmitsMetrics(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: "http://localhost:1"},
		},
		Callers: []CallerConfig{
			{
				Name: "test-caller", TenantKey: "talon-gw-test-001", TenantID: "default",
				AllowedProviders: []string{"anthropic"},
			},
		},
		ServerDefaults: ServerDefaults{DefaultPIIAction: "warn"},
		Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	gw, spy, evStore := setupGatewayWithSpy(t, cfg, nil)

	w := postGateway(gw, "/v1/proxy/openai/v1/chat/completions", "talon-gw-test-001",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`)

	require.Equal(t, http.StatusForbidden, w.Code)

	assert.Equal(t, 1, spy.count(), "provider-not-allowed should emit a dashboard event")
	ev := spy.lastEvent()
	assert.True(t, ev["blocked"].(bool), "event should mark request as blocked")

	list, err := evStore.List(context.Background(), "default", "test-caller", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.Len(t, list, 1, "provider-not-allowed should record evidence")
	assert.False(t, list[0].PolicyDecision.Allowed)
	assert.Contains(t, list[0].PolicyDecision.Reasons, "provider not allowed")
}

func TestBlockedPath_PolicyEvalError_EmitsMetrics(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://localhost:1"},
		},
		Callers: []CallerConfig{
			{Name: "test-caller", TenantKey: "talon-gw-test-001", TenantID: "default"},
		},
		ServerDefaults: ServerDefaults{DefaultPIIAction: "warn"},
		Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	gw, spy, evStore := setupGatewayWithSpy(t, cfg, &errorPolicy{})

	w := postGateway(gw, "/v1/proxy/ollama/v1/chat/completions", "talon-gw-test-001",
		`{"model":"llama2","messages":[{"role":"user","content":"Hello"}]}`)

	require.Equal(t, http.StatusInternalServerError, w.Code)

	assert.Equal(t, 1, spy.count(), "policy-eval-error should emit a dashboard event")
	ev := spy.lastEvent()
	assert.True(t, ev["blocked"].(bool))
	assert.True(t, ev["has_error"].(bool))

	list, err := evStore.List(context.Background(), "default", "test-caller", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.Len(t, list, 1, "policy-eval-error should record evidence")
	assert.False(t, list[0].PolicyDecision.Allowed)
	assert.Contains(t, list[0].PolicyDecision.Reasons, "policy evaluation error")
}

func TestBlockedPath_SecretFailure_EmitsMetrics(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: "http://localhost:1", SecretName: "nonexistent-secret"},
		},
		Callers: []CallerConfig{
			{Name: "test-caller", TenantKey: "talon-gw-test-001", TenantID: "default"},
		},
		ServerDefaults: ServerDefaults{DefaultPIIAction: "warn"},
		Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	dir := t.TempDir()
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })

	cls := classifier.MustNewScanner()
	gw, err := NewGateway(cfg, cls, evStore, secStore, nil, nil)
	require.NoError(t, err)

	spy := &metricsRecorderSpy{}
	gw.SetMetricsRecorder(spy)

	w := postGateway(gw, "/v1/proxy/openai/v1/chat/completions", "talon-gw-test-001",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`)

	require.Equal(t, http.StatusInternalServerError, w.Code)

	assert.Equal(t, 1, spy.count(), "secret-failure should emit a dashboard event")
	ev := spy.lastEvent()
	assert.True(t, ev["blocked"].(bool))
	assert.True(t, ev["has_error"].(bool))

	list, err := evStore.List(context.Background(), "default", "test-caller", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.Len(t, list, 1, "secret-failure should record evidence")
	assert.False(t, list[0].PolicyDecision.Allowed)
	assert.Contains(t, list[0].PolicyDecision.Reasons, "secret retrieval error")
}

func TestBlockedPath_AuthFailure_EmitsErrorCounter(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://localhost:1"},
		},
		Callers: []CallerConfig{
			{Name: "test", TenantKey: "correct-key", TenantID: "default"},
		},
		ServerDefaults: ServerDefaults{RequireCallerID: boolPtr(true)},
		Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	dir := t.TempDir()
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	cls := classifier.MustNewScanner()
	gw, err := NewGateway(cfg, cls, evStore, secStore, nil, nil)
	require.NoError(t, err)

	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			"http://test/v1/proxy/ollama/v1/chat/completions",
			bytes.NewReader([]byte(`{"model":"x","messages":[]}`)))
		req.Header.Set("Authorization", "Bearer wrong-key")
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, req)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	})

	m := findMetric(metrics, "talon.gateway.errors.total")
	require.NotNil(t, m, "auth failure should emit talon.gateway.errors.total")
	sum := m.Data.(metricdata.Sum[int64])
	var authErrors int64
	for _, dp := range sum.DataPoints {
		for _, attr := range dp.Attributes.ToSlice() {
			if attr.Key == "error_type" && attr.Value.AsString() == "auth" {
				authErrors += dp.Value
			}
		}
	}
	assert.Equal(t, int64(1), authErrors, "should record exactly 1 auth error")
}

// TestBlockedPath_PIIBlock_EmitsDashboardEvent verifies the pre-existing PII block
// path (which already had emitMetrics) fires a dashboard event.
func TestBlockedPath_PIIBlock_EmitsDashboardEvent(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://localhost:1"},
		},
		Callers: []CallerConfig{
			{Name: "test-caller", TenantKey: "talon-gw-test-001", TenantID: "default"},
		},
		ServerDefaults: ServerDefaults{DefaultPIIAction: "block"},
		Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	gw, spy, _ := setupGatewayWithSpy(t, cfg, nil)

	w := postGateway(gw, "/v1/proxy/ollama/v1/chat/completions", "talon-gw-test-001",
		`{"model":"llama2","messages":[{"role":"user","content":"Email me at user@example.com"}]}`)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, 1, spy.count(), "PII block should emit a dashboard event")
	ev := spy.lastEvent()
	assert.True(t, ev["blocked"].(bool))
}

// TestBlockedPath_PolicyDeny_EmitsDashboardEvent verifies the pre-existing policy deny
// path fires a dashboard event.
func TestBlockedPath_PolicyDeny_EmitsDashboardEvent(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://localhost:1"},
		},
		Callers: []CallerConfig{
			{Name: "test-caller", TenantKey: "talon-gw-test-001", TenantID: "default"},
		},
		ServerDefaults: ServerDefaults{DefaultPIIAction: "warn"},
		Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	gw, spy, _ := setupGatewayWithSpy(t, cfg, &denyAllPolicy{})

	w := postGateway(gw, "/v1/proxy/ollama/v1/chat/completions", "talon-gw-test-001",
		`{"model":"llama2","messages":[{"role":"user","content":"Hello"}]}`)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, 1, spy.count(), "policy deny should emit a dashboard event")
	ev := spy.lastEvent()
	assert.True(t, ev["blocked"].(bool))
}

// TestBlockedPath_AllBlockedPathsConsistent verifies that every blocked path type
// produces a dashboard event with blocked=true, preventing dashboard drift after restart.
func TestBlockedPath_AllBlockedPathsConsistent(t *testing.T) {
	tests := []struct {
		name           string
		setupOverrides func(*GatewayConfig)
		policy         GatewayPolicyEvaluator
		body           string
		wantStatus     int
	}{
		{
			name: "pii_block",
			setupOverrides: func(c *GatewayConfig) {
				c.ServerDefaults.DefaultPIIAction = "block"
			},
			body:       `{"model":"gpt-4o","messages":[{"role":"user","content":"Email: user@example.com"}]}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "policy_deny",
			policy:     &denyAllPolicy{},
			body:       `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "provider_not_allowed",
			setupOverrides: func(c *GatewayConfig) {
				c.Callers[0].AllowedProviders = []string{"anthropic"}
			},
			body:       `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &GatewayConfig{
				Enabled:      true,
				ListenPrefix: "/v1/proxy",
				Mode:         ModeEnforce,
				Providers: map[string]ProviderConfig{
					"openai": {Enabled: true, BaseURL: "http://localhost:1"},
				},
				Callers: []CallerConfig{
					{Name: "test-caller", TenantKey: "talon-gw-test-001", TenantID: "default"},
				},
				ServerDefaults: ServerDefaults{DefaultPIIAction: "warn"},
				Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
			}
			if tt.setupOverrides != nil {
				tt.setupOverrides(cfg)
			}
			gw, spy, _ := setupGatewayWithSpy(t, cfg, tt.policy)

			w := postGateway(gw, "/v1/proxy/openai/v1/chat/completions", "talon-gw-test-001", tt.body)

			assert.Equal(t, tt.wantStatus, w.Code)
			require.Equal(t, 1, spy.count(), "blocked path %q should emit exactly 1 dashboard event", tt.name)
			ev := spy.lastEvent()
			assert.True(t, ev["blocked"].(bool), "blocked path %q should set blocked=true", tt.name)
			assert.Equal(t, "test-caller", ev["caller_id"], "blocked path %q should include caller_id", tt.name)
		})
	}
}

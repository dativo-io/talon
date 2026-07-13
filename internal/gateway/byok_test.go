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
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestGateway_BYOKClientBearerForwarded(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	gw, evStore, agent := newBYOKGateway(t, upstream.URL)
	req := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	req.Header.Set("Authorization", "Bearer sk-client-key")
	req = req.WithContext(WithQuickstartIdentity(req.Context(), agent))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer sk-client-key" {
		t.Fatalf("upstream auth = %q", gotAuth)
	}
	list, err := evStore.List(context.Background(), agent.TenantID, agent.Name, time.Time{}, time.Time{}, 10)
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("expected evidence record for byok request")
	}
	if list[0].UpstreamAuthMode != "client_bearer" {
		t.Fatalf("upstream_auth_mode = %q", list[0].UpstreamAuthMode)
	}
	if list[0].UpstreamKeySource != "client" {
		t.Fatalf("upstream_key_source = %q", list[0].UpstreamKeySource)
	}
	if len(list[0].UpstreamKeyFingerprint) != 12 {
		t.Fatalf("unexpected upstream key fingerprint: %q", list[0].UpstreamKeyFingerprint)
	}
	if list[0].UpstreamKeyFingerprint == "sk-client-key" {
		t.Fatalf("fingerprint must not store raw key")
	}
}

func TestGateway_BYOKEnvFallback(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-env-fallback")

	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	gw, _, agent := newBYOKGateway(t, upstream.URL)
	req := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	req = req.WithContext(WithQuickstartIdentity(req.Context(), agent))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer sk-env-fallback" {
		t.Fatalf("upstream auth = %q", gotAuth)
	}
	evs, err := newEvidenceList(t, gw, agent)
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	if len(evs) == 0 {
		t.Fatalf("expected evidence record")
	}
	if evs[0].UpstreamKeySource != "env" {
		t.Fatalf("upstream_key_source = %q", evs[0].UpstreamKeySource)
	}
}

func TestGateway_BYOKMissingKeyReturns401(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called")
	}))
	defer upstream.Close()

	gw, _, agent := newBYOKGateway(t, upstream.URL)
	req := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	req = req.WithContext(WithQuickstartIdentity(req.Context(), agent))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// newBYOKGateway mirrors the quickstart wiring: a nil registry (no keyed
// agents) and the synthetic quickstart identity injected via request context.
func newBYOKGateway(t *testing.T, upstreamURL string) (*Gateway, *evidence.Store, *ResolvedIdentity) {
	t.Helper()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstreamURL, UpstreamAuthMode: "client_bearer"},
		},
		OrganizationPolicy: OrganizationPolicy{
			Defaults: OrgDefaults{PIIAction: "redact"},
		},
		RateLimits: RateLimitsConfig{
			GlobalRequestsPerMin:   1000,
			PerAgentRequestsPerMin: 1000,
		},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	// This helper mirrors the in-process quickstart profile — the only
	// context where client_bearer validates (#266).
	cfg.EnableQuickstartProfile()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate cfg: %v", err)
	}
	dir := t.TempDir()
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	if err != nil {
		t.Fatalf("new evidence store: %v", err)
	}
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	if err != nil {
		t.Fatalf("new secrets store: %v", err)
	}
	t.Cleanup(func() { _ = secStore.Close() })
	gw, err := NewGateway(cfg, NewRegistryHolder(nil), classifier.MustNewScanner(), evStore, secStore, nil, nil)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return gw, evStore, NewQuickstartIdentity()
}

func gatewayRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://talon.local/v1/proxy/openai/v1/chat/completions", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func newEvidenceList(t *testing.T, gw *Gateway, agent *ResolvedIdentity) ([]evidence.Evidence, error) {
	t.Helper()
	if gw == nil || gw.evidenceStore == nil {
		return nil, nil
	}
	return gw.evidenceStore.List(context.Background(), agent.TenantID, agent.Name, time.Time{}, time.Time{}, 10)
}

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestGateway_QuickstartCallerFromContextOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	gw, evStore, quickstartCaller := newBYOKGateway(t, upstream.URL)

	// No context caller and no bearer key: caller resolves via existing fallback.
	req := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with missing upstream key, got %d", rec.Code)
	}
	records, err := evStore.List(context.Background(), "", "", time.Time{}, time.Time{}, 20)
	if err != nil {
		t.Fatalf("listing evidence: %v", err)
	}
	for i := range records {
		if records[i].AgentID == quickstartCaller.Name {
			t.Fatalf("unexpected quickstart caller from fallback path")
		}
	}

	// Context caller must be honored.
	req2 := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	req2.Header.Set("Authorization", "Bearer sk-context")
	req2 = req2.WithContext(WithQuickstartCaller(req2.Context(), quickstartCaller))
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec2.Code, rec2.Body.String())
	}
	got, err := evStore.List(context.Background(), quickstartCaller.TenantID, quickstartCaller.Name, time.Time{}, time.Time{}, 20)
	if err != nil {
		t.Fatalf("listing evidence by caller: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected quickstart evidence record")
	}

	// Header-only "claim" must not impersonate quickstart-local identity.
	req3 := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	req3.Header.Set("X-Talon-Caller", quickstartCaller.Name)
	req3.Header.Set("Authorization", "Bearer sk-no-context")
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized && rec3.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rec3.Code)
	}
	all, err := evStore.List(context.Background(), "", "", time.Time{}, time.Time{}, 50)
	if err != nil {
		t.Fatalf("listing all evidence: %v", err)
	}
	// Decode full records to ensure there is at least one non-quickstart caller.
	foundNonQuickstart := false
	for i := range all {
		if all[i].AgentID != quickstartCaller.Name {
			foundNonQuickstart = true
			break
		}
	}
	if !foundNonQuickstart {
		t.Fatalf("expected at least one non-quickstart caller from non-context request")
	}
}

func TestQuickstartCallerContextHelpers(t *testing.T) {
	caller := &CallerConfig{Name: "quickstart-local", TenantID: "quickstart"}
	ctx := context.Background()
	if QuickstartCallerFromContext(ctx) != nil {
		t.Fatalf("unexpected caller in empty context")
	}
	ctx = WithQuickstartCaller(ctx, caller)
	got := QuickstartCallerFromContext(ctx)
	if got == nil || got.Name != caller.Name || got.TenantID != caller.TenantID {
		raw, _ := json.Marshal(got)
		t.Fatalf("unexpected caller: %s", string(raw))
	}
}

func TestGateway_AnonymousFallbackWhenCallerIDNotRequired(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstream.URL, UpstreamAuthMode: "client_bearer"},
		},
		ServerDefaults: ServerDefaults{
			DefaultPIIAction: "redact",
			RequireCallerID:  boolPtr(false),
		},
		RateLimits: RateLimitsConfig{
			GlobalRequestsPerMin:    1000,
			PerCallerRequestsPerMin: 1000,
		},
		Timeouts: TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	dir := t.TempDir()
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	if err != nil {
		t.Fatalf("evidence store: %v", err)
	}
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	if err != nil {
		t.Fatalf("secrets store: %v", err)
	}
	t.Cleanup(func() { _ = secStore.Close() })
	gw, err := NewGateway(cfg, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://talon.local/v1/proxy/openai/v1/chat/completions",
		bytes.NewBufferString(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Authorization", "Bearer sk-anon")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	records, err := evStore.List(context.Background(), "default", "anonymous", time.Time{}, time.Time{}, 10)
	if err != nil {
		t.Fatalf("listing evidence: %v", err)
	}
	if len(records) == 0 {
		t.Fatalf("expected anonymous fallback evidence")
	}
}

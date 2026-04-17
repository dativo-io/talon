package server

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
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestQuickstartFacade_PathMappingAnd404(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	facade, _ := newFacadeForTest(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-facade")
	rec := httptest.NewRecorder()
	facade.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("upstream path=%q", gotPath)
	}

	reqNotFound := httptest.NewRequest(http.MethodPost, "/v1/embeddings", nil)
	recNotFound := httptest.NewRecorder()
	facade.ServeHTTP(recNotFound, reqNotFound)
	if recNotFound.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recNotFound.Code, recNotFound.Body.String())
	}
	if !strings.Contains(recNotFound.Body.String(), "partial OpenAI compatibility") {
		t.Fatalf("expected partial compatibility message, got %s", recNotFound.Body.String())
	}
}

func TestQuickstartFacade_ResponsesStoreInjection(t *testing.T) {
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	facade, _ := newFacadeForTest(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(`{"model":"gpt-4o-mini","input":"hello","store":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-facade")
	rec := httptest.NewRecorder()
	facade.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(string(gotBody), `"store":true`) {
		t.Fatalf("expected store:true injection, body=%s", string(gotBody))
	}
}

func TestQuickstartFacade_InjectsSyntheticCaller(t *testing.T) {
	var gotTenant string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	facade, evStore := newFacadeForTest(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-facade")
	rec := httptest.NewRecorder()
	facade.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	list, err := evStore.List(context.Background(), "quickstart", "quickstart-local", time.Time{}, time.Time{}, 10)
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	if len(list) == 0 {
		t.Fatalf("expected quickstart evidence record")
	}
	gotTenant = list[0].TenantID
	if gotTenant != "quickstart" {
		t.Fatalf("tenant=%q", gotTenant)
	}
}

func newFacadeForTest(t *testing.T, upstreamURL string) (http.Handler, *evidence.Store) {
	t.Helper()
	cfg := &gateway.GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         gateway.ModeEnforce,
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstreamURL, UpstreamAuthMode: "client_bearer"},
		},
		Callers: []gateway.CallerConfig{
			{Name: "quickstart-local", TenantID: "quickstart", Tags: []string{"quickstart"}, AllowedProviders: []string{"openai"}},
		},
		ServerDefaults: gateway.ServerDefaults{
			DefaultPIIAction: "redact",
			RequireCallerID:  boolPtr(false),
		},
		RateLimits: gateway.RateLimitsConfig{GlobalRequestsPerMin: 1000, PerCallerRequestsPerMin: 1000},
		Timeouts: gateway.TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate cfg: %v", err)
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
	gw, err := gateway.NewGateway(cfg, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return newQuickstartFacade(gw, "/v1/proxy", &cfg.Callers[0]), evStore
}

func boolPtr(b bool) *bool { return &b }

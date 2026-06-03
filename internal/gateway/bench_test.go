package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/go-chi/chi/v5"
)

// BenchmarkGatewayPipelineOverhead measures end-to-end gateway wall time for one
// non-streaming chat completion through ServeHTTP, with a local mock upstream (no
// WAN RTT). This approximates Talon pipeline overhead for a typical payload:
// route, caller auth, PII scan, policy evaluation, forward, response PII scan,
// evidence write, and metrics.
func BenchmarkGatewayPipelineOverhead(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	}))
	defer upstream.Close()

	dir := b.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"ollama": {Enabled: true, BaseURL: upstream.URL},
		},
		Callers: []CallerConfig{
			{
				Name: "bench-caller", TenantKey: "talon-gw-bench", TenantID: "default",
				PolicyOverrides: &CallerPolicyOverrides{
					AllowedModels: []string{"llama2"},
					MaxDailyCost:  1000,
				},
			},
		},
		ServerDefaults: ServerDefaults{DefaultPIIAction: "warn"},
		RateLimits: RateLimitsConfig{
			GlobalRequestsPerMin:    1_000_000,
			PerCallerRequestsPerMin: 1_000_000,
		},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	if err != nil {
		b.Fatal(err)
	}
	defer evStore.Close()

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	if err != nil {
		b.Fatal(err)
	}
	defer secStore.Close()

	cls := classifier.MustNewScanner()
	policyEngine, err := policy.NewGatewayEngine(context.Background())
	if err != nil {
		b.Fatal(err)
	}

	gw, err := NewGateway(cfg, cls, evStore, secStore, policyEngine, nil)
	if err != nil {
		b.Fatal(err)
	}

	router := chi.NewRouter()
	router.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})

	// Representative user text with EU PII patterns (email + IBAN).
	body := []byte(`{"model":"llama2","messages":[{"role":"user","content":"Contact hans.mueller@acme.de about IBAN DE89370400440532013000"}]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://test/v1/proxy/ollama/v1/chat/completions", bytes.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer talon-gw-bench")
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	}
}

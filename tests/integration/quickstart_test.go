//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/server"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestQuickstartFacadeGatewayIntegration_BYOKAndFallback(t *testing.T) {
	t.Run("client bearer", func(t *testing.T) {
		var upstreamAuth string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
		}))
		defer upstream.Close()

		api, evStore := newQuickstartIntegrationServer(t, upstream.URL)
		defer api.Close()

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, api.URL+"/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-client-integration")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "Bearer sk-client-integration", upstreamAuth)

		list, err := evStore.List(context.Background(), "quickstart", "quickstart-local", time.Time{}, time.Time{}, 10)
		require.NoError(t, err)
		require.NotEmpty(t, list)
		require.Equal(t, "client_bearer", list[0].UpstreamAuthMode)
		require.Equal(t, "client", list[0].UpstreamKeySource)
		require.NotEmpty(t, list[0].UpstreamKeyFingerprint)
	})

	t.Run("env fallback", func(t *testing.T) {
		t.Setenv("OPENAI_API_KEY", "sk-env-integration")
		var upstreamAuth string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
		}))
		defer upstream.Close()

		api, evStore := newQuickstartIntegrationServer(t, upstream.URL)
		defer api.Close()
		resp, err := http.Post(api.URL+"/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "Bearer sk-env-integration", upstreamAuth)

		list, err := evStore.List(context.Background(), "quickstart", "quickstart-local", time.Time{}, time.Time{}, 10)
		require.NoError(t, err)
		require.NotEmpty(t, list)
		require.Equal(t, "env", list[0].UpstreamKeySource)
	})
}

func TestQuickstartFacadeGatewayIntegration_401AndRedactAndResponses(t *testing.T) {
	var capturedBodies [][]byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBodies = append(capturedBodies, body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/responses"):
			_, _ = w.Write([]byte(`{"id":"resp_1","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}`))
		default:
			_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
		}
	}))
	defer upstream.Close()

	api, _ := newQuickstartIntegrationServer(t, upstream.URL)
	defer api.Close()

	// No key anywhere => 401.
	resp401, err := http.Post(api.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
	require.NoError(t, err)
	defer resp401.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp401.StatusCode)

	// PII redaction by default.
	reqPII, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, api.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"IBAN DE89370400440532013000"}]}`))
	reqPII.Header.Set("Content-Type", "application/json")
	reqPII.Header.Set("Authorization", "Bearer sk-redact")
	respPII, err := http.DefaultClient.Do(reqPII)
	require.NoError(t, err)
	defer respPII.Body.Close()
	require.Equal(t, http.StatusOK, respPII.StatusCode)
	require.NotEmpty(t, capturedBodies)
	require.NotContains(t, string(capturedBodies[len(capturedBodies)-1]), "DE89370400440532013000")

	// Responses API under quickstart's force_if_absent mode: an explicit
	// client store:false is honored (#213), not reversed.
	reqResp, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, api.URL+"/v1/responses",
		strings.NewReader(`{"model":"gpt-4o-mini","input":"hello","store":false}`))
	reqResp.Header.Set("Content-Type", "application/json")
	reqResp.Header.Set("Authorization", "Bearer sk-responses")
	resp1, err := http.DefaultClient.Do(reqResp)
	require.NoError(t, err)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	require.Contains(t, string(capturedBodies[len(capturedBodies)-1]), `"store":false`)

	// A request that references previous_response_id but omits store: absent →
	// force_if_absent injects store:true so the referenced response persists.
	reqResp2, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, api.URL+"/v1/responses",
		strings.NewReader(`{"model":"gpt-4o-mini","input":"follow up","previous_response_id":"resp_1"}`))
	reqResp2.Header.Set("Content-Type", "application/json")
	reqResp2.Header.Set("Authorization", "Bearer sk-responses")
	resp2, err := http.DefaultClient.Do(reqResp2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.Contains(t, string(capturedBodies[len(capturedBodies)-1]), `"store":true`)
}

func newQuickstartIntegrationServer(t *testing.T, upstreamURL string) (*httptest.Server, *evidence.Store) {
	t.Helper()

	quickstartCfg, err := gateway.QuickstartConfig(gateway.QuickstartOptions{OpenAIBaseURL: upstreamURL})
	require.NoError(t, err)

	dir := t.TempDir()
	evStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })

	pol := &policy.Policy{Agent: policy.AgentConfig{Name: "integration", Version: "1.0"}, Policies: policy.PoliciesConfig{}}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	gwPolicy, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)
	gw, err := gateway.NewGateway(quickstartCfg, classifier.MustNewScanner(), evStore, secStore, gwPolicy, nil)
	require.NoError(t, err)

	opts := []server.Option{
		server.WithGateway(gw),
		server.WithQuickstartEnabled(true),
		server.WithProxyQuickstart(server.NewQuickstartFacade(gw, quickstartCfg.ListenPrefix, &quickstartCfg.Callers[0])),
	}
	srv := server.NewServer(nil, evStore, nil, engine, pol, "", secStore, "", map[string]string{"quickstart": "quickstart"}, opts...)
	api := httptest.NewServer(srv.Routes())
	t.Cleanup(api.Close)
	return api, evStore
}

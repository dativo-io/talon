package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// OpenAI Responses API conformance suite for Codex-shaped traffic
// (#200, epic #192 PR-C).
//
// Each fixture under testdata/conformance/responses/ replays a recorded
// Codex-CLI-shaped request through the FULL gateway pipeline against a canned
// upstream, asserting the transforms tolerate real client body shapes
// (client_metadata, prompt_cache_key, full-transcript resend) and that the
// provider's responses_store_mode governs the "store" field. Codex facts
// verified 2026-07 against the openai/codex source: Responses-only wire, SSE
// terminated by response.completed, store:false everywhere except Azure.
// Fixtures are sanitized: synthetic keys, example.com corpus emails only.

const (
	respConfAgentKeyWarn   = "talon-gw-respconf-warn-01"
	respConfAgentKeyRedact = "talon-gw-respconf-redact-01"
)

type responsesFixture struct {
	Name string `json:"name"`
	// AgentPIIAction selects which registered agent replays the fixture
	// (warn or redact). The json tag matches the recorded fixture corpus.
	AgentPIIAction string          `json:"caller_pii_action"`
	RequestBody    json.RawMessage `json:"request_body"`
	Upstream       struct {
		Status    int             `json:"status"`
		JSON      json.RawMessage `json:"json,omitempty"`
		SSEEvents []string        `json:"sse_events,omitempty"`
	} `json:"upstream"`
	Expect struct {
		Status                 int      `json:"status"`
		ForwardedContains      []string `json:"forwarded_contains,omitempty"`
		ForwardedNotContains   []string `json:"forwarded_not_contains,omitempty"`
		ForwardedJSONValid     bool     `json:"forwarded_json_valid,omitempty"`
		ResponseEqualsUpstream bool     `json:"response_equals_upstream,omitempty"`
	} `json:"expect"`
}

type responsesUpstream struct {
	server   *httptest.Server
	lastBody atomic.Value // string
	fixture  atomic.Value // *responsesFixture
	rawSSE   atomic.Value // string
}

func newResponsesUpstream(t *testing.T) *responsesUpstream {
	t.Helper()
	u := &responsesUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.lastBody.Store(string(raw))
		fx, _ := u.fixture.Load().(*responsesFixture)
		if fx == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		status := fx.Upstream.Status
		if status == 0 {
			status = http.StatusOK
		}
		if len(fx.Upstream.SSEEvents) > 0 {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(status)
			var sb strings.Builder
			for _, ev := range fx.Upstream.SSEEvents {
				sb.WriteString(ev)
				sb.WriteString("\n\n")
			}
			u.rawSSE.Store(sb.String())
			_, _ = w.Write([]byte(sb.String()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(fx.Upstream.JSON)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func newResponsesConformanceGateway(t *testing.T, upstreamURL, storeMode string) (*evidence.Store, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstreamURL, SecretName: "openai-key", ResponsesStoreMode: storeMode},
		},
		// Response-side scanning stays out of request-path conformance:
		// "allow" keeps SSE streams passing through byte-identically.
		OrganizationPolicy: OrganizationPolicy{DefaultPIIAction: "warn", ResponsePIIAction: "allow", MaxDailyCost: 100, MaxMonthlyCost: 2000},
		RateLimits:         RateLimitsConfig{GlobalRequestsPerMin: 10000, PerAgentRequestsPerMin: 10000},
		Timeouts:           TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.Validate())
	registry := testRegistry(
		testIdentity("respconf-warn", "respconf-tenant", respConfAgentKeyWarn,
			&PolicyOverride{PIIAction: "warn", MaxDailyCost: 100, MaxMonthlyCost: 2000}),
		testIdentity("respconf-redact", "respconf-tenant", respConfAgentKeyRedact,
			&PolicyOverride{PIIAction: "redact", MaxDailyCost: 100, MaxMonthlyCost: 2000}),
	)
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "openai-key", []byte("sk-test-000-respconf"),
		secrets.ACL{Tenants: []string{"respconf-tenant"}, Agents: []string{"*"}}))
	gw, err := NewGateway(cfg, registry, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	return evStore, r
}

func sendResponsesRequest(t *testing.T, router http.Handler, body []byte, agentKey string) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/openai/v1/responses", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+agentKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestConformanceResponses_Fixtures(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "conformance", "responses"))
	require.NoError(t, err)
	upstream := newResponsesUpstream(t)
	// Fixtures run under the gateway default: responses_store_mode preserve.
	_, router := newResponsesConformanceGateway(t, upstream.server.URL, "")

	ran := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("testdata", "conformance", "responses", e.Name())) // #nosec G304 -- test fixtures
		require.NoError(t, err)
		var fx responsesFixture
		require.NoError(t, json.Unmarshal(raw, &fx), "fixture %s must parse", e.Name())
		ran++
		t.Run(fx.Name, func(t *testing.T) {
			upstream.fixture.Store(&fx)
			key := respConfAgentKeyWarn
			if fx.AgentPIIAction == "redact" {
				key = respConfAgentKeyRedact
			}
			w := sendResponsesRequest(t, router, fx.RequestBody, key)

			wantStatus := fx.Expect.Status
			if wantStatus == 0 {
				wantStatus = http.StatusOK
			}
			require.Equal(t, wantStatus, w.Code, "fixture %s: body: %s", fx.Name, w.Body.String())

			forwarded, _ := upstream.lastBody.Load().(string)
			require.NotEmpty(t, forwarded, "fixture %s: nothing reached the upstream", fx.Name)
			for _, s := range fx.Expect.ForwardedContains {
				assert.Contains(t, forwarded, s, "fixture %s: forwarded body must contain %q", fx.Name, s)
			}
			for _, s := range fx.Expect.ForwardedNotContains {
				assert.NotContains(t, forwarded, s, "fixture %s: forwarded body must not contain %q", fx.Name, s)
			}
			if fx.Expect.ForwardedJSONValid {
				var js map[string]interface{}
				assert.NoError(t, json.Unmarshal([]byte(forwarded), &js),
					"fixture %s: forwarded body must remain valid JSON", fx.Name)
			}
			if fx.Expect.ResponseEqualsUpstream {
				if len(fx.Upstream.SSEEvents) > 0 {
					raw, _ := upstream.rawSSE.Load().(string)
					assert.Equal(t, raw, w.Body.String(),
						"fixture %s: SSE stream must reach the client byte-identical (Codex requires the terminal response.completed)", fx.Name)
				} else {
					assert.JSONEq(t, string(fx.Upstream.JSON), w.Body.String(),
						"fixture %s: response must pass through", fx.Name)
				}
			}
		})
	}
	require.Greater(t, ran, 0, "no responses fixtures found")
}

// The three responses_store_mode values, end to end: preserve honors explicit
// client intent (#213), force_if_absent covers previous_response_id
// continuity, force_true records the override of explicit client intent in
// signed evidence.
func TestConformanceResponses_StoreModes(t *testing.T) {
	upstreamResp := json.RawMessage(`{"id":"resp_conf_store","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":8,"output_tokens":1}}`)
	newUpstream := func(t *testing.T) *responsesUpstream {
		u := newResponsesUpstream(t)
		fx := &responsesFixture{}
		fx.Upstream.Status = 200
		fx.Upstream.JSON = upstreamResp
		u.fixture.Store(fx)
		return u
	}
	storeFalseBody := []byte(`{"model":"gpt-5.3-codex","store":false,"input":"resend the full transcript"}`)
	storeAbsentBody := []byte(`{"model":"gpt-5.3-codex","input":"no store field at all"}`)

	t.Run("preserve honors explicit store false and leaves absent absent", func(t *testing.T) {
		u := newUpstream(t)
		_, router := newResponsesConformanceGateway(t, u.server.URL, ResponsesStorePreserve)

		w := sendResponsesRequest(t, router, storeFalseBody, respConfAgentKeyWarn)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		forwarded, _ := u.lastBody.Load().(string)
		assert.Contains(t, forwarded, `"store":false`, "explicit client store:false is a retention decision the gateway must not reverse")

		w = sendResponsesRequest(t, router, storeAbsentBody, respConfAgentKeyWarn)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		forwarded, _ = u.lastBody.Load().(string)
		assert.NotContains(t, forwarded, `"store"`, "preserve must not invent a store field")
	})

	t.Run("force_if_absent stores only when the client sent nothing", func(t *testing.T) {
		u := newUpstream(t)
		_, router := newResponsesConformanceGateway(t, u.server.URL, ResponsesStoreForceIfAbsent)

		w := sendResponsesRequest(t, router, storeAbsentBody, respConfAgentKeyWarn)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		forwarded, _ := u.lastBody.Load().(string)
		assert.Contains(t, forwarded, `"store":true`)

		w = sendResponsesRequest(t, router, storeFalseBody, respConfAgentKeyWarn)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		forwarded, _ = u.lastBody.Load().(string)
		assert.Contains(t, forwarded, `"store":false`, "explicit client intent is still honored")
	})

	t.Run("force_true overrides explicit false and evidences it", func(t *testing.T) {
		u := newUpstream(t)
		evStore, router := newResponsesConformanceGateway(t, u.server.URL, ResponsesStoreForceTrue)

		w := sendResponsesRequest(t, router, storeFalseBody, respConfAgentKeyWarn)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		forwarded, _ := u.lastBody.Load().(string)
		assert.Contains(t, forwarded, `"store":true`)

		sid := w.Header().Get("X-Talon-Session-ID")
		require.True(t, strings.HasPrefix(sid, "sess_"))
		records, err := evStore.ListByCorrelationID(context.Background(), strings.TrimPrefix(sid, "sess_"))
		require.NoError(t, err)
		require.NotEmpty(t, records)
		rec := records[len(records)-1]
		assert.Contains(t, rec.GatewayAnnotations, "responses_store_overridden",
			"reversing explicit client store:false must be visible in signed evidence")
		assert.True(t, evStore.VerifyRecord(rec))

		// No override annotation when the client sent nothing to reverse.
		w = sendResponsesRequest(t, router, storeAbsentBody, respConfAgentKeyWarn)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		sid = w.Header().Get("X-Talon-Session-ID")
		records, err = evStore.ListByCorrelationID(context.Background(), strings.TrimPrefix(sid, "sess_"))
		require.NoError(t, err)
		require.NotEmpty(t, records)
		assert.NotContains(t, records[len(records)-1].GatewayAnnotations, "responses_store_overridden")
	})
}

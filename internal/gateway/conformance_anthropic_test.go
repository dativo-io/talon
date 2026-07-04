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

// Anthropic protocol conformance suite (#193, epic #192 PR-A).
//
// Each fixture under testdata/conformance/anthropic/ replays a recorded
// Claude-Code-shaped request through the FULL gateway pipeline (extraction,
// PII scan/redaction, tool governance, forward, evidence) against a canned
// upstream, asserting the transform did not corrupt the wire format and that
// signed evidence records truthful usage and cost. Fixtures are sanitized:
// synthetic keys, example.com corpus emails only. Recapture procedure:
// scripts/record-conformance-fixtures.sh; see testdata/conformance/README.md.

const (
	confTenantKeyWarn   = "talon-gw-conf-warn-0001"
	confTenantKeyRedact = "talon-gw-conf-redact-0001"
)

type conformanceFixture struct {
	Name            string          `json:"name"`
	Path            string          `json:"path"`
	CallerPIIAction string          `json:"caller_pii_action"`
	RequestBody     json.RawMessage `json:"request_body"`
	Upstream        struct {
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
		Evidence               *struct {
			InputTokens    *int    `json:"input_tokens,omitempty"`
			OutputTokens   *int    `json:"output_tokens,omitempty"`
			CostZero       *bool   `json:"cost_zero,omitempty"`
			InvocationType *string `json:"invocation_type,omitempty"`
		} `json:"evidence,omitempty"`
	} `json:"expect"`
}

// conformanceUpstream captures the forwarded request and replays a canned
// JSON or SSE response from the active fixture.
type conformanceUpstream struct {
	server   *httptest.Server
	lastBody atomic.Value // string
	fixture  atomic.Value // *conformanceFixture
	rawSSE   atomic.Value // string: exact bytes served for SSE fixtures
}

func newConformanceUpstream(t *testing.T) *conformanceUpstream {
	t.Helper()
	u := &conformanceUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.lastBody.Store(string(raw))
		fx, _ := u.fixture.Load().(*conformanceFixture)
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

func newConformanceGateway(t *testing.T, upstreamURL string) (*Gateway, *evidence.Store, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"anthropic": {Enabled: true, BaseURL: upstreamURL, SecretName: "anthropic-key"},
		},
		Callers: []CallerConfig{
			{
				Name: "conf-warn", TenantKey: confTenantKeyWarn, TenantID: "conf-tenant",
				PolicyOverrides: &CallerPolicyOverrides{PIIAction: "warn", MaxDailyCost: 100, MaxMonthlyCost: 2000},
			},
			{
				Name: "conf-redact", TenantKey: confTenantKeyRedact, TenantID: "conf-tenant",
				PolicyOverrides: &CallerPolicyOverrides{PIIAction: "redact", MaxDailyCost: 100, MaxMonthlyCost: 2000},
			},
		},
		// Response-side scanning is out of scope for request-path conformance:
		// "allow" keeps streams passing through byte-identically.
		ServerDefaults: ServerDefaults{DefaultPIIAction: "warn", ResponsePIIAction: "allow", MaxDailyCost: 100, MaxMonthlyCost: 2000},
		// The whole corpus runs through one gateway; default per-caller RPM
		// would 429 everything after the first fixture.
		RateLimits: RateLimitsConfig{GlobalRequestsPerMin: 10000, PerCallerRequestsPerMin: 10000},
		Timeouts:   TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.Validate())
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "anthropic-key", []byte("sk-ant-test-000-conformance"),
		secrets.ACL{Tenants: []string{"conf-tenant"}, Agents: []string{"*"}}))
	gw, err := NewGateway(cfg, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	return gw, evStore, r
}

func loadConformanceFixtures(t *testing.T, dir string) []*conformanceFixture {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "fixture dir must exist")
	var out []*conformanceFixture
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- test fixtures
		require.NoError(t, err)
		var fx conformanceFixture
		require.NoError(t, json.Unmarshal(raw, &fx), "fixture %s must parse", e.Name())
		require.NotEmpty(t, fx.Name, "fixture %s needs a name", e.Name())
		out = append(out, &fx)
	}
	require.NotEmpty(t, out, "no fixtures found in %s", dir)
	return out
}

func runConformanceFixture(t *testing.T, fx *conformanceFixture, upstream *conformanceUpstream, router http.Handler, evStore *evidence.Store) {
	t.Helper()
	upstream.fixture.Store(fx)

	key := confTenantKeyWarn
	if fx.CallerPIIAction == "redact" {
		key = confTenantKeyRedact
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/anthropic"+fx.Path, bytes.NewReader(fx.RequestBody))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

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
				"fixture %s: SSE stream must reach the client byte-identical", fx.Name)
		} else {
			assert.JSONEq(t, string(fx.Upstream.JSON), w.Body.String(),
				"fixture %s: response must pass through", fx.Name)
		}
	}

	if fx.Expect.Evidence != nil {
		// The gateway does not echo the correlation id directly; the synthesized
		// session id is "sess_"+correlationID (same derivation as failover tests).
		sid := w.Header().Get("X-Talon-Session-ID")
		require.True(t, strings.HasPrefix(sid, "sess_"), "fixture %s: session header %q", fx.Name, sid)
		correlationID := strings.TrimPrefix(sid, "sess_")
		records, err := evStore.ListByCorrelationID(context.Background(), correlationID)
		require.NoError(t, err)
		require.NotEmpty(t, records, "fixture %s: evidence must be written", fx.Name)
		rec := records[len(records)-1]
		exp := fx.Expect.Evidence
		if exp.InputTokens != nil {
			assert.Equal(t, *exp.InputTokens, rec.Execution.Tokens.Input,
				"fixture %s: evidence input tokens", fx.Name)
		}
		if exp.OutputTokens != nil {
			assert.Equal(t, *exp.OutputTokens, rec.Execution.Tokens.Output,
				"fixture %s: evidence output tokens", fx.Name)
		}
		if exp.CostZero != nil {
			if *exp.CostZero {
				assert.Zero(t, rec.Execution.Cost, "fixture %s: cost must be zero", fx.Name)
				assert.Zero(t, rec.Execution.EstimatedCost, "fixture %s: estimated cost must be zero", fx.Name)
			} else {
				assert.Greater(t, rec.Execution.Cost, 0.0, "fixture %s: cost must be non-zero", fx.Name)
			}
		}
		if exp.InvocationType != nil {
			assert.Equal(t, *exp.InvocationType, rec.InvocationType,
				"fixture %s: invocation type", fx.Name)
		}
	}
}

func TestConformanceAnthropic_Fixtures(t *testing.T) {
	fixtures := loadConformanceFixtures(t, filepath.Join("testdata", "conformance", "anthropic"))
	upstream := newConformanceUpstream(t)
	_, evStore, router := newConformanceGateway(t, upstream.server.URL)
	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.Name, func(t *testing.T) {
			runConformanceFixture(t, fx, upstream, router, evStore)
		})
	}
}

// A ~50KB system prompt (Claude Code's norm) must survive the full pipeline
// under redact without corruption or failure. Generated, not stored: the
// content is deterministic (strings.Repeat), so a checked-in 50KB fixture
// would add nothing but repo weight.
func TestConformanceAnthropic_LargeSystemPrompt(t *testing.T) {
	upstream := newConformanceUpstream(t)
	_, evStore, router := newConformanceGateway(t, upstream.server.URL)

	sentence := "You are a careful coding assistant; when unsure, ask. Escalations go to jane.doe@example.com for review. "
	system := strings.Repeat(sentence, 500) // ~52KB
	require.Greater(t, len(system), 50*1024)
	body := map[string]interface{}{
		"model":      "claude-sonnet-5",
		"max_tokens": 100,
		"system":     system,
		"messages":   []map[string]interface{}{{"role": "user", "content": "hello"}},
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)

	fx := &conformanceFixture{Name: "large_system_prompt", Path: "/v1/messages", CallerPIIAction: "redact"}
	fx.RequestBody = raw
	fx.Upstream.Status = 200
	fx.Upstream.JSON = json.RawMessage(`{"id":"msg_conf_large","type":"message","role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":13000,"output_tokens":2}}`)
	fx.Expect.Status = 200
	fx.Expect.ForwardedNotContains = []string{"jane.doe@example.com"}
	fx.Expect.ForwardedJSONValid = true
	runConformanceFixture(t, fx, upstream, router, evStore)
}

// Identical PII-bearing input must produce byte-identical transformed output
// across repeated requests: non-deterministic rewrites silently break
// provider-side prompt caching for clients — a 10x+ cost regression Talon
// must never cause.
func TestConformanceAnthropic_TransformDeterminism(t *testing.T) {
	upstream := newConformanceUpstream(t)
	_, _, router := newConformanceGateway(t, upstream.server.URL)

	raw, err := os.ReadFile(filepath.Join("testdata", "conformance", "anthropic", "system_block_array_cache_control.json"))
	require.NoError(t, err)
	var fx conformanceFixture
	require.NoError(t, json.Unmarshal(raw, &fx))
	upstream.fixture.Store(&fx)

	send := func() string {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://test/v1/proxy/anthropic"+fx.Path, bytes.NewReader(fx.RequestBody))
		req.Header.Set("Authorization", "Bearer "+confTenantKeyRedact)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		body, _ := upstream.lastBody.Load().(string)
		return body
	}
	first := send()
	second := send()
	assert.Equal(t, first, second, "transformed bodies must be byte-identical across repeats")
}

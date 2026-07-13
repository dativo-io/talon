package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/pricing"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// Provider-aware cache-token usage extraction + pricing (#196, epic #192 PR-E).

func TestApplyAnthropicUsage_CacheTokensDirect(t *testing.T) {
	// Anthropic input_tokens EXCLUDES cache tokens; all counts map directly.
	u := map[string]interface{}{
		"input_tokens":                float64(25),
		"output_tokens":               float64(8),
		"cache_creation_input_tokens": float64(100),
		"cache_read_input_tokens":     float64(2000),
	}
	var got TokenUsage
	applyAnthropicUsage(u, &got)
	assert.Equal(t, TokenUsage{Input: 25, Output: 8, CacheWrite: 100, CacheRead: 2000}, got)
}

func TestApplyOpenAIUsage_CachedIsSubset(t *testing.T) {
	t.Run("chat completions: cached_tokens subtracted from prompt", func(t *testing.T) {
		u := map[string]interface{}{
			"prompt_tokens":         float64(50),
			"completion_tokens":     float64(9),
			"prompt_tokens_details": map[string]interface{}{"cached_tokens": float64(40)},
		}
		var got TokenUsage
		applyOpenAIUsage(u, &got)
		assert.Equal(t, TokenUsage{Input: 10, Output: 9, CacheRead: 40}, got, "input = prompt - cached")
	})

	t.Run("responses api: input_tokens_details.cached_tokens", func(t *testing.T) {
		u := map[string]interface{}{
			"input_tokens":         float64(42),
			"output_tokens":        float64(11),
			"input_tokens_details": map[string]interface{}{"cached_tokens": float64(16)},
		}
		var got TokenUsage
		applyOpenAIUsage(u, &got)
		assert.Equal(t, TokenUsage{Input: 26, Output: 11, CacheRead: 16}, got)
	})

	t.Run("no cache details", func(t *testing.T) {
		u := map[string]interface{}{"prompt_tokens": float64(7), "completion_tokens": float64(3)}
		var got TokenUsage
		applyOpenAIUsage(u, &got)
		assert.Equal(t, TokenUsage{Input: 7, Output: 3}, got)
	})
}

func TestExtractUsage_ResponsesCompleted(t *testing.T) {
	// OpenAI Responses API streaming: usage rides response.completed nested
	// under "response" — Codex always streams, so without this its cost is
	// estimate-only.
	payload := []byte(`{"type":"response.completed","response":{"id":"r","status":"completed","usage":{"input_tokens":100,"input_tokens_details":{"cached_tokens":80},"output_tokens":4}}}`)
	var got TokenUsage
	extractUsageFromJSONPayload(payload, &got)
	assert.Equal(t, TokenUsage{Input: 20, Output: 4, CacheRead: 80}, got)
}

func TestExtractUsage_AnthropicStreamCacheTokens(t *testing.T) {
	// message_start carries input + cache tokens; message_delta carries output.
	var got TokenUsage
	extractUsageFromJSONPayload([]byte(`{"type":"message_start","message":{"usage":{"input_tokens":25,"cache_creation_input_tokens":100,"cache_read_input_tokens":2000}}}`), &got)
	extractUsageFromJSONPayload([]byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":23}}`), &got)
	assert.Equal(t, TokenUsage{Input: 25, Output: 23, CacheWrite: 100, CacheRead: 2000}, got)
}

func TestParseUsageFromJSON_RoutingByCacheKeys(t *testing.T) {
	t.Run("anthropic non-streaming with cache tokens", func(t *testing.T) {
		var got TokenUsage
		parseUsageFromJSON([]byte(`{"usage":{"input_tokens":10,"output_tokens":4,"cache_read_input_tokens":500}}`), "", &got)
		assert.Equal(t, TokenUsage{Input: 10, Output: 4, CacheRead: 500}, got)
	})
	t.Run("openai non-streaming with cached subset", func(t *testing.T) {
		var got TokenUsage
		parseUsageFromJSON([]byte(`{"usage":{"prompt_tokens":30,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":20}}}`), "", &got)
		assert.Equal(t, TokenUsage{Input: 10, Output: 5, CacheRead: 20}, got)
	})
}

func TestEnsureStreamUsage(t *testing.T) {
	parse := func(t *testing.T, b []byte) map[string]interface{} {
		t.Helper()
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(b, &m))
		return m
	}
	t.Run("adds include_usage on streaming request", func(t *testing.T) {
		out := ensureStreamUsage([]byte(`{"model":"gpt-4o-mini","stream":true,"messages":[]}`))
		m := parse(t, out)
		opts, ok := m["stream_options"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, true, opts["include_usage"])
	})
	t.Run("preserves existing stream_options", func(t *testing.T) {
		out := ensureStreamUsage([]byte(`{"stream":true,"stream_options":{"foo":"bar"}}`))
		m := parse(t, out)
		opts := m["stream_options"].(map[string]interface{})
		assert.Equal(t, true, opts["include_usage"])
		assert.Equal(t, "bar", opts["foo"])
	})
	t.Run("leaves non-streaming request untouched", func(t *testing.T) {
		in := `{"model":"gpt-4o-mini","messages":[]}`
		assert.Equal(t, in, string(ensureStreamUsage([]byte(in))))
	})
	t.Run("invalid json passes through", func(t *testing.T) {
		assert.Equal(t, "nope", string(ensureStreamUsage([]byte("nope"))))
	})
}

func TestDefaultCostEstimator_CacheAware(t *testing.T) {
	r := defaultCostEstimator("openai", "x", Usage{Input: 500, CacheRead: 500, Output: 0})
	assert.False(t, r.PricingKnown)
	assert.Equal(t, PricingBasisDefault, r.PricingBasis)
	assert.Greater(t, r.Amount, 0.0)
}

// End-to-end: an Anthropic response with cache tokens yields evidence whose
// cost matches the hand-computed cache-aware figure and whose token breakdown
// carries the cache counts.
func TestGatewayCacheCost_EndToEnd(t *testing.T) {
	// claude-sonnet-5 rates (per 1M): input 3.00, output 15.00, cache_read 0.3,
	// cache_write 3.75. Upstream reports input 1000, output 100, cache_read
	// 4000, cache_write 200.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg","type":"message","role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1000,"output_tokens":100,"cache_creation_input_tokens":200,"cache_read_input_tokens":4000}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled: true, ListenPrefix: "/v1/proxy", Mode: ModeEnforce,
		Providers:          map[string]ProviderConfig{"anthropic": {Enabled: true, BaseURL: upstream.URL, SecretName: "anthropic-key"}},
		OrganizationPolicy: OrganizationPolicy{Defaults: OrgDefaults{PIIAction: "warn", ResponsePIIAction: "allow", DailyCost: 100, MonthlyCost: 2000}},
		RateLimits:         RateLimitsConfig{GlobalRequestsPerMin: 10000, PerAgentRequestsPerMin: 10000},
		Timeouts:           TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.Validate())
	registry := testRegistry(testIdentity("cc", "t", "talon-gw-cache-0001",
		&PolicyOverride{PIIAction: "warn", MaxDailyCost: 100, MaxMonthlyCost: 2000}))
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "anthropic-key", []byte("sk-ant-test-000-cache"),
		secrets.ACL{Tenants: []string{"t"}, Agents: []string{"*"}}))

	// Real cache-aware estimator over the current pricing table.
	table, err := pricing.Load("../../pricing/models.yaml")
	require.NoError(t, err)
	estimator := func(provider, model string, u Usage) CostResult {
		cost, known, fb := table.EstimateCached(provider, model, u.Input, u.CacheRead, u.CacheWrite, u.Output)
		basis := PricingBasisTable
		if fb {
			basis = PricingBasisCacheFalling
		}
		return CostResult{Amount: cost, PricingKnown: known, PricingBasis: basis}
	}
	gw, err := NewGateway(cfg, NewRegistryHolder(registry), classifier.MustNewScanner(), evStore, secStore, nil, estimator)
	require.NoError(t, err)
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/anthropic/v1/messages", bytes.NewReader([]byte(`{"model":"claude-sonnet-5","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}`)))
	req.Header.Set("Authorization", "Bearer talon-gw-cache-0001")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	sid := w.Header().Get("X-Talon-Session-ID")
	recs, err := evStore.ListBySessionID(context.Background(), sid)
	require.NoError(t, err)
	require.NotEmpty(t, recs)
	rec := recs[len(recs)-1]

	assert.Equal(t, 1000, rec.Execution.Tokens.Input)
	assert.Equal(t, 100, rec.Execution.Tokens.Output)
	assert.Equal(t, 4000, rec.Execution.Tokens.CacheRead)
	assert.Equal(t, 200, rec.Execution.Tokens.CacheWrite)
	assert.Equal(t, "table", rec.Execution.PricingBasis)
	assert.True(t, rec.Execution.PricingKnown)
	// Hand-computed: 1000*3.00 + 4000*0.3 + 200*3.75 + 100*15.00, all /1e6.
	want := (1000*3.00 + 4000*0.3 + 200*3.75 + 100*15.00) / 1e6
	assert.InDelta(t, want, rec.Execution.Cost, 1e-9)
	assert.True(t, evStore.VerifyRecord(rec))
}

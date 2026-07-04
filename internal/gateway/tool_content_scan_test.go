package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// Observation-only tool-content scan (#212, epic #192 PR-B): tool_use inputs,
// tool_result outputs, and function-call arguments are scanned for evidence
// but NEVER influence enforcement — tool blocks cannot be redacted yet, so
// acting on the signal would fail-close every redact-mode deployment on
// agentic traffic.

func TestExtractToolText_Anthropic(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-5",
		"messages": [
			{"role": "user", "content": "read the customer file"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"path": "/data/customers.csv", "note": "contact bob@example.com"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_1", "content": "name,email\nJane,jane.doe@example.com"}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "nested block test@example.com"}]}
			]}
		]
	}`)
	ex, err := ExtractAnthropic(body)
	require.NoError(t, err)
	// Tool content collected for the observation scan…
	assert.Contains(t, ex.ToolText, "bob@example.com", "tool_use input values")
	assert.Contains(t, ex.ToolText, "jane.doe@example.com", "tool_result string content")
	assert.Contains(t, ex.ToolText, "test@example.com", "tool_result nested block content")
	// …and kept OUT of the enforcement text.
	assert.NotContains(t, ex.Text, "jane.doe@example.com")
	assert.NotContains(t, ex.Text, "bob@example.com")
	assert.Contains(t, ex.Text, "read the customer file")
}

func TestExtractToolText_OpenAI(t *testing.T) {
	t.Run("chat_completions_tool_calls", func(t *testing.T) {
		body := []byte(`{
			"model": "gpt-5.5",
			"messages": [
				{"role": "user", "content": "look up the account"},
				{"role": "assistant", "content": null, "tool_calls": [
					{"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": "{\"email\":\"jane.doe@example.com\"}"}}
				]},
				{"role": "tool", "tool_call_id": "call_1", "content": "account 42"}
			]
		}`)
		ex, err := ExtractOpenAI(body)
		require.NoError(t, err)
		assert.Contains(t, ex.ToolText, "jane.doe@example.com", "tool_calls arguments")
		assert.NotContains(t, ex.Text, "jane.doe@example.com")
		// role:"tool" string content is ordinary message content (already covered
		// by the main extractor) — not duplicated into ToolText.
		assert.Contains(t, ex.Text, "account 42")
	})

	t.Run("responses_function_call_output", func(t *testing.T) {
		body := []byte(`{
			"model": "gpt-5.5",
			"input": [
				{"role": "user", "content": "run the query"},
				{"type": "function_call", "call_id": "call_2", "name": "sql", "arguments": "{\"q\":\"select email from users\"}"},
				{"type": "function_call_output", "call_id": "call_2", "output": "email: jane.doe@example.com"}
			]
		}`)
		ex, err := ExtractOpenAI(body)
		require.NoError(t, err)
		assert.Contains(t, ex.ToolText, "jane.doe@example.com", "function_call_output output")
		assert.Contains(t, ex.ToolText, "select email from users", "function_call arguments")
		assert.NotContains(t, ex.Text, "jane.doe@example.com")
	})

	t.Run("responses_instructions_is_main_text", func(t *testing.T) {
		// instructions is the Responses system-prompt equivalent: ordinary
		// prompt text, scanned and redactable like any other — NOT tool content.
		body := []byte(`{"model":"gpt-5.5","instructions":"escalate to jane.doe@example.com","input":"hello"}`)
		ex, err := ExtractOpenAI(body)
		require.NoError(t, err)
		assert.Contains(t, ex.Text, "jane.doe@example.com")
		assert.Empty(t, ex.ToolText)
	})
}

func TestRedactOpenAIBody_Instructions(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","instructions":"escalate to jane.doe@example.com","input":"hello"}`)
	out, err := RedactRequestBody(context.Background(), "openai", body, classifier.MustNewScanner())
	require.NoError(t, err)
	assert.NotContains(t, string(out), "jane.doe@example.com", "instructions must be redacted")
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &m))
	assert.Equal(t, "hello", m["input"], "input untouched")
}

const toolScanTenantKey = "talon-gw-toolscan-0001"

func newToolScanGateway(t *testing.T, upstreamURL, scanToolContent string) (*evidence.Store, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"anthropic": {Enabled: true, BaseURL: upstreamURL, SecretName: "anthropic-key"},
		},
		Callers: []CallerConfig{{
			Name: "toolscan-bot", TenantKey: toolScanTenantKey, TenantID: "toolscan-tenant",
			PolicyOverrides: &CallerPolicyOverrides{PIIAction: "redact", MaxDailyCost: 100, MaxMonthlyCost: 2000},
		}},
		ServerDefaults: ServerDefaults{DefaultPIIAction: "redact", ResponsePIIAction: "allow", ScanToolContent: scanToolContent, MaxDailyCost: 100, MaxMonthlyCost: 2000},
		RateLimits:     RateLimitsConfig{GlobalRequestsPerMin: 10000, PerCallerRequestsPerMin: 10000},
		Timeouts:       TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.Validate())
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "anthropic-key", []byte("sk-ant-test-000-toolscan"),
		secrets.ACL{Tenants: []string{"toolscan-tenant"}, Agents: []string{"*"}}))
	gw, err := NewGateway(cfg, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	return evStore, r
}

// PII that exists ONLY in tool_result content must (a) forward unchanged —
// enforcement does not act on tool content in v1 — and (b) appear in the
// evidence-only tool_content observation.
func TestGatewayToolContentScan_EvidenceOnly(t *testing.T) {
	var forwarded string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		forwarded = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_ts","type":"message","role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":30,"output_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)
	evStore, router := newToolScanGateway(t, upstream.URL, ScanToolContentEvidenceOnly)

	body := `{
		"model": "claude-sonnet-5",
		"max_tokens": 100,
		"messages": [
			{"role": "user", "content": "summarize the tool output"},
			{"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_ts", "name": "read_file", "input": {"path": "/data/users.csv"}}]},
			{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_ts", "content": "row: jane.doe@example.com"}]}
		]
	}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/anthropic/v1/messages", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+toolScanTenantKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	// (a) tool content forwarded unchanged, no fail-closed 400, no rewrite.
	assert.Contains(t, forwarded, "jane.doe@example.com",
		"tool_result content is observation-only in v1: it must forward unchanged")

	// (b) evidence carries the observation.
	sid := w.Header().Get("X-Talon-Session-ID")
	require.True(t, strings.HasPrefix(sid, "sess_"))
	records, err := evStore.ListByCorrelationID(context.Background(), strings.TrimPrefix(sid, "sess_"))
	require.NoError(t, err)
	require.NotEmpty(t, records)
	rec := records[len(records)-1]
	require.NotNil(t, rec.Classification.ToolContent, "tool_content observation must be recorded")
	assert.True(t, rec.Classification.ToolContent.Scanned)
	assert.True(t, rec.Classification.ToolContent.HasPII)
	assert.Contains(t, rec.Classification.ToolContent.EntityTypes, "email")
	assert.Greater(t, rec.Classification.ToolContent.EntityCount, 0)
	// The enforcement classification saw only clean main text.
	assert.Empty(t, rec.Classification.PIIDetected, "main-text classification must not include tool content")
	// Signature still verifies with the new omitempty block present.
	assert.True(t, evStore.VerifyRecord(rec), "signature must verify with tool_content present")
	// Flat export carries the observation (talon audit export --format json).
	exp := evidence.ToExportRecord(rec)
	require.NotNil(t, exp.ToolContentScanned)
	assert.True(t, *exp.ToolContentScanned)
	assert.True(t, exp.ToolContentHasPII)
	assert.Contains(t, exp.ToolContentEntityTypes, "email")
}

func TestGatewayToolContentScan_Off(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_ts2","type":"message","role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":10,"output_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)
	evStore, router := newToolScanGateway(t, upstream.URL, ScanToolContentOff)

	body := `{"model":"claude-sonnet-5","max_tokens":100,"messages":[
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_x","content":"row: jane.doe@example.com"}]}]}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/anthropic/v1/messages", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+toolScanTenantKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	sid := w.Header().Get("X-Talon-Session-ID")
	records, err := evStore.ListByCorrelationID(context.Background(), strings.TrimPrefix(sid, "sess_"))
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.Nil(t, records[len(records)-1].Classification.ToolContent,
		"scan_tool_content: off must record nothing")
}

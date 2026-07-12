package gateway

import (
	"bytes"
	"context"
	"encoding/json"
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

// Provider-neutral orchestration metadata contract (#194, epic #192 PR-D).

func newRequestWithHeaders(h map[string]string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/proxy/openai/v1/chat/completions", nil)
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

func TestResolveOrchestration_Precedence(t *testing.T) {
	t.Run("generic headers win over vendor", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{
			"X-Talon-Session-ID":            "gen-sess",
			"X-Talon-Agent-ID":              "gen-agent",
			"X-Claude-Code-Session-Id":      "cc-sess",
			"X-Claude-Code-Agent-Id":        "cc-agent",
			"X-Claude-Code-Parent-Agent-Id": "cc-parent",
		})
		o, sid, src, err := resolveOrchestration(r, true, "synthetic")
		require.NoError(t, err)
		require.NotNil(t, o)
		assert.Equal(t, "gen-sess", o.SessionID)
		assert.Equal(t, "gen-sess", sid)
		assert.Equal(t, orchSourceClientAsserted, src)
		assert.Equal(t, "gen-agent", o.AgentID)
		assert.Equal(t, "cc-parent", o.ParentAgentID, "unset generic field falls back to vendor")
		assert.Equal(t, orchProvenanceClientAsserted, o.Provenance)
	})

	t.Run("claude code vendor adapter", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{
			"X-Claude-Code-Session-Id":      "cc-sess",
			"X-Claude-Code-Agent-Id":        "cc-agent",
			"X-Claude-Code-Parent-Agent-Id": "cc-parent",
		})
		o, sid, src, err := resolveOrchestration(r, true, "synthetic")
		require.NoError(t, err)
		require.NotNil(t, o)
		assert.Equal(t, "cc-sess", o.SessionID)
		assert.Equal(t, "cc-sess", sid)
		assert.Equal(t, orchSourceVendorAsserted, src)
		assert.Equal(t, "cc-agent", o.AgentID)
		assert.Equal(t, "cc-parent", o.ParentAgentID)
		assert.Equal(t, "claude-code", o.Client)
	})

	t.Run("codex vendor adapter", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{
			"Session-Id":        "cx-sess",
			"X-Openai-Subagent": "cx-sub",
		})
		o, _, src, err := resolveOrchestration(r, true, "synthetic")
		require.NoError(t, err)
		require.NotNil(t, o)
		assert.Equal(t, "cx-sess", o.SessionID)
		assert.Equal(t, orchSourceVendorAsserted, src)
		assert.Equal(t, "cx-sub", o.AgentID)
		assert.Equal(t, "codex", o.Client)
	})

	t.Run("generic headers with explicit client", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{
			"X-Talon-Session-ID": "gen-sess",
			"X-Talon-Agent-ID":   "gen-agent",
			"X-Talon-Client":     "aider",
		})
		o, _, _, err := resolveOrchestration(r, true, "synthetic")
		require.NoError(t, err)
		require.NotNil(t, o)
		assert.Equal(t, "aider", o.Client, "explicit X-Talon-Client wins")
	})

	t.Run("generic session only defaults client to generic", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{"X-Talon-Session-ID": "gen-sess"})
		o, _, src, err := resolveOrchestration(r, true, "synthetic")
		require.NoError(t, err)
		require.NotNil(t, o)
		assert.Equal(t, orchSourceClientAsserted, src)
		assert.Equal(t, "generic", o.Client)
	})
}

func TestResolveOrchestration_AbsentAndFlag(t *testing.T) {
	t.Run("no headers → no block, synthetic session", func(t *testing.T) {
		r := newRequestWithHeaders(nil)
		o, sid, src, err := resolveOrchestration(r, true, "sess_synth")
		require.NoError(t, err)
		assert.Nil(t, o)
		assert.Equal(t, "sess_synth", sid)
		assert.Equal(t, orchSourceSynthetic, src)
	})

	t.Run("flag off ignores agent/vendor identity", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{
			"X-Claude-Code-Session-Id": "cc-sess",
			"X-Claude-Code-Agent-Id":   "cc-agent",
		})
		o, sid, src, err := resolveOrchestration(r, false, "sess_synth")
		require.NoError(t, err)
		assert.Nil(t, o, "flag off → vendor identity not recorded")
		assert.Equal(t, "sess_synth", sid, "vendor session not adopted when flag off")
		assert.Equal(t, orchSourceSynthetic, src)
	})

	t.Run("flag off still honors the generic session header (pre-epic behavior)", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{"X-Talon-Session-ID": "gen-sess"})
		o, sid, src, err := resolveOrchestration(r, false, "sess_synth")
		require.NoError(t, err)
		assert.Equal(t, "gen-sess", sid)
		assert.Equal(t, orchSourceClientAsserted, src)
		assert.Nil(t, o, "no agent identity recorded, but session spine preserved")
	})
}

func TestResolveOrchestration_Hygiene(t *testing.T) {
	t.Run("oversized value rejected", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{"X-Talon-Agent-ID": strings.Repeat("a", orchHeaderMaxLen+1)})
		_, _, _, err := resolveOrchestration(r, true, "s")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds")
	})

	t.Run("HTML-injection value rejected, never reaches evidence", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{"X-Talon-Agent-ID": `<img src=x onerror=alert(1)>`})
		o, _, _, err := resolveOrchestration(r, true, "s")
		require.Error(t, err, "disallowed characters must be rejected")
		assert.Nil(t, o)
	})

	t.Run("vendor header hygiene enforced too", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{"X-Claude-Code-Agent-Id": "bad value with space"})
		_, _, _, err := resolveOrchestration(r, true, "s")
		require.Error(t, err)
	})

	t.Run("uuid-shaped values accepted", func(t *testing.T) {
		r := newRequestWithHeaders(map[string]string{
			"X-Talon-Session-ID": "b7c1e0d2-9a4f-4c3e-8b1a-000000000001",
			"X-Talon-Agent-ID":   "agent_01ABCdef",
		})
		o, _, _, err := resolveOrchestration(r, true, "s")
		require.NoError(t, err)
		require.NotNil(t, o)
	})
}

func TestNormalizeStage(t *testing.T) {
	assert.Equal(t, "generation", normalizeStage("generation"))
	assert.Equal(t, "judge", normalizeStage("judge"))
	assert.Equal(t, "commit", normalizeStage("commit"))
	assert.Equal(t, "", normalizeStage("garbage"))
	assert.Equal(t, "", normalizeStage(""))
}

// End-to-end: orchestration identity is recorded in signed evidence, groups by
// session across provider routes, is agent-isolated, and rejected on hygiene
// violation before reaching evidence.
const (
	orchAgentKeyA = "talon-gw-orch-a-0001"
	orchAgentKeyB = "talon-gw-orch-b-0001"
)

func newOrchGateway(t *testing.T, anthropicURL, openaiURL string, acceptA *bool) (*evidence.Store, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeEnforce,
		Providers: map[string]ProviderConfig{
			"anthropic": {Enabled: true, BaseURL: anthropicURL, SecretName: "anthropic-key"},
			"openai":    {Enabled: true, BaseURL: openaiURL, SecretName: "openai-key"},
		},
		OrganizationPolicy: OrganizationPolicy{DefaultPIIAction: "warn", ResponsePIIAction: "allow", MaxDailyCost: 100, MaxMonthlyCost: 2000},
		RateLimits:         RateLimitsConfig{GlobalRequestsPerMin: 10000, PerAgentRequestsPerMin: 10000},
		Timeouts:           TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.Validate())
	idA := testIdentity("orch-a", "tenant-a", orchAgentKeyA,
		&PolicyOverride{PIIAction: "warn", MaxDailyCost: 100, MaxMonthlyCost: 2000})
	idA.AcceptClientMetadata = acceptA
	idB := testIdentity("orch-b", "tenant-b", orchAgentKeyB,
		&PolicyOverride{PIIAction: "warn", MaxDailyCost: 100, MaxMonthlyCost: 2000})
	registry := testRegistry(idA, idB)
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	acl := secrets.ACL{Tenants: []string{"tenant-a", "tenant-b"}, Agents: []string{"*"}}
	require.NoError(t, secStore.Set(context.Background(), "anthropic-key", []byte("sk-ant-test-000-orch"), acl))
	require.NoError(t, secStore.Set(context.Background(), "openai-key", []byte("sk-test-000-orch"), acl))
	gw, err := NewGateway(cfg, registry, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	return evStore, r
}

func orchUpstream(t *testing.T, family string) *httptest.Server {
	t.Helper()
	body := `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`
	if family == "anthropic" {
		body = `{"id":"msg_x","type":"message","role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":5,"output_tokens":1}}`
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func lastEvidence(t *testing.T, evStore *evidence.Store, w *httptest.ResponseRecorder) *evidence.Evidence {
	t.Helper()
	sid := w.Header().Get("X-Talon-Session-ID")
	require.NotEmpty(t, sid, "session header")
	// The evidence session_id column is the resolved session id (client-asserted
	// or synthetic), so look up by session — not by a correlation id.
	records, err := evStore.ListBySessionID(context.Background(), sid)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	return records[len(records)-1]
}

func postOrch(t *testing.T, router http.Handler, path, agentKey string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	if strings.Contains(path, "anthropic") {
		body = `{"model":"claude-sonnet-5","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}`
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://test"+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+agentKey)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestGatewayOrchestration_RecordedInEvidence(t *testing.T) {
	up := orchUpstream(t, "openai")
	evStore, router := newOrchGateway(t, up.URL, up.URL, nil)

	w := postOrch(t, router, "/v1/proxy/openai/v1/chat/completions", orchAgentKeyA, map[string]string{
		"X-Claude-Code-Session-Id":      "session-xyz",
		"X-Claude-Code-Agent-Id":        "opus-reviewer",
		"X-Claude-Code-Parent-Agent-Id": "fable-main",
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "session-xyz", w.Header().Get("X-Talon-Session-ID"), "vendor session id echoed back")

	rec := lastEvidence(t, evStore, w)
	require.NotNil(t, rec.Orchestration)
	assert.Equal(t, "opus-reviewer", rec.Orchestration.AgentID)
	assert.Equal(t, "fable-main", rec.Orchestration.ParentAgentID)
	assert.Equal(t, "claude-code", rec.Orchestration.Client)
	assert.Equal(t, orchSourceVendorAsserted, rec.Orchestration.SessionSource)
	assert.Equal(t, orchProvenanceClientAsserted, rec.Orchestration.Provenance)
	assert.Equal(t, "session-xyz", rec.SessionID, "orchestration session mirrors the session_id column")
	// agent_id column stays the agent identity name (budgets depend on it).
	assert.Equal(t, "orch-a", rec.AgentID)
	assert.True(t, evStore.VerifyRecord(rec), "signature must verify with orchestration block")

	// Export carries the flattened orchestration fields.
	exp := evidence.ToExportRecord(rec)
	assert.Equal(t, "opus-reviewer", exp.OrchAgentID)
	assert.Equal(t, "claude-code", exp.OrchClient)
	assert.Equal(t, "vendor_asserted", exp.OrchSessionSource)
}

func TestGatewayOrchestration_CrossProviderAndIsolation(t *testing.T) {
	anthropicUp := orchUpstream(t, "anthropic")
	openaiUp := orchUpstream(t, "openai")
	evStore, router := newOrchGateway(t, anthropicUp.URL, openaiUp.URL, nil)

	// Same generic session id across two provider routes, same agent → group.
	sess := "shared-coding-session"
	wA := postOrch(t, router, "/v1/proxy/anthropic/v1/messages", orchAgentKeyA, map[string]string{"X-Talon-Session-ID": sess, "X-Talon-Agent-ID": "sub1"})
	require.Equal(t, http.StatusOK, wA.Code, wA.Body.String())
	wO := postOrch(t, router, "/v1/proxy/openai/v1/chat/completions", orchAgentKeyA, map[string]string{"X-Talon-Session-ID": sess, "X-Talon-Agent-ID": "sub2"})
	require.Equal(t, http.StatusOK, wO.Code, wO.Body.String())

	grouped, err := evStore.ListBySessionID(context.Background(), sess)
	require.NoError(t, err)
	assert.Len(t, grouped, 2, "both provider routes group under one agent-asserted session")

	// A DIFFERENT agent asserting the SAME session id is attributed to itself,
	// not folded into agent A's session. Grouping stays agent-scoped: the raw
	// session string is never a global key that one agent can join another's
	// session with. (#194 agent-scoping.)
	wB := postOrch(t, router, "/v1/proxy/openai/v1/chat/completions", orchAgentKeyB, map[string]string{"X-Talon-Session-ID": sess, "X-Talon-Agent-ID": "sub3"})
	require.Equal(t, http.StatusOK, wB.Code, wB.Body.String())

	all, err := evStore.ListBySessionID(context.Background(), sess)
	require.NoError(t, err)
	aRecords, bRecords := 0, 0
	for _, r := range all {
		switch r.AgentID {
		case "orch-a":
			aRecords++
		case "orch-b":
			bRecords++
		}
	}
	assert.Equal(t, 2, aRecords, "both of agent A's provider routes")
	assert.Equal(t, 1, bRecords, "agent B's record is attributed to agent B, not A")
}

func TestGatewayOrchestration_HygieneRejectedAtGateway(t *testing.T) {
	up := orchUpstream(t, "openai")
	_, router := newOrchGateway(t, up.URL, up.URL, nil)

	w := postOrch(t, router, "/v1/proxy/openai/v1/chat/completions", orchAgentKeyA, map[string]string{
		"X-Talon-Agent-ID": `<script>alert(1)</script>`,
	})
	require.Equal(t, http.StatusBadRequest, w.Code)
	// OpenAI-family error envelope, no orchestration value leaked.
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotContains(t, w.Body.String(), "script")
}

func TestGatewayOrchestration_FlagOff(t *testing.T) {
	up := orchUpstream(t, "openai")
	off := false
	// agent orch-a with AcceptClientMetadata=false
	evStore, router := newOrchGateway(t, up.URL, up.URL, &off)

	w := postOrch(t, router, "/v1/proxy/openai/v1/chat/completions", orchAgentKeyA, map[string]string{
		"X-Claude-Code-Session-Id": "cc-sess",
		"X-Claude-Code-Agent-Id":   "cc-agent",
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	rec := lastEvidence(t, evStore, w)
	assert.Nil(t, rec.Orchestration, "flag off → no orchestration block recorded")
}

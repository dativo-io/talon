//go:build integration

package integration

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/session"
	"github.com/dativo-io/talon/internal/testutil"
)

// CI smoke of the coding-agents demo (#203, epic #192 PR-I): the REAL
// dual-wire mock provider binary (examples/docker-compose/mock-provider) is
// compiled and started, a gateway is pointed at it, and the demo sequence
// runs deterministically offline: a cross-provider session with subagent
// attribution, cache-aware usage from both wire families' SSE, a
// session_budget_exceeded denial, a PII event, and a signed export that
// verifies. examples/coding-agents-demo/demo.sh walks the same sequence
// against the docker-compose stack for humans.

const demoAgentKey = "talon-gw-demo-coding-0001"

func startMockProvider(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "mock-provider")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = "../../examples/docker-compose/mock-provider" // own module, not in the main go.mod
	out, err := build.CombinedOutput()
	require.NoError(t, err, "building mock provider: %s", out)

	// Fixed port would race parallel CI; ask the kernel via a throwaway listener.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	cmd := exec.Command(bin, "-port", strconv.Itoa(port))
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + "/health") //nolint:noctx // health poll in test setup
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "mock provider must become healthy")
	return base
}

func newDemoGateway(t *testing.T, mockURL string) (*evidence.Store, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := &gateway.GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         gateway.ModeEnforce,
		Providers: map[string]gateway.ProviderConfig{
			"anthropic": {Enabled: true, BaseURL: mockURL, SecretName: "anthropic-api-key", APIFamily: "anthropic"},
			"openai":    {Enabled: true, BaseURL: mockURL, SecretName: "openai-api-key"},
		},
		OrganizationPolicy: gateway.OrganizationPolicy{Defaults: gateway.OrgDefaults{PIIAction: "warn", ResponsePIIAction: "allow"}},
		RateLimits:         gateway.RateLimitsConfig{GlobalRequestsPerMin: 100000, PerAgentRequestsPerMin: 100000},
		Timeouts:           gateway.TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.Validate())

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	acl := secrets.ACL{Tenants: []string{"demo"}, Agents: []string{"*"}}
	require.NoError(t, secStore.Set(context.Background(), "anthropic-api-key", []byte("sk-ant-mock-demo-000"), acl))
	require.NoError(t, secStore.Set(context.Background(), "openai-api-key", []byte("sk-mock-demo-000"), acl))

	// Agent identity (#266): vault-bound traffic key resolved via the registry.
	require.NoError(t, secStore.Set(context.Background(), "claude-code-talon-key", []byte(demoAgentKey), secrets.ACL{}))
	registry, err := gateway.BuildIdentityRegistry(context.Background(), []gateway.LoadedAgent{
		{
			Path: "agent.talon.yaml", Name: "claude-code", TenantID: "demo", KeySecretName: "claude-code-talon-key",
			Override: &gateway.PolicyOverride{
				PIIAction:         "warn",
				ResponsePIIAction: "allow",
				MaxSessionCost:    0.02, // trips after a few mock-priced requests
			},
		},
	}, secStore, "")
	require.NoError(t, err)

	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)
	sessStore, err := session.NewStore(filepath.Join(dir, "sessions.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessStore.Close() })

	// Deterministic estimator: pre-request estimate (the fixed 500/500 token
	// guess) costs 0.004, every real request 0.005 — the 0.02 session cap
	// trips on exactly the fifth session request.
	estimator := func(_, _ string, u gateway.Usage) gateway.CostResult {
		if u.Input == 500 && u.Output == 500 {
			return gateway.CostResult{Amount: 0.004, PricingKnown: true, PricingBasis: gateway.PricingBasisTable}
		}
		return gateway.CostResult{Amount: 0.005, PricingKnown: true, PricingBasis: gateway.PricingBasisTable}
	}
	gw, err := gateway.NewGateway(cfg, gateway.NewRegistryHolder(registry), classifier.MustNewScanner(), evStore, secStore, policyEngine, estimator)
	require.NoError(t, err)
	gw.SetSessionStore(sessStore)
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	return evStore, r
}

func demoRequest(t *testing.T, h http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+demoAgentKey)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCodingAgentsDemo_EndToEnd(t *testing.T) {
	mockURL := startMockProvider(t)
	evStore, h := newDemoGateway(t, mockURL)
	ctx := context.Background()
	const sessID = "sess-demo-e2e"

	// 1. Anthropic route, streaming SSE, subagent "generator".
	rec := demoRequest(t, h, "/v1/proxy/anthropic/v1/messages",
		`{"model":"claude-sonnet-5","max_tokens":128,"stream":true,"messages":[{"role":"user","content":"write a summary"}]}`,
		map[string]string{"X-Talon-Session-ID": sessID, "X-Talon-Agent-ID": "generator", "X-Talon-Client": "claude-code"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "message_stop", "SSE passthrough intact")

	// 2. OpenAI Responses route, streaming, subagent "executor" — SAME session.
	rec = demoRequest(t, h, "/v1/proxy/openai/v1/responses",
		`{"model":"gpt-5.3-codex","input":"execute the plan","stream":true,"store":false}`,
		map[string]string{"X-Talon-Session-ID": sessID, "X-Talon-Agent-ID": "executor", "X-Talon-Parent-Agent-ID": "generator", "X-Talon-Client": "codex"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "response.completed")

	// 3. PII event: input scan warns, request still flows (pii_action warn).
	rec = demoRequest(t, h, "/v1/proxy/anthropic/v1/messages",
		`{"model":"claude-sonnet-5","max_tokens":64,"messages":[{"role":"user","content":"email jane.doe@example.com the summary"}]}`,
		map[string]string{"X-Talon-Session-ID": sessID, "X-Talon-Agent-ID": "generator"})
	require.Equal(t, http.StatusOK, rec.Code)

	// 4. Loop until the session budget trips (soft cap 0.02).
	denied := false
	var denyBody string
	for i := 0; i < 30 && !denied; i++ {
		rec = demoRequest(t, h, "/v1/proxy/anthropic/v1/messages",
			`{"model":"claude-sonnet-5","max_tokens":64,"messages":[{"role":"user","content":"keep going"}]}`,
			map[string]string{"X-Talon-Session-ID": sessID, "X-Talon-Agent-ID": "generator"})
		if rec.Code == http.StatusForbidden {
			denied = true
			denyBody = rec.Body.String()
		}
	}
	require.True(t, denied, "session budget must trip within the loop")
	assert.Contains(t, denyBody, "session_budget_exceeded", "deny rendered provider-native with machine code")

	// 5. The session is ONE cross-provider unit with per-subagent rollup.
	records, err := evStore.ListBySessionID(ctx, sessID)
	require.NoError(t, err)
	sum := evidence.BuildSessionSummary(sessID, records)
	assert.ElementsMatch(t, []string{"anthropic", "openai"}, sum.Providers, "one session, two providers")
	agentIDs := make([]string, 0, len(sum.Subagents))
	for _, a := range sum.Subagents {
		agentIDs = append(agentIDs, a.AgentID)
	}
	assert.Contains(t, agentIDs, "generator")
	assert.Contains(t, agentIDs, "executor")
	assert.GreaterOrEqual(t, sum.Denied, 1, "the budget denial is part of the session record")
	assert.Greater(t, sum.CacheReadTokens, 0, "cache-aware usage extracted from both wire families")

	// 6. Every record in the session verifies (signed evidence).
	for _, ev := range records {
		assert.True(t, evStore.VerifyRecord(ev), "record %s must verify", ev.ID)
	}

	// 7. The deny record carries the structured session_budget detail.
	foundDetail := false
	for _, ev := range records {
		if ev.SessionBudget != nil {
			foundDetail = true
			assert.InDelta(t, 0.02, ev.SessionBudget.Limit, 1e-9)
			assert.Greater(t, ev.SessionBudget.Spent, 0.0)
		}
	}
	assert.True(t, foundDetail, "structured {limit, spent, estimate} present on the deny record")
}

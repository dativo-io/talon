package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/session"
	"github.com/dativo-io/talon/internal/testutil"
)

// Session budget enforcement at the gateway (#198, epic #192 PR-G).
//
// The estimator below prices the pre-request estimate (the fixed 500/500
// token guess) at sbEstimate and everything else (real usage) at sbActual, so
// tests can steer spend and estimate independently.

const (
	sbTenantKeyA = "talon-gw-sb-aaaaaaa00001"
	sbTenantKeyB = "talon-gw-sb-bbbbbbb00001"
	sbTenantKeyX = "talon-gw-sb-xxxxxxx00001"
	sbEstimate   = 1.0
	sbActual     = 6.0
)

func sbEstimator(_, _ string, u Usage) CostResult {
	if u.Input == 500 && u.Output == 500 {
		return CostResult{Amount: sbEstimate, PricingKnown: true, PricingBasis: PricingBasisTable}
	}
	return CostResult{Amount: sbActual, PricingKnown: true, PricingBasis: PricingBasisTable}
}

func newSessionBudgetUpstreams(t *testing.T) (anthropicURL, openaiURL string) {
	t.Helper()
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":10,"output_tokens":5}}`))
	}))
	t.Cleanup(anth.Close)
	oai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl_1","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	}))
	t.Cleanup(oai.Close)
	return anth.URL, oai.URL
}

// newSessionBudgetGateway builds an enforce-mode gateway with the real OPA
// gateway engine, a session store, and the deterministic estimator above.
func newSessionBudgetGateway(t *testing.T, mode Mode, maxSessionCost float64) (evStore *evidence.Store, sessStore *session.Store, handler http.Handler) {
	t.Helper()
	anthropicURL, openaiURL := newSessionBudgetUpstreams(t)
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         mode,
		Providers: map[string]ProviderConfig{
			"anthropic": {Enabled: true, BaseURL: anthropicURL, SecretName: "anthropic-key"},
			"openai":    {Enabled: true, BaseURL: openaiURL, SecretName: "openai-key"},
		},
		OrganizationPolicy: OrganizationPolicy{Defaults: OrgDefaults{PIIAction: "warn", ResponsePIIAction: "allow"}},
		RateLimits:         RateLimitsConfig{GlobalRequestsPerMin: 100000, PerAgentRequestsPerMin: 100000},
		Timeouts:           TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.Validate())
	registry := testRegistry(
		testIdentity("coder-a", "tenant-a", sbTenantKeyA, &PolicyOverride{PIIAction: "warn", MaxSessionCost: maxSessionCost}),
		testIdentity("coder-b", "tenant-a", sbTenantKeyB, &PolicyOverride{PIIAction: "warn", MaxSessionCost: maxSessionCost}),
		testIdentity("coder-x", "tenant-b", sbTenantKeyX, &PolicyOverride{PIIAction: "warn", MaxSessionCost: maxSessionCost}),
	)
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	acl := secrets.ACL{Tenants: []string{"tenant-a", "tenant-b"}, Agents: []string{"*"}}
	require.NoError(t, secStore.Set(context.Background(), "anthropic-key", []byte("sk-ant-test-000-sb"), acl))
	require.NoError(t, secStore.Set(context.Background(), "openai-key", []byte("sk-test-000-sb"), acl))
	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)
	sessStore, err = session.NewStore(filepath.Join(dir, "sess.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessStore.Close() })
	gw, err := NewGateway(cfg, NewRegistryHolder(registry), classifier.MustNewScanner(), evStore, secStore, policyEngine, sbEstimator)
	require.NoError(t, err)
	gw.SetSessionStore(sessStore)
	gw.SetPricingCurrency("USD")
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	return evStore, sessStore, r
}

func sbDo(t *testing.T, h http.Handler, provider, key, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	var path, body string
	if provider == "anthropic" {
		path = "/v1/proxy/anthropic/v1/messages"
		body = `{"model":"claude-sonnet-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`
	} else {
		path = "/v1/proxy/openai/v1/chat/completions"
		body = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set("X-Talon-Session-ID", sessionID)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func lastGatewayEvidence(t *testing.T, evStore *evidence.Store, tenant string) *evidence.Evidence {
	t.Helper()
	list, err := evStore.List(context.Background(), tenant, "", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)
	require.NotEmpty(t, list)
	newest := &list[0]
	for i := range list {
		if list[i].Timestamp.After(newest.Timestamp) {
			newest = &list[i]
		}
	}
	return newest
}

// TestSessionBudget_CrossProviderDeny: €6 spent on anthropic against a €10
// cap → the next request is denied on the OTHER provider route, because the
// session accumulates per (tenant, agent, external id), not per provider.
func TestSessionBudget_CrossProviderDeny(t *testing.T) {
	evStore, sessStore, h := newSessionBudgetGateway(t, ModeEnforce, 10)

	rec1 := sbDo(t, h, "anthropic", sbTenantKeyA, "sess-xp")
	require.Equal(t, http.StatusOK, rec1.Code, rec1.Body.String())

	sess, err := sessStore.GetByExternal(context.Background(), "tenant-a", "coder-a", "sess-xp")
	require.NoError(t, err)
	assert.InDelta(t, sbActual, sess.TotalCost, 1e-9, "actual cost accumulated onto the session row")
	assert.Equal(t, session.SourceClientAsserted, sess.Source)

	// 6 spent + 6 estimate... estimate is 1.0: 6+1=7 <= 10 → still allowed.
	rec2 := sbDo(t, h, "openai", sbTenantKeyA, "sess-xp")
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())

	// Now 12 spent + 1 estimate > 10 → denied, on either provider route.
	rec3 := sbDo(t, h, "openai", sbTenantKeyA, "sess-xp")
	require.Equal(t, http.StatusForbidden, rec3.Code)
	assert.Contains(t, rec3.Body.String(), "session_budget_exceeded")

	rec4 := sbDo(t, h, "anthropic", sbTenantKeyA, "sess-xp")
	require.Equal(t, http.StatusForbidden, rec4.Code)
	assert.Contains(t, rec4.Body.String(), "session_budget_exceeded")

	// The deny evidence carries the structured {limit, spent, estimate}.
	ev := lastGatewayEvidence(t, evStore, "tenant-a")
	require.NotNil(t, ev.SessionBudget, "session_budget detail must be on the deny record")
	assert.InDelta(t, 10.0, ev.SessionBudget.Limit, 1e-9)
	assert.InDelta(t, 2*sbActual, ev.SessionBudget.Spent, 1e-9)
	assert.InDelta(t, sbEstimate, ev.SessionBudget.Estimate, 1e-9)
	assert.False(t, ev.PolicyDecision.Allowed)
}

// TestSessionBudget_AgentAndTenantIsolation: the same external session id
// under a different agent (same tenant) or different tenant is a separate
// session with a separate budget (#214, #215).
func TestSessionBudget_AgentAndTenantIsolation(t *testing.T) {
	_, sessStore, h := newSessionBudgetGateway(t, ModeEnforce, 10)

	// coder-a exhausts its cap under sess-shared.
	require.Equal(t, http.StatusOK, sbDo(t, h, "anthropic", sbTenantKeyA, "sess-shared").Code)
	require.Equal(t, http.StatusOK, sbDo(t, h, "anthropic", sbTenantKeyA, "sess-shared").Code)
	require.Equal(t, http.StatusForbidden, sbDo(t, h, "anthropic", sbTenantKeyA, "sess-shared").Code)

	// coder-b (same tenant) asserting the same id: fresh session, allowed.
	recB := sbDo(t, h, "anthropic", sbTenantKeyB, "sess-shared")
	require.Equal(t, http.StatusOK, recB.Code, recB.Body.String())

	// coder-x (different tenant) asserting the same id: fresh session, allowed.
	recX := sbDo(t, h, "anthropic", sbTenantKeyX, "sess-shared")
	require.Equal(t, http.StatusOK, recX.Code, recX.Body.String())

	// Three distinct rows, one per (tenant, agent) tuple.
	a, err := sessStore.GetByExternal(context.Background(), "tenant-a", "coder-a", "sess-shared")
	require.NoError(t, err)
	b, err := sessStore.GetByExternal(context.Background(), "tenant-a", "coder-b", "sess-shared")
	require.NoError(t, err)
	x, err := sessStore.GetByExternal(context.Background(), "tenant-b", "coder-x", "sess-shared")
	require.NoError(t, err)
	assert.NotEqual(t, a.ID, b.ID)
	assert.NotEqual(t, a.ID, x.ID)
	assert.InDelta(t, sbActual, b.TotalCost, 1e-9, "agent-b budget untouched by agent-a spend")
}

// TestSessionBudget_SyntheticSessionsCreateNoRows: header-less traffic gets a
// synthetic session id in evidence but must create ZERO session rows (#214).
func TestSessionBudget_SyntheticSessionsCreateNoRows(t *testing.T) {
	_, sessStore, h := newSessionBudgetGateway(t, ModeEnforce, 10)
	for i := 0; i < 5; i++ {
		require.Equal(t, http.StatusOK, sbDo(t, h, "openai", sbTenantKeyA, "").Code)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		rows, err := sessStore.ListByTenant(context.Background(), tenant, "", "")
		require.NoError(t, err)
		assert.Empty(t, rows, "synthetic sessions must not materialize session rows")
	}
}

// TestSessionBudget_FirstRequestOverCap: with no session row yet, spend is 0 —
// an estimate that alone exceeds the cap is denied on the session's first
// request.
func TestSessionBudget_FirstRequestOverCap(t *testing.T) {
	_, _, h := newSessionBudgetGateway(t, ModeEnforce, 0.5) // cap < estimate (1.0)
	rec := sbDo(t, h, "anthropic", sbTenantKeyA, "sess-first")
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "session_budget_exceeded")
}

// TestSessionBudget_SoftCapOvershoot documents the soft-cap semantics (#192
// §3.7): one in-flight request whose real cost exceeds the estimate can
// overshoot the cap; the NEXT request is denied. Atomic reservation is #144.
func TestSessionBudget_SoftCapOvershoot(t *testing.T) {
	_, sessStore, h := newSessionBudgetGateway(t, ModeEnforce, 5)

	// 0 + estimate(1) <= 5 → allowed; real cost 6 lands on the session.
	require.Equal(t, http.StatusOK, sbDo(t, h, "anthropic", sbTenantKeyA, "sess-over").Code)
	sess, err := sessStore.GetByExternal(context.Background(), "tenant-a", "coder-a", "sess-over")
	require.NoError(t, err)
	assert.Greater(t, sess.TotalCost, 5.0, "soft cap: a single request may overshoot")

	// The overshoot is caught on the next request.
	require.Equal(t, http.StatusForbidden, sbDo(t, h, "anthropic", sbTenantKeyA, "sess-over").Code)
}

// TestSessionBudget_ConcurrentBurstBound: N concurrent first requests all see
// zero spend (soft cap), so total spend is bounded by N * per-request cost —
// and the unique tuple index collapses the race to exactly one session row.
func TestSessionBudget_ConcurrentBurstBound(t *testing.T) {
	_, sessStore, h := newSessionBudgetGateway(t, ModeEnforce, 10)
	const n = 5
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = sbDo(t, h, "openai", sbTenantKeyA, "sess-burst").Code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		assert.Contains(t, []int{http.StatusOK, http.StatusForbidden}, c, "request %d", i)
	}
	rows, err := sessStore.ListByTenant(context.Background(), "tenant-a", "", "")
	require.NoError(t, err)
	require.Len(t, rows, 1, "concurrent create-if-absent must collapse to one row")
	assert.LessOrEqual(t, rows[0].TotalCost, float64(n)*sbActual+1e-9,
		"burst overshoot is bounded by N * per-request cost")
}

// TestSessionBudget_FailOpenAnnotated: a session-store failure must not take
// down traffic — the request proceeds and the gap is visible in signed
// evidence via the session_budget_unavailable annotation.
func TestSessionBudget_FailOpenAnnotated(t *testing.T) {
	evStore, sessStore, h := newSessionBudgetGateway(t, ModeEnforce, 10)
	require.NoError(t, sessStore.Close()) // break the store

	rec := sbDo(t, h, "openai", sbTenantKeyA, "sess-broken")
	require.Equal(t, http.StatusOK, rec.Code, "session budget check fails open")

	ev := lastGatewayEvidence(t, evStore, "tenant-a")
	assert.Contains(t, ev.GatewayAnnotations, "session_budget_unavailable")
	assert.True(t, ev.PolicyDecision.Allowed)
}

// TestSessionBudget_ShadowMode: in shadow mode the would-have-denied request
// proceeds and the deny is recorded as a shadow violation.
func TestSessionBudget_ShadowMode(t *testing.T) {
	evStore, _, h := newSessionBudgetGateway(t, ModeShadow, 10)

	require.Equal(t, http.StatusOK, sbDo(t, h, "anthropic", sbTenantKeyA, "sess-shadow").Code)
	require.Equal(t, http.StatusOK, sbDo(t, h, "anthropic", sbTenantKeyA, "sess-shadow").Code)
	// 12 + 1 > 10 → would deny; shadow lets it through.
	rec := sbDo(t, h, "anthropic", sbTenantKeyA, "sess-shadow")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	ev := lastGatewayEvidence(t, evStore, "tenant-a")
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "policy_deny" && strings.Contains(sv.Detail, "session_budget_exceeded") {
			found = true
		}
	}
	assert.True(t, found, "shadow violation must carry the session budget deny: %+v", ev.ShadowViolations)
	assert.True(t, ev.ObservationModeOverride)
}

// TestSessionBudgetDetail_OnlyOnSessionDeny: the structured detail is nil for
// unrelated reasons and populated from the policy input for session denies.
func TestSessionBudgetDetail_OnlyOnSessionDeny(t *testing.T) {
	assert.Nil(t, sessionBudgetDetail([]string{"budget_exceeded: daily"}, map[string]interface{}{}, 1))
	d := sessionBudgetDetail(
		[]string{"session_budget_exceeded: session spend 6.00 + estimate 1.00 exceeds limit 5.00"},
		map[string]interface{}{"agent_max_session_cost": 5.0, "session_cost_total": 6.0}, 1.0)
	require.NotNil(t, d)
	assert.Equal(t, 5.0, d.Limit)
	assert.Equal(t, 6.0, d.Spent)
	assert.Equal(t, 1.0, d.Estimate)
}

// Guard: the SessionBudget evidence field is additive (omitempty) — a record
// without it marshals identically to a pre-1.8 record.
func TestSessionBudget_EvidenceFieldAdditive(t *testing.T) {
	ev := evidence.Evidence{ID: "x"}
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "session_budget")
}

// TestPolicyInputParity_WithAssertedSession extends the parity guarantee to
// session state: with an asserted session (source in context) and a populated
// session store, the primary and every failover candidate must see the exact
// same session_cost_total and session_stage_counts — a candidate evaluated
// against different session state could allow what the primary denied.
func TestPolicyInputParity_WithAssertedSession(t *testing.T) {
	_, sessStore, _ := newSessionBudgetGateway(t, ModeEnforce, 10)
	// Reach the gateway through a second handle to call the builder directly.
	dir := t.TempDir()
	_ = dir
	ctx := context.Background()
	sess, err := sessStore.GetOrCreateExternal(ctx, "tenant-a", "coder-a", "sess-parity", session.SourceClientAsserted)
	require.NoError(t, err)
	require.NoError(t, sessStore.AddUsage(ctx, sess.ID, 4.5, 100))
	require.NoError(t, sessStore.IncrementStageCount(ctx, sess.ID, "judge"))

	agent := testIdentity("coder-a", "tenant-a", sbTenantKeyA, &PolicyOverride{MaxSessionCost: 10})
	gw, err := NewGateway(&GatewayConfig{
		Enabled: true, ListenPrefix: "/v1/proxy", Mode: ModeEnforce,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: "http://unused", SecretName: "k"},
			"backup": {Enabled: true, BaseURL: "http://unused", SecretName: "k"},
		},
		Timeouts: TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}, NewRegistryHolder(testRegistry(agent)), classifier.MustNewScanner(), nil, nil, nil, sbEstimator)
	require.NoError(t, err)
	gw.SetSessionStore(sessStore)

	assertedCtx := context.WithValue(ctx, gatewaySessionSourceKey, orchSourceClientAsserted)

	primary, primaryUnavail := gw.buildPolicyInputForRequest(assertedCtx, agent, "openai", "gpt-4o-mini", 1, 0.01, 1, 2, "sess-parity")
	candidate, candUnavail := gw.buildPolicyInputForRequest(assertedCtx, agent, "backup", "gpt-4o", 1, 0.02, 1, 2, "sess-parity")

	require.False(t, primaryUnavail)
	require.False(t, candUnavail)
	assert.Equal(t, 4.5, primary["session_cost_total"])
	assert.Equal(t, primary["session_cost_total"], candidate["session_cost_total"],
		"candidate must see the same session spend as the primary")
	assert.Equal(t, primary["session_stage_counts"], candidate["session_stage_counts"],
		"candidate must see the same stage counts as the primary")
	assert.Equal(t, 10.0, primary["agent_max_session_cost"])
	assert.Equal(t, primary["agent_max_session_cost"], candidate["agent_max_session_cost"])

	primaryKeys := make([]string, 0, len(primary))
	for k := range primary {
		primaryKeys = append(primaryKeys, k)
	}
	candidateKeys := make([]string, 0, len(candidate))
	for k := range candidate {
		candidateKeys = append(candidateKeys, k)
	}
	assert.ElementsMatch(t, primaryKeys, candidateKeys,
		"primary and candidate must expose the same fields with session state present")
}

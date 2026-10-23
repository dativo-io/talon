package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

// Preventive budget governance for the agent daily/monthly caps: the caps
// are enforced BEFORE dispatch, hold under concurrency across sessions, and
// fail closed when the state they depend on cannot be established. Every
// denial here is proven preventive by the upstream call counter (AGENTS.md
// "Preventive-control proof"), never by the status code alone.

type budgetUpstream struct {
	calls   atomic.Int64
	handler atomic.Pointer[http.HandlerFunc]
}

func (u *budgetUpstream) set(h http.HandlerFunc) { u.handler.Store(&h) }

// newBudgetGateway builds an enforce gateway for one agent ("coder-a" in
// "tenant-a") with the given override and estimator. The openai upstream
// answers with a fixed usage unless the test installs its own handler.
func newBudgetGateway(t *testing.T, override *PolicyOverride, estimator CostEstimator) (gw *Gateway, evStore *evidence.Store, sessStore *session.Store, h http.Handler, up *budgetUpstream) {
	t.Helper()
	up = &budgetUpstream{}
	up.set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl_1","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.calls.Add(1)
		(*up.handler.Load())(w, r)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled: true, ListenPrefix: "/v1/proxy",
		Providers: map[string]ProviderConfig{
			"openai":    {Enabled: true, BaseURL: srv.URL, SecretName: "openai-key"},
			"anthropic": {Enabled: true, BaseURL: srv.URL, SecretName: "openai-key"},
		},
		OrganizationPolicy: OrganizationPolicy{Defaults: OrgDefaults{PIIAction: "warn", ResponsePIIAction: "allow"}},
		RateLimits:         RateLimitsConfig{GlobalRequestsPerMin: 100000, PerAgentRequestsPerMin: 100000},
		Timeouts:           TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.Validate())
	if override == nil {
		override = &PolicyOverride{PIIAction: "warn"}
	}
	registry := testRegistry(testIdentity("coder-a", "tenant-a", sbTenantKeyA, override))
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "openai-key", []byte("sk-test-000-budget"), secrets.ACL{Tenants: []string{"tenant-a"}, Agents: []string{"*"}}))
	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)
	sessStore, err = session.NewStore(filepath.Join(dir, "sess.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessStore.Close() })
	gw, err = NewGateway(cfg, NewRegistryHolder(registry), classifier.MustNewScanner(), evStore, secStore, policyEngine, estimator)
	require.NoError(t, err)
	gw.SetSessionStore(sessStore)
	gw.SetPricingCurrency("USD")
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	return gw, evStore, sessStore, r, up
}

func agentSpendToday(t *testing.T, evStore *evidence.Store, tenant, agent string) float64 {
	t.Helper()
	now := time.Now().UTC()
	byAgent, err := evStore.CostByAgent(context.Background(), tenant, time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC), now.Add(time.Minute))
	require.NoError(t, err)
	return byAgent[agent]
}

// TestBudget_ConcurrentSessions_AgentCapHardBound: an agent daily cap of 3
// at a flat 1.0 estimate/actual, five concurrent first requests on five
// DIFFERENT sessions — before the in-flight ledger all five read the same
// zero spend and all five reached the provider. Now exactly three do.
func TestBudget_ConcurrentSessions_AgentCapHardBound(t *testing.T) {
	gw, evStore, _, h, up := newBudgetGateway(t, &PolicyOverride{PIIAction: "warn", MaxDailyCost: 3}, sbFlatEstimator)
	const n = 5
	var wg sync.WaitGroup
	codes := make([]int, n)
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := sbDo(t, h, "openai", sbTenantKeyA, "sess-"+string(rune('a'+i)))
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}(i)
	}
	wg.Wait()
	allowed, denied := 0, 0
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			allowed++
		case http.StatusForbidden:
			denied++
			assert.Contains(t, bodies[i], "budget_exceeded")
		default:
			t.Fatalf("request %d: unexpected status %d: %s", i, c, bodies[i])
		}
	}
	assert.Equal(t, 3, allowed, "cap 3 at 1.0/request admits exactly 3 across sessions")
	assert.Equal(t, 2, denied)
	assert.Equal(t, int64(3), up.calls.Load(), "denied requests never reach the provider")
	assert.InDelta(t, 3.0, agentSpendToday(t, evStore, "tenant-a", "coder-a"), 1e-9, "settled spend equals the admitted requests")
	assert.Zero(t, gw.agentInflight.pending(agentInflightKey(testIdentity("coder-a", "tenant-a", "", nil))), "every in-flight claim released")
}

// TestBudget_HealthyState_Unaffected: with healthy stores and a priced
// model, capped traffic flows exactly as before — allowed records, settled
// spend accumulating, no claim left behind.
func TestBudget_HealthyState_Unaffected(t *testing.T) {
	gw, evStore, sessStore, h, up := newBudgetGateway(t, &PolicyOverride{PIIAction: "warn", MaxDailyCost: 100, MaxSessionCost: 50}, sbEstimator)
	for i := 0; i < 3; i++ {
		rec := sbDo(t, h, "openai", sbTenantKeyA, "sess-healthy")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	}
	assert.Equal(t, int64(3), up.calls.Load())
	ev := lastGatewayEvidence(t, evStore, "tenant-a")
	assert.True(t, ev.PolicyDecision.Allowed)
	assert.Empty(t, ev.GatewayAnnotations, "healthy state carries no budget-gap annotation")
	assert.InDelta(t, 3*sbActual, agentSpendToday(t, evStore, "tenant-a", "coder-a"), 1e-9)
	sess, err := sessStore.GetByExternal(context.Background(), "tenant-a", "coder-a", "sess-healthy")
	require.NoError(t, err)
	assert.InDelta(t, 3*sbActual, sess.TotalCost, 1e-9)
	assert.Zero(t, sess.ReservedCost)
	assert.Zero(t, gw.agentInflight.pending(agentInflightKey(testIdentity("coder-a", "tenant-a", "", nil))))
}

// TestBudget_AgentSpendUnreadable_FailClosed: the agent spend read fails
// while a daily cap binds. The request is denied 503 budget_unavailable
// before any dispatch, and the signed deny record carries the
// agent_budget_unavailable annotation (which used to be silently dropped by
// the annotation registry) so exhaustion and system failure are told apart.
func TestBudget_AgentSpendUnreadable_FailClosed(t *testing.T) {
	gw, evStore, _, h, up := newBudgetGateway(t, &PolicyOverride{PIIAction: "warn", MaxDailyCost: 3}, sbEstimator)
	gw.budgetReadHook = func(context.Context) error { return errors.New("injected: evidence store unreachable") }

	rec := sbDo(t, h, "openai", sbTenantKeyA, "sess-unreadable")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, CodeBudgetUnavailable, providerErrorType(t, rec))
	assert.Equal(t, int64(0), up.calls.Load(), "a request whose budget state is unknown must not reach the provider")

	ev := lastGatewayEvidence(t, evStore, "tenant-a")
	assertEnforcedDenial(t, ev)
	assert.Contains(t, ev.GatewayAnnotations, "agent_budget_unavailable")
	assert.Contains(t, strings.Join(ev.PolicyDecision.Reasons, " "), "budget state unavailable")
	assert.NotContains(t, strings.Join(ev.PolicyDecision.Reasons, " "), "budget_exceeded", "system failure is not exhaustion")
	assert.Nil(t, ev.CostBudget, "no cap was exceeded; the deny carries no exhaustion detail")

	// The store recovers: the very next request is admitted (retriable code).
	gw.budgetReadHook = nil
	rec = sbDo(t, h, "openai", sbTenantKeyA, "sess-unreadable")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, int64(1), up.calls.Load())
}

// TestBudget_EvidenceStoreOutage_FailClosed: a real outage (store closed)
// — no spend read, and no record could be written either. The client gets
// the operational error, nothing is dispatched, and no receipt is claimed.
func TestBudget_EvidenceStoreOutage_FailClosed(t *testing.T) {
	_, evStore, _, h, up := newBudgetGateway(t, &PolicyOverride{PIIAction: "warn", MaxDailyCost: 3}, sbEstimator)
	require.NoError(t, evStore.Close())
	rec := sbDo(t, h, "openai", sbTenantKeyA, "")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, CodeBudgetUnavailable, providerErrorType(t, rec))
	assert.Equal(t, int64(0), up.calls.Load())
	assert.NotContains(t, rec.Header().Get("X-Talon-Evidence-ID"), "ev_", "no audit receipt may be claimed for an unrecorded denial")
}

// TestBudget_UnpricedModel_DeniedUnderCap: a model the pricing table does
// not know would be admitted and settled at a flat fallback that
// under-counts frontier models by an order of magnitude. Under a binding
// cap the request is denied pricing_unavailable before dispatch; a priced
// model on the same agent is unaffected.
func TestBudget_UnpricedModel_DeniedUnderCap(t *testing.T) {
	unpricedOpenAI := func(provider, _ string, u Usage) CostResult {
		if provider == "openai" {
			return defaultCostEstimator(provider, "", u)
		}
		return sbEstimator(provider, "", u)
	}
	_, evStore, _, h, up := newBudgetGateway(t, &PolicyOverride{PIIAction: "warn", MaxDailyCost: 5}, unpricedOpenAI)

	rec := sbDo(t, h, "openai", sbTenantKeyA, "")
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, CodePricingUnavailable, providerErrorType(t, rec))
	assert.Contains(t, rec.Body.String(), "pricing/models.yaml", "the error names the remediation")
	assert.Equal(t, int64(0), up.calls.Load(), "an unpriced request under a cap never reaches the provider")
	ev := lastGatewayEvidence(t, evStore, "tenant-a")
	assertEnforcedDenial(t, ev)
	assert.Contains(t, strings.Join(ev.PolicyDecision.Reasons, " "), "pricing unavailable")

	rec = sbDo(t, h, "anthropic", sbTenantKeyA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, int64(1), up.calls.Load())
	ev = lastGatewayEvidence(t, evStore, "tenant-a")
	assert.True(t, ev.PolicyDecision.Allowed)
	assert.True(t, ev.Execution.PricingKnown)
}

// TestBudget_StreamingSettledOnce: a streamed completion settles exactly one
// charge — priced from the usage the stream reported — into the evidence
// record, the agent's daily spend and the session total; the reservation
// is consumed, not leaked.
func TestBudget_StreamingSettledOnce(t *testing.T) {
	_, evStore, sessStore, h, up := newBudgetGateway(t, &PolicyOverride{PIIAction: "warn", MaxDailyCost: 100, MaxSessionCost: 50}, sbEstimator)
	up.set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n" +
			"data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\n" +
			"data: [DONE]\n\n"))
	})
	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sbTenantKeyA)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Session-ID", "sess-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, int64(1), up.calls.Load())

	ev := lastGatewayEvidence(t, evStore, "tenant-a")
	assert.True(t, ev.PolicyDecision.Allowed)
	assert.Equal(t, 10, ev.Execution.Tokens.Input)
	assert.Equal(t, 5, ev.Execution.Tokens.Output)
	assert.InDelta(t, sbActual, ev.Execution.Cost, 1e-9, "settled from reported usage, not the estimate")
	assert.InDelta(t, sbEstimate, ev.Execution.EstimatedCost, 1e-9)
	assert.InDelta(t, sbActual, agentSpendToday(t, evStore, "tenant-a", "coder-a"), 1e-9, "one charge in the agent's spend")
	sess, err := sessStore.GetByExternal(context.Background(), "tenant-a", "coder-a", "sess-stream")
	require.NoError(t, err)
	assert.InDelta(t, sbActual, sess.TotalCost, 1e-9, "one charge on the session")
	assert.Zero(t, sess.ReservedCost)
}

// TestBudget_RetrySettledOnce: a transient upstream failure that recovers
// on a same-provider retry is one request with two provider attempts: the
// failed attempt is signed evidence carrying no cost, and the agent's spend
// grows by exactly one settled charge.
func TestBudget_RetrySettledOnce(t *testing.T) {
	_, evStore, sessStore, h, up := newBudgetGateway(t, &PolicyOverride{
		PIIAction: "warn", MaxDailyCost: 100, MaxSessionCost: 50,
		Retry: &RetryConfig{MaxAttempts: 2, InitialBackoff: "1ms", MaxBackoff: "5ms"},
	}, sbEstimator)
	var attempt atomic.Int64
	up.set(func(w http.ResponseWriter, _ *http.Request) {
		if attempt.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"upstream unavailable","type":"server_error"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl_1","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	})
	rec := sbDo(t, h, "openai", sbTenantKeyA, "sess-retry")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, int64(2), up.calls.Load(), "first attempt + one retry")

	recs, err := evStore.List(context.Background(), "tenant-a", "coder-a", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)
	var attempts, finals int
	for i := range recs {
		switch recs[i].InvocationType {
		case "gateway_failover_attempt":
			attempts++
			assert.Zero(t, recs[i].Execution.Cost, "a failed attempt books no cost")
		case "gateway":
			finals++
			assert.InDelta(t, sbActual, recs[i].Execution.Cost, 1e-9)
		}
	}
	assert.Equal(t, 1, attempts)
	assert.Equal(t, 1, finals)
	assert.InDelta(t, sbActual, agentSpendToday(t, evStore, "tenant-a", "coder-a"), 1e-9, "retries never double-count")
	sess, err := sessStore.GetByExternal(context.Background(), "tenant-a", "coder-a", "sess-retry")
	require.NoError(t, err)
	assert.InDelta(t, sbActual, sess.TotalCost, 1e-9)
	assert.Zero(t, sess.ReservedCost)
}

// TestAgentInflight_ReserveRelease pins the ledger arithmetic: others'
// claims are visible to a new reservation, releases are idempotent, and an
// emptied key does not linger.
func TestAgentInflight_ReserveRelease(t *testing.T) {
	var a agentInflight
	r1, others := a.reserve("k", 1)
	assert.Zero(t, others)
	r2, others := a.reserve("k", 2)
	assert.InDelta(t, 1.0, others, 1e-12)
	assert.InDelta(t, 3.0, a.pending("k"), 1e-12)
	a.release(r1)
	a.release(r1) // idempotent
	assert.InDelta(t, 2.0, a.pending("k"), 1e-12)
	a.release(r2)
	assert.Zero(t, a.pending("k"))
	assert.Empty(t, a.m)
	a.release(nil) // nil-safe
}

// TestBudget_FailoverCandidateUnpriced_FailsClosed: the pricing precondition
// binds fallback candidates too. A capped agent whose primary fails must not
// be rescued by a provider Talon cannot price — the candidate is skipped,
// the request fails closed, and the backup is never dispatched.
func TestBudget_FailoverCandidateUnpriced_FailsClosed(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
	gw.costEstimate = func(provider, model string, u Usage) CostResult {
		if provider == "backup" {
			return defaultCostEstimator(provider, model, u) // not in the pricing table
		}
		return testTableEstimator(provider, model, u)
	}

	w := makeFailoverRequest(gw, failoverTestBody)
	assert.NotEqual(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, int64(1), primary.calls.Load())
	assert.Equal(t, int64(0), backup.calls.Load(), "an unpriced candidate must never be dispatched under a cap")

	_, final := failoverRecords(t, store, correlationIDFromResponse(t, w))
	require.NotNil(t, final)
	require.NotNil(t, final.Failover)
	assert.Equal(t, evidence.FailoverRoleFailClosed, final.Failover.Role)
	require.Len(t, final.Failover.SkippedCandidates, 1)
	assert.Equal(t, "backup", final.Failover.SkippedCandidates[0].Provider)
	assert.Contains(t, final.Failover.SkippedCandidates[0].Reason, CodePricingUnavailable)
}

// TestBudget_FailoverBurst_AgentCapHardBound: the agent-cap claim follows
// the model that is actually dispatched. Daily cap 3; the primary prices at
// 0.01 and always fails transiently; the fallback prices at 2. Five
// concurrent requests on five sessions each claim 0.01 for the primary —
// enough for all five — but every fallback candidate is re-admitted at ITS
// estimate against settled spend + the other requests' fallback claims, so
// exactly one request reaches the backup provider; the others fail closed
// with no policy-valid candidate.
func TestBudget_FailoverBurst_AgentCapHardBound(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
	gw.costEstimate = func(provider, _ string, _ Usage) CostResult {
		if provider == "backup" {
			return CostResult{Amount: 2, PricingKnown: true, PricingBasis: PricingBasisTable}
		}
		return CostResult{Amount: 0.01, PricingKnown: true, PricingBasis: PricingBasisTable}
	}
	agent := failoverAgent(gw)
	if agent.Override == nil {
		agent.Override = &PolicyOverride{}
	}
	agent.Override.MaxDailyCost = 3

	const n = 5
	var wg sync.WaitGroup
	codes := make([]int, n)
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := chi.NewRouter()
			r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://test/v1/proxy/openai/v1/chat/completions", strings.NewReader(failoverTestBody))
			req.Header.Set("Authorization", "Bearer "+failoverTestAgentKey)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Talon-Session-ID", "sess-fo-"+string(rune('a'+i)))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			codes[i], bodies[i] = w.Code, w.Body.String()
		}(i)
	}
	wg.Wait()

	ok := 0
	for i, c := range codes {
		if c == http.StatusOK {
			ok++
			continue
		}
		assert.NotEqual(t, http.StatusOK, c, "request %d: %s", i, bodies[i])
	}
	assert.Equal(t, 1, ok, "cap 3 admits exactly one fallback at 2.0: codes=%v", codes)
	// The hard bound is the backup count. How many requests reached the
	// primary depends on scheduling: a request admitted after the winner
	// settled 2.0 while another still holds its 2.0 fallback claim sees the
	// cap exceeded and is denied before the primary — conservative, never
	// an over-admission — so the primary count is bounded, not fixed.
	primaryCalls := primary.calls.Load()
	assert.GreaterOrEqual(t, primaryCalls, int64(1), "the winner tried the primary first")
	assert.LessOrEqual(t, primaryCalls, int64(n), "no request tried the primary twice")
	assert.Equal(t, int64(1), backup.calls.Load(), "fallback candidates serialize against each other's fallback estimates")

	recs, err := store.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 100)
	require.NoError(t, err)
	var settled float64
	for i := range recs {
		if recs[i].InvocationType == "gateway" && recs[i].PolicyDecision.Allowed && recs[i].Status != "failed" {
			settled += recs[i].Execution.Cost
		}
	}
	assert.InDelta(t, 2.0, settled, 1e-9, "one fallback charge settled")
	assert.Zero(t, gw.agentInflight.pending(agentInflightKey(agent)), "every claim released, re-priced ones included")
}

// TestBudget_UnrecordedCharge_CountedUntilRestart: the provider answered,
// the evidence record failed to commit. The charge cannot reach the store,
// but this process remembers it: the agent's next admission reads spend
// including the lost charge, so it is denied once the cap is reached rather
// than admitted on a short total.
func TestBudget_UnrecordedCharge_CountedUntilRestart(t *testing.T) {
	gw, evStore, sessStore, h, up := newBudgetGateway(t, &PolicyOverride{PIIAction: "warn", MaxDailyCost: 6.5, MaxSessionCost: 50}, sbEstimator)
	var failures atomic.Int64
	gw.evidenceWriteHook = func(_ context.Context, p *RecordGatewayEvidenceParams) error {
		if p.PolicyAllowed && failures.Add(1) == 1 {
			return errors.New("injected: evidence store refused the record")
		}
		return nil
	}

	// 1. Dispatched and answered; the record is lost. The client got its
	//    response (nothing can un-send it), the session is still settled.
	rec := sbDo(t, h, "openai", sbTenantKeyA, "sess-lost")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, int64(1), up.calls.Load())
	assert.Zero(t, agentSpendToday(t, evStore, "tenant-a", "coder-a"), "the lost record never reached the store")
	sess, err := sessStore.GetByExternal(context.Background(), "tenant-a", "coder-a", "sess-lost")
	require.NoError(t, err)
	assert.InDelta(t, sbActual, sess.TotalCost, 1e-9, "the session is settled regardless")
	assert.Zero(t, sess.ReservedCost)

	// 2. The next admission counts the unrecorded 6.0: 6.0 + 1.0 estimate
	//    > 6.5 → denied budget_exceeded, no dispatch. On the old code it read
	//    zero spend and dispatched.
	rec = sbDo(t, h, "openai", sbTenantKeyA, "sess-next")
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "budget_exceeded", providerErrorType(t, rec))
	assert.Equal(t, int64(1), up.calls.Load(), "the lost charge still gates the next request")
	ev := lastGatewayEvidence(t, evStore, "tenant-a")
	assertEnforcedDenial(t, ev)
	require.NotNil(t, ev.CostBudget)
	assert.InDelta(t, sbActual, ev.CostBudget.Spent, 1e-9, "the deny record shows the unrecorded charge as spend")
}

func TestAgentInflight_AdjustAndUnrecorded(t *testing.T) {
	var a agentInflight
	r1, _ := a.reserve("k", 0.01)
	r2, _ := a.reserve("k", 0.01)
	r1, others := a.adjust(r1, "k", 2)
	assert.InDelta(t, 0.01, others, 1e-12, "the other claim is still at the primary price")
	assert.InDelta(t, 2.01, a.pending("k"), 1e-12)
	_, others = a.adjust(r2, "k", 2)
	assert.InDelta(t, 2.0, others, 1e-12, "the re-priced claim is visible to the next candidate")
	r1, _ = a.adjust(r1, "k", 0.01) // reverted
	assert.InDelta(t, 2.01, a.pending("k"), 1e-12)
	a.release(r1)
	a.release(r2)
	assert.Zero(t, a.pending("k"))
	created, others := a.adjust(nil, "k", 3) // a claim that did not exist (zero primary estimate)
	assert.Zero(t, others)
	a.release(created)
	assert.Empty(t, a.m)

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	day := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	month := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a.noteUnrecorded("k", 1.5, now)
	a.noteUnrecorded("k", 0.5, day.Add(-time.Hour)) // yesterday: monthly only
	a.noteUnrecorded("k", 9, month.Add(-time.Hour)) // last month: pruned
	a.noteUnrecorded("k", 0, now)                   // nothing to remember
	assert.InDelta(t, 1.5, a.unrecordedSince("k", day, month), 1e-12)
	assert.InDelta(t, 2.0, a.unrecordedSince("k", month, month), 1e-12)
	assert.Len(t, a.unrecorded["k"], 2, "last month's charge was pruned")
}

// TestBudget_FailoverBurst_SessionCapHardBound is the session-cap twin of
// the agent-cap burst: session cap 3, agent cap 100, primary 0.01 (always
// failing transiently), fallback 2, five concurrent requests on ONE
// session. Each reserved 0.01 against the session for the primary; a
// dearer fallback re-reserves the difference atomically in the session
// store and is admitted against settled + every other request's fallback
// reservation — exactly one reaches the backup, the session settles 2.0
// and holds no reservation afterwards.
func TestBudget_FailoverBurst_SessionCapHardBound(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, _ := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
	sessStore, err := session.NewStore(filepath.Join(t.TempDir(), "sess.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessStore.Close() })
	gw.SetSessionStore(sessStore)
	gw.costEstimate = func(provider, _ string, _ Usage) CostResult {
		if provider == "backup" {
			return CostResult{Amount: 2, PricingKnown: true, PricingBasis: PricingBasisTable}
		}
		return CostResult{Amount: 0.01, PricingKnown: true, PricingBasis: PricingBasisTable}
	}
	agent := failoverAgent(gw)
	if agent.Override == nil {
		agent.Override = &PolicyOverride{}
	}
	agent.Override.MaxDailyCost = 100
	agent.Override.MaxSessionCost = 3

	const n = 5
	var wg sync.WaitGroup
	codes := make([]int, n)
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := chi.NewRouter()
			r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://test/v1/proxy/openai/v1/chat/completions", strings.NewReader(failoverTestBody))
			req.Header.Set("Authorization", "Bearer "+failoverTestAgentKey)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Talon-Session-ID", "sess-fo-shared")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			codes[i], bodies[i] = w.Code, w.Body.String()
		}(i)
	}
	wg.Wait()

	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	assert.Equal(t, 1, ok, "session cap 3 admits exactly one fallback at 2.0: codes=%v", codes)
	// The hard bound is the backup count. How many requests reached the
	// primary depends on scheduling: a request admitted after the winner
	// settled 2.0 while another still holds its re-priced 2.0 session
	// reservation sees settled + reserved + 0.01 > 3 and is denied before
	// the primary — conservative, never an over-admission — so the primary
	// count is bounded, not fixed, and the settled total follows it.
	primaryCalls := primary.calls.Load()
	assert.GreaterOrEqual(t, primaryCalls, int64(1), "the winner tried the primary first")
	assert.LessOrEqual(t, primaryCalls, int64(n), "no request tried the primary twice")
	assert.Equal(t, int64(1), backup.calls.Load(), "fallback candidates serialize against each other's session reservations")

	sess, err := sessStore.GetByExternal(context.Background(), agent.TenantID, agent.Name, "sess-fo-shared")
	require.NoError(t, err)
	// 2.0 for the one fallback plus 0.01 for each request that tried the
	// primary and then failed closed: those book their primary estimate (no
	// usage was observed — pre-existing settle semantics, unchanged here).
	// A request denied before the primary books nothing.
	failedClosed := float64(primaryCalls - 1)
	assert.InDelta(t, 2.0+failedClosed*0.01, sess.TotalCost, 1e-9, "the one fallback settled at its actual cost; fail-closed attempts at their estimate")
	assert.InDelta(t, 0, sess.ReservedCost, 1e-9, "every reservation — re-priced or reverted — was released")
	assert.Zero(t, gw.agentInflight.pending(agentInflightKey(agent)))
}

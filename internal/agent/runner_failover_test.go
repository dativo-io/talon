package agent

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

// flakyProvider fails Generate with the given error until failWith is
// cleared, then succeeds.
type flakyProvider struct {
	name         string
	jurisdiction string
	failWith     error
	calls        int
}

func (p *flakyProvider) Name() string { return p.name }
func (p *flakyProvider) Metadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{ID: p.name, DisplayName: p.name, Jurisdiction: p.jurisdiction}
}

func (p *flakyProvider) Generate(_ context.Context, req *llm.Request) (*llm.Response, error) {
	p.calls++
	if p.failWith != nil {
		return nil, p.failWith
	}
	return &llm.Response{Content: "ok from " + p.name, Model: req.Model, InputTokens: 1, OutputTokens: 1}, nil
}

func (p *flakyProvider) Stream(_ context.Context, _ *llm.Request, ch chan<- llm.StreamChunk) error {
	close(ch)
	return nil
}
func (p *flakyProvider) EstimateCost(string, int, int) float64    { return 0.0001 }
func (p *flakyProvider) ValidateConfig() error                    { return nil }
func (p *flakyProvider) HealthCheck(context.Context) error        { return nil }
func (p *flakyProvider) WithHTTPClient(*http.Client) llm.Provider { return p }

func newFailoverTestRunner(t *testing.T, providers map[string]llm.Provider, routing *policy.ModelRoutingConfig) (*Runner, *evidence.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return &Runner{
		router:        llm.NewRouter(routing, providers, nil),
		evidence:      evidence.NewGenerator(store),
		evidenceStore: store,
	}, store
}

// runFailoverRecords splits a correlation's records into failed attempts and
// per-engagement terminal records.
func runFailoverRecords(t *testing.T, store *evidence.Store, correlationID string) (attempts, terminals []*evidence.Evidence) {
	t.Helper()
	records, err := store.ListByCorrelationID(context.Background(), correlationID)
	require.NoError(t, err)
	for _, ev := range records {
		switch ev.InvocationType {
		case "llm_failover_attempt":
			attempts = append(attempts, ev)
		case "llm_failover_decision":
			terminals = append(terminals, ev)
		}
	}
	return attempts, terminals
}

// TestResolveProvider_SovereigntyRoutes_USRejectedLocalSelected proves the
// genuine policy-driven sovereignty routing behind the demo's ROUTED act
// (#107): under eu_strict, a HEALTHY US primary is pre-emptively rejected by
// the routing policy (never dispatched) and a LOCAL candidate is selected for
// the SAME request, with BOTH candidates captured in the RouteDecision that
// flows into signed evidence. This is distinct from error-driven failover.
func TestResolveProvider_SovereigntyRoutes_USRejectedLocalSelected(t *testing.T) {
	usPrimary := &flakyProvider{name: "openai", jurisdiction: "US"} // healthy — not failing
	localFallback := &flakyProvider{name: "ollama", jurisdiction: "LOCAL"}
	routing := &policy.ModelRoutingConfig{
		Tier2: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3:70b"}},
	}
	r, _ := newFailoverTestRunner(t, map[string]llm.Provider{"openai": usPrimary, "ollama": localFallback}, routing)

	req := &RunRequest{TenantID: "t1", AgentName: "a1", InvocationType: "manual", SovereigntyMode: "eu_strict"}
	provider, model, _, _, routeDecision, _, err := r.resolveProvider(
		context.Background(), req, 2, nil, euOnlyRoutingEvaluator{}, req.SovereigntyMode)
	require.NoError(t, err)

	// LOCAL candidate selected; US primary never dispatched.
	assert.Equal(t, "ollama", provider.Name(), "LOCAL candidate must be selected")
	assert.Equal(t, "llama3:70b", model)
	assert.Equal(t, 0, usPrimary.calls, "sovereignty-rejected US primary must never be dispatched")

	// Evidence-bearing RouteDecision records BOTH the rejected US candidate and
	// the selected LOCAL one.
	require.NotNil(t, routeDecision)
	assert.Equal(t, "ollama", routeDecision.SelectedProvider)
	require.NotEmpty(t, routeDecision.Rejected, "the rejected US candidate must be recorded")
	var rejectedOpenAI *llm.RejectedRouteCandidate
	for i := range routeDecision.Rejected {
		if routeDecision.Rejected[i].ProviderID == "openai" {
			rejectedOpenAI = &routeDecision.Rejected[i]
		}
	}
	require.NotNil(t, rejectedOpenAI, "openai/US must appear as a rejected candidate")
	assert.NotEmpty(t, rejectedOpenAI.Reason, "rejection reason must be recorded")
}

func TestRunFailover_TransientErrorFailsOverToChainCandidate(t *testing.T) {
	primary := &flakyProvider{name: "openai", jurisdiction: "US", failWith: &llm.ProviderError{Code: "server_error", Provider: "openai", Message: "boom"}}
	backup := &flakyProvider{name: "ollama", jurisdiction: "LOCAL"}
	routing := &policy.ModelRoutingConfig{
		Tier1: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3:70b"}},
	}
	r, store := newFailoverTestRunner(t, map[string]llm.Provider{"openai": primary, "ollama": backup}, routing)

	req := &RunRequest{TenantID: "t1", AgentName: "a1", InvocationType: "manual"}
	fo := r.newRunFailover(context.Background(), req, "corr-fo-1", 1, nil, "", nil)

	resp, usedProvider, usedModel, err := fo.generate(context.Background(),
		primary, "gpt-4o", &llm.Request{Model: "gpt-4o", Messages: []llm.Message{{Role: "user", Content: "hi"}}})
	require.NoError(t, err)
	assert.Equal(t, "ok from ollama", resp.Content)
	assert.Equal(t, "ollama", usedProvider.Name())
	assert.Equal(t, "llama3:70b", usedModel)
	assert.Equal(t, 1, primary.calls)
	assert.Equal(t, 1, backup.calls)

	attempts, terminals := runFailoverRecords(t, store, "corr-fo-1")
	require.Len(t, attempts, 1, "one failed-attempt record")
	att := attempts[0]
	assert.Equal(t, evidence.FailoverRoleFailedAttempt, att.Failover.Role)
	assert.Equal(t, "openai", att.Failover.Provider)
	assert.Equal(t, "upstream_5xx", att.Failover.ErrorClass)
	assert.Equal(t, evidence.FailureReasonProviderTransient, att.FailureReason)
	assert.NotEmpty(t, att.Failover.FailoverGroupID)
	assert.True(t, store.VerifyRecord(att))

	require.Len(t, terminals, 1, "one terminal record per engagement")
	dec := terminals[0]
	assert.Equal(t, evidence.FailoverRoleFallbackDecision, dec.Failover.Role)
	assert.Equal(t, "ollama", dec.Failover.Provider)
	assert.Equal(t, att.Failover.FailoverGroupID, dec.Failover.FailoverGroupID, "attempt and terminal share a group")
	assert.Equal(t, []string{att.ID}, dec.Failover.FailedAttemptIDs)
	assert.True(t, store.VerifyRecord(dec))

	finding, err := store.VerifyFailoverChain(context.Background(), "corr-fo-1")
	require.NoError(t, err)
	require.NotNil(t, finding)
	assert.Equal(t, evidence.FailoverVerdictValidFallback, finding.Verdict, "details: %v", finding.Details)
}

func TestRunFailover_PermanentErrorDoesNotFailOver(t *testing.T) {
	primary := &flakyProvider{name: "openai", jurisdiction: "US", failWith: &llm.ProviderError{Code: "auth_failed", Provider: "openai", Message: "bad key"}}
	backup := &flakyProvider{name: "ollama", jurisdiction: "LOCAL"}
	routing := &policy.ModelRoutingConfig{
		Tier1: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3:70b"}},
	}
	r, store := newFailoverTestRunner(t, map[string]llm.Provider{"openai": primary, "ollama": backup}, routing)

	req := &RunRequest{TenantID: "t1", AgentName: "a1", InvocationType: "manual"}
	fo := r.newRunFailover(context.Background(), req, "corr-fo-2", 1, nil, "", nil)

	_, _, _, err := fo.generate(context.Background(),
		primary, "gpt-4o", &llm.Request{Model: "gpt-4o"})
	require.Error(t, err)
	assert.Equal(t, 0, backup.calls, "permanent errors must not trigger failover")

	records, err := store.ListByCorrelationID(context.Background(), "corr-fo-2")
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestRunFailover_AllCandidatesFail_FailsClosed(t *testing.T) {
	primary := &flakyProvider{name: "openai", jurisdiction: "US", failWith: &llm.ProviderError{Code: "server_error", Provider: "openai"}}
	backup := &flakyProvider{name: "ollama", jurisdiction: "LOCAL", failWith: &llm.ProviderError{Code: "rate_limit", Provider: "ollama"}}
	routing := &policy.ModelRoutingConfig{
		Tier1: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3:70b"}},
	}
	r, store := newFailoverTestRunner(t, map[string]llm.Provider{"openai": primary, "ollama": backup}, routing)

	req := &RunRequest{TenantID: "t1", AgentName: "a1", InvocationType: "manual"}
	fo := r.newRunFailover(context.Background(), req, "corr-fo-3", 1, nil, "", nil)

	_, _, _, err := fo.generate(context.Background(), primary, "gpt-4o", &llm.Request{Model: "gpt-4o"})
	require.Error(t, err)
	assert.Equal(t, 1, backup.calls)

	attempts, terminals := runFailoverRecords(t, store, "corr-fo-3")
	assert.Len(t, attempts, 2, "both failed attempts evidenced")
	require.Len(t, terminals, 1)
	assert.Equal(t, evidence.FailoverRoleFailClosed, terminals[0].Failover.Role)
	assert.Equal(t, evidence.FailureReasonNoValidFallbackCandidate, terminals[0].FailureReason)
	assert.Len(t, terminals[0].Failover.FailedAttemptIDs, 2)

	finding, err := store.VerifyFailoverChain(context.Background(), "corr-fo-3")
	require.NoError(t, err)
	assert.Equal(t, evidence.FailoverVerdictValidFailClosed, finding.Verdict, "details: %v", finding.Details)
}

// Once failover is engaged, a permanently failing fallback candidate is
// evidenced (with a permanent failure reason) and the chain keeps walking.
func TestRunFailover_ChainContinuesPastPermanentFallback(t *testing.T) {
	primary := &flakyProvider{name: "openai", jurisdiction: "US", failWith: &llm.ProviderError{Code: "server_error", Provider: "openai"}}
	badBackup := &flakyProvider{name: "anthropic", jurisdiction: "US", failWith: &llm.ProviderError{Code: "auth_failed", Provider: "anthropic"}}
	goodBackup := &flakyProvider{name: "ollama", jurisdiction: "LOCAL"}
	routing := &policy.ModelRoutingConfig{
		Tier1: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"claude-sonnet-4-20250514", "llama3:70b"}},
	}
	r, store := newFailoverTestRunner(t, map[string]llm.Provider{"openai": primary, "anthropic": badBackup, "ollama": goodBackup}, routing)

	req := &RunRequest{TenantID: "t1", AgentName: "a1", InvocationType: "manual"}
	fo := r.newRunFailover(context.Background(), req, "corr-fo-5", 1, nil, "", nil)

	resp, usedProvider, usedModel, err := fo.generate(context.Background(), primary, "gpt-4o", &llm.Request{Model: "gpt-4o"})
	require.NoError(t, err)
	assert.Equal(t, "ok from ollama", resp.Content)
	assert.Equal(t, "ollama", usedProvider.Name())
	assert.Equal(t, "llama3:70b", usedModel)
	assert.Equal(t, 1, badBackup.calls)
	assert.Equal(t, 1, goodBackup.calls)

	attempts, terminals := runFailoverRecords(t, store, "corr-fo-5")
	require.Len(t, attempts, 2)
	assert.Equal(t, evidence.FailureReasonProviderTransient, attempts[0].FailureReason)
	assert.Equal(t, "auth_error", attempts[1].Failover.ErrorClass)
	assert.Equal(t, evidence.FailureReasonProviderPermanent, attempts[1].FailureReason,
		"failure_reason must not contradict the error class")
	require.Len(t, terminals, 1)
	assert.Equal(t, "ollama", terminals[0].Failover.Provider)
	assert.Len(t, terminals[0].Failover.FailedAttemptIDs, 2)
}

func TestRunFailover_ComplianceModeExcludesSovereigntyRejectedCandidates(t *testing.T) {
	primary := &flakyProvider{name: "ollama", jurisdiction: "LOCAL", failWith: &llm.ProviderError{Code: "server_error", Provider: "ollama"}}
	usBackup := &flakyProvider{name: "openai", jurisdiction: "US"}
	routing := &policy.ModelRoutingConfig{
		Tier2: &policy.TierConfig{Primary: "llama3:70b", FallbackChain: []string{"gpt-4o"}},
	}
	r, store := newFailoverTestRunner(t, map[string]llm.Provider{"ollama": primary, "openai": usBackup}, routing)

	req := &RunRequest{TenantID: "t1", AgentName: "a1", InvocationType: "manual"}
	fo := r.newRunFailover(context.Background(), req, "corr-fo-4", 2, euOnlyRoutingEvaluator{}, "eu_strict", nil)

	_, _, _, err := fo.generate(context.Background(), primary, "llama3:70b", &llm.Request{Model: "llama3:70b"})
	require.Error(t, err)
	assert.Equal(t, 0, usBackup.calls, "sovereignty-rejected candidate must never be dispatched")

	attempts, terminals := runFailoverRecords(t, store, "corr-fo-4")
	require.Len(t, attempts, 1)
	require.Len(t, terminals, 1)
	assert.Equal(t, evidence.FailoverRoleFailClosed, terminals[0].Failover.Role)
	assert.NotEmpty(t, terminals[0].Failover.SkippedCandidates)

	finding, err := store.VerifyFailoverChain(context.Background(), "corr-fo-4")
	require.NoError(t, err)
	require.NotNil(t, finding)
	assert.Equal(t, evidence.FailoverVerdictValidFailClosed, finding.Verdict, "details: %v", finding.Details)
}

// An agentic run makes many LLM calls under one correlation ID: every call
// gets its own failover engagement with a fresh chain walk and its own group,
// and each group verifies independently.
func TestRunFailover_MultipleEngagementsPerRun_GetSeparateGroups(t *testing.T) {
	primary := &flakyProvider{name: "openai", jurisdiction: "US", failWith: &llm.ProviderError{Code: "server_error", Provider: "openai"}}
	backup := &flakyProvider{name: "ollama", jurisdiction: "LOCAL"}
	routing := &policy.ModelRoutingConfig{
		Tier1: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3:70b"}},
	}
	r, store := newFailoverTestRunner(t, map[string]llm.Provider{"openai": primary, "ollama": backup}, routing)

	req := &RunRequest{TenantID: "t1", AgentName: "a1", InvocationType: "manual"}
	fo := r.newRunFailover(context.Background(), req, "corr-fo-6", 1, nil, "", nil)

	// Call 1: primary fails, fallback succeeds.
	_, p1, m1, err := fo.generate(context.Background(), primary, "gpt-4o", &llm.Request{Model: "gpt-4o"})
	require.NoError(t, err)

	// Call 2 (same run, later loop iteration): the now-current provider
	// fails too — the engagement must walk a FRESH chain copy, not the
	// consumed remainder of call 1.
	backup.failWith = &llm.ProviderError{Code: "server_error", Provider: "ollama"}
	_, _, _, err = fo.generate(context.Background(), p1, m1, &llm.Request{Model: m1})
	require.Error(t, err, "no other candidate remains for call 2")

	attempts, terminals := runFailoverRecords(t, store, "corr-fo-6")
	require.Len(t, terminals, 2, "each engagement gets its own terminal record")
	assert.Equal(t, evidence.FailoverRoleFallbackDecision, terminals[0].Failover.Role)
	assert.Equal(t, evidence.FailoverRoleFailClosed, terminals[1].Failover.Role,
		"call 2's outcome must not inherit call 1's successful decision")
	assert.NotEqual(t, terminals[0].Failover.FailoverGroupID, terminals[1].Failover.FailoverGroupID,
		"engagements must not share a failover group")
	require.Len(t, attempts, 2)

	finding, err := store.VerifyFailoverChain(context.Background(), "corr-fo-6")
	require.NoError(t, err)
	require.NotNil(t, finding)
	assert.True(t, finding.OK(), "both groups must verify independently: %v", finding.Details)
}

// euOnlyRoutingEvaluator rejects non-EU/LOCAL jurisdictions (eu_strict stub).
type euOnlyRoutingEvaluator struct{}

func (euOnlyRoutingEvaluator) EvaluateRouting(_ context.Context, in *policy.RoutingInput) (*policy.Decision, error) {
	if in.ProviderJurisdiction == "EU" || in.ProviderJurisdiction == "LOCAL" {
		return &policy.Decision{Allowed: true}, nil
	}
	return &policy.Decision{Allowed: false, Reasons: []string{"sovereignty: not allowed"}}, nil
}

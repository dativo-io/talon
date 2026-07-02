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

// flakyProvider fails Generate with the given error until failCount calls
// have happened, then succeeds.
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

	require.NotNil(t, fo.decision)
	assert.Equal(t, evidence.FailoverRoleFallbackDecision, fo.decision.Role)
	assert.Equal(t, "ollama", fo.decision.Provider)
	assert.Len(t, fo.decision.FailedAttemptIDs, 1)

	records, err := store.ListByCorrelationID(context.Background(), "corr-fo-1")
	require.NoError(t, err)
	require.Len(t, records, 1, "one failed-attempt record")
	att := records[0]
	assert.Equal(t, "llm_failover_attempt", att.InvocationType)
	assert.Equal(t, evidence.FailoverRoleFailedAttempt, att.Failover.Role)
	assert.Equal(t, "openai", att.Failover.Provider)
	assert.Equal(t, "upstream_5xx", att.Failover.ErrorClass)
	assert.Equal(t, evidence.FailureReasonProviderTransient, att.FailureReason)
	assert.True(t, store.VerifyRecord(att))
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
	assert.Nil(t, fo.decision)

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

	require.NotNil(t, fo.decision)
	assert.Equal(t, evidence.FailoverRoleFailClosed, fo.decision.Role)
	assert.Len(t, fo.decision.FailedAttemptIDs, 2)

	records, err := store.ListByCorrelationID(context.Background(), "corr-fo-3")
	require.NoError(t, err)
	assert.Len(t, records, 2, "both failed attempts evidenced")
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

	require.NotNil(t, fo.decision)
	assert.Equal(t, evidence.FailoverRoleFallbackDecision, fo.decision.Role)
	assert.Equal(t, "ollama", fo.decision.Provider)
	assert.Len(t, fo.decision.FailedAttemptIDs, 2)

	records, err := store.ListByCorrelationID(context.Background(), "corr-fo-5")
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, evidence.FailureReasonProviderTransient, records[0].FailureReason)
	assert.Equal(t, "auth_error", records[1].Failover.ErrorClass)
	assert.Equal(t, evidence.FailureReasonProviderPermanent, records[1].FailureReason,
		"failure_reason must not contradict the error class")
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

	require.NotNil(t, fo.decision)
	assert.Equal(t, evidence.FailoverRoleFailClosed, fo.decision.Role)

	records, err := store.ListByCorrelationID(context.Background(), "corr-fo-4")
	require.NoError(t, err)
	require.Len(t, records, 1)
	finding := evidence.VerifyFailoverRecords("corr-fo-4", append(records, failClosedRunRecord("corr-fo-4", fo.decision)), nil)
	require.NotNil(t, finding)
	assert.Equal(t, evidence.FailoverVerdictValidFailClosed, finding.Verdict, "details: %v", finding.Details)
}

// failClosedRunRecord simulates the run's final evidence record carrying the
// fail-closed decision (the real record is written by executeLLMPipeline).
func failClosedRunRecord(correlationID string, fc *evidence.FailoverContext) *evidence.Evidence {
	return &evidence.Evidence{ID: "req_final", CorrelationID: correlationID, Failover: fc}
}

// euOnlyRoutingEvaluator rejects non-EU/LOCAL jurisdictions (eu_strict stub).
type euOnlyRoutingEvaluator struct{}

func (euOnlyRoutingEvaluator) EvaluateRouting(_ context.Context, in *policy.RoutingInput) (*policy.Decision, error) {
	if in.ProviderJurisdiction == "EU" || in.ProviderJurisdiction == "LOCAL" {
		return &policy.Decision{Allowed: true}, nil
	}
	return &policy.Decision{Allowed: false, Reasons: []string{"sovereignty: not allowed"}}, nil
}

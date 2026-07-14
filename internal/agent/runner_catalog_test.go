package agent

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/testutil"
)

// writeCatalogTestAgent writes one fleet agent whose tier-0 primary model
// selects a DISTINCT provider — the observable proof that a run executed
// under its own agent's routing (#267).
func writeCatalogTestAgent(t *testing.T, agentsDir, name, tenant, primaryModel string) {
	t.Helper()
	d := filepath.Join(agentsDir, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
	if tenant != "" {
		y += "  tenant_id: " + tenant + "\n"
	}
	y += `policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  model_routing:
    tier_0:
      primary: "` + primaryModel + `"
    tier_1:
      primary: "` + primaryModel + `"
    tier_2:
      primary: "` + primaryModel + `"
`
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
}

func catalogTestSnapshot(t *testing.T, agentsDir string, providers map[string]llm.Provider) *agentcatalog.RuntimeSnapshot {
	t.Helper()
	ctx := context.Background()
	scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err)
	bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{Providers: providers})
	require.NoError(t, err)
	return agentcatalog.NewRuntimeSnapshot(scan, bundles, nil, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
}

func newCatalogTestRunner(t *testing.T, holder *agentcatalog.RuntimeHolder) (*Runner, *evidence.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewRunner(RunnerConfig{
		Catalog:  holder,
		Evidence: store,
	}), store
}

// TestRun_CatalogResolvesPerAgentBundle (#267): each agent's run executes
// under its OWN compiled bundle — agent B's request never touches agent A's
// router — and identity/tenant resolution follows the catalog.
func TestRun_CatalogResolvesPerAgentBundle(t *testing.T) {
	ctx := context.Background()
	agentsDir := t.TempDir()
	writeCatalogTestAgent(t, agentsDir, "support", "acme", "gpt-4o")  // routes to openai
	writeCatalogTestAgent(t, agentsDir, "coding", "acme", "llama3.2") // routes to ollama
	openai := &flakyProvider{name: "openai", jurisdiction: "US"}
	ollama := &flakyProvider{name: "ollama", jurisdiction: "LOCAL"}
	holder := agentcatalog.NewRuntimeHolder(catalogTestSnapshot(t, agentsDir, map[string]llm.Provider{
		"openai": openai, "ollama": ollama,
	}))
	r, store := newCatalogTestRunner(t, holder)

	respA, err := r.Run(ctx, &RunRequest{AgentName: "support", Prompt: "hello", InvocationType: "manual"})
	require.NoError(t, err)
	assert.Equal(t, "ok from openai", respA.Response, "support runs under ITS routing")

	respB, err := r.Run(ctx, &RunRequest{AgentName: "coding", Prompt: "hello", InvocationType: "manual"})
	require.NoError(t, err)
	assert.Equal(t, "ok from ollama", respB.Response, "coding runs under ITS routing — never agent A's router")
	assert.Equal(t, 1, openai.calls, "agent B's run must not touch agent A's provider")

	// Tenant follows the agent file; evidence attributes per agent.
	records, err := store.List(ctx, "acme", "coding", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.NotEmpty(t, records)

	// Unknown and ambiguous names fail loudly BEFORE any lifecycle state.
	_, err = r.Run(ctx, &RunRequest{AgentName: "nope", Prompt: "x", InvocationType: "manual"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "coding", "the error lists discovered agents")

	_, err = r.Run(ctx, &RunRequest{AgentName: "default", Prompt: "x", InvocationType: "manual"})
	require.Error(t, err, "the default sentinel is ambiguous with two agents")
	assert.Contains(t, err.Error(), "ambiguous")

	// A declared tenant is authoritative: an explicit different tenant errors.
	_, err = r.Run(ctx, &RunRequest{AgentName: "support", TenantID: "globex", Prompt: "x", InvocationType: "manual"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant mismatch")
}

// TestRun_DisabledAgentRefused (#268): enabled: false denies NEW native work
// — direct runs AND trigger dispatch — before any lifecycle state, leaving
// only signed early-termination evidence; the enabled sibling keeps running.
func TestRun_DisabledAgentRefused(t *testing.T) {
	ctx := context.Background()
	agentsDir := t.TempDir()
	writeCatalogTestAgent(t, agentsDir, "running", "acme", "gpt-4o")
	// The stopped agent: same shape plus enabled: false.
	d := filepath.Join(agentsDir, "stopped")
	require.NoError(t, os.MkdirAll(d, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(`agent:
  name: stopped
  version: "1.0.0"
  tenant_id: acme
  enabled: false
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  model_routing:
    tier_0:
      primary: "gpt-4o"
`), 0o600))

	openai := &flakyProvider{name: "openai", jurisdiction: "US"}
	holder := agentcatalog.NewRuntimeHolder(catalogTestSnapshot(t, agentsDir, map[string]llm.Provider{"openai": openai}))
	r, store := newCatalogTestRunner(t, holder)

	// Direct run refused with the kill-switch reason; no provider call.
	_, err := r.Run(ctx, &RunRequest{AgentName: "stopped", Prompt: "x", InvocationType: "manual"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "agent_disabled")
	assert.Contains(t, err.Error(), "talon agents enable stopped")
	assert.Equal(t, 0, openai.calls, "a disabled agent never reaches a provider")

	// Trigger dispatch refused the same way.
	require.Error(t, r.RunFromTrigger(ctx, "stopped", "scheduled work", "scheduled"))
	assert.Equal(t, 0, openai.calls)

	// The refusals left signed early-termination evidence, attributed — and
	// classified as a deliberate BLOCK, never an internal failure (#268
	// review), so the health projection reads it as a stop.
	records, err := store.List(ctx, "acme", "stopped", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Contains(t, records[0].PolicyDecision.Reasons[0], "agent_disabled")
	assert.Equal(t, "agent_disabled", records[0].PolicyDecision.Action, "action is agent_disabled, not early_termination")
	assert.Equal(t, "blocked", records[0].Status, "status is blocked, not failed")
	assert.Equal(t, "agent_disabled", records[0].FailureReason, "failure_reason is agent_disabled, not internal_error")

	// The enabled sibling runs untouched.
	resp, err := r.Run(ctx, &RunRequest{AgentName: "running", Prompt: "hello", InvocationType: "manual"})
	require.NoError(t, err)
	assert.Equal(t, "ok from openai", resp.Response)
}

// blockingProvider holds Generate until released — the seam for proving a
// run finishes on the generation it started with (#267).
type blockingProvider struct {
	name    string
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (p *blockingProvider) Name() string { return p.name }
func (p *blockingProvider) Metadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{ID: p.name, DisplayName: p.name, Jurisdiction: "US"}
}

func (p *blockingProvider) Generate(_ context.Context, req *llm.Request) (*llm.Response, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	<-p.release
	return &llm.Response{Content: "ok from " + p.name, Model: req.Model, InputTokens: 1, OutputTokens: 1}, nil
}

func (p *blockingProvider) Stream(_ context.Context, _ *llm.Request, ch chan<- llm.StreamChunk) error {
	close(ch)
	return nil
}
func (p *blockingProvider) EstimateCost(string, int, int) float64    { return 0.0001 }
func (p *blockingProvider) ValidateConfig() error                    { return nil }
func (p *blockingProvider) HealthCheck(context.Context) error        { return nil }
func (p *blockingProvider) WithHTTPClient(*http.Client) llm.Provider { return p }

// TestRun_GenerationConsistency (#267): a run captures ONE snapshot at entry
// and completes under it — activating a new generation mid-run changes
// nothing for the in-flight run, and the NEXT run resolves the new one.
func TestRun_GenerationConsistency(t *testing.T) {
	ctx := context.Background()
	agentsDir := t.TempDir()
	writeCatalogTestAgent(t, agentsDir, "support", "acme", "gpt-4o")
	genABlocking := &blockingProvider{name: "openai", release: make(chan struct{})}
	holder := agentcatalog.NewRuntimeHolder(catalogTestSnapshot(t, agentsDir, map[string]llm.Provider{
		"openai": genABlocking,
	}))
	r, _ := newCatalogTestRunner(t, holder)

	type result struct {
		resp *RunResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := r.Run(ctx, &RunRequest{AgentName: "support", Prompt: "hello", InvocationType: "manual"})
		done <- result{resp, err}
	}()

	// Wait until the in-flight run reached generation A's provider.
	require.Eventually(t, func() bool {
		genABlocking.mu.Lock()
		defer genABlocking.mu.Unlock()
		return genABlocking.calls == 1
	}, 5*time.Second, 10*time.Millisecond)

	// Activate generation B: same agent name, DIFFERENT provider wiring.
	genBProvider := &flakyProvider{name: "openai", jurisdiction: "US"}
	holder.Swap(catalogTestSnapshot(t, agentsDir, map[string]llm.Provider{"openai": genBProvider}))

	// Release generation A — the in-flight run completes on ITS bundle.
	close(genABlocking.release)
	res := <-done
	require.NoError(t, res.err)
	assert.Equal(t, "ok from openai", res.resp.Response)
	assert.Equal(t, 0, genBProvider.calls, "the in-flight run must never touch generation B")

	// The NEXT run resolves generation B.
	_, err := r.Run(ctx, &RunRequest{AgentName: "support", Prompt: "hello again", InvocationType: "manual"})
	require.NoError(t, err)
	assert.Equal(t, 1, genBProvider.calls, "a new run resolves the activated generation")
}

// TestRunFromTrigger_CatalogResolution (#267): trigger dispatch resolves the
// agent from the CURRENT generation by name — no pinned policy path — so a
// swap governs the next firing.
func TestRunFromTrigger_CatalogResolution(t *testing.T) {
	ctx := context.Background()
	agentsDir := t.TempDir()
	writeCatalogTestAgent(t, agentsDir, "support", "", "gpt-4o")
	writeCatalogTestAgent(t, agentsDir, "coding", "", "llama3.2")
	openai := &flakyProvider{name: "openai", jurisdiction: "US"}
	ollama := &flakyProvider{name: "ollama", jurisdiction: "LOCAL"}
	holder := agentcatalog.NewRuntimeHolder(catalogTestSnapshot(t, agentsDir, map[string]llm.Provider{
		"openai": openai, "ollama": ollama,
	}))
	r, store := newCatalogTestRunner(t, holder)

	require.NoError(t, r.RunFromTrigger(ctx, "coding", "scheduled work", "scheduled"))
	assert.Equal(t, 1, ollama.calls, "the trigger dispatched under the named agent's OWN routing")
	assert.Equal(t, 0, openai.calls)

	records, err := store.List(ctx, "default", "coding", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.NotEmpty(t, records, "trigger runs attribute to the dispatched agent")

	require.Error(t, r.RunFromTrigger(ctx, "removed-agent", "x", "scheduled"),
		"a trigger for an unknown agent fails loudly, never runs under another policy")
}

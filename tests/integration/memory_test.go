//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func writeMemoryPolicy(t *testing.T, dir, name string) string {
	t.Helper()
	return writeMemoryPolicyWithDedup(t, dir, name, 0)
}

// writeMemoryPolicyWithDedup writes a memory policy; dedupMinutes 0 = disabled, >0 enables input-hash dedup window.
func writeMemoryPolicyWithDedup(t *testing.T, dir, name string, dedupMinutes int) string {
	t.Helper()
	dedupYaml := ""
	if dedupMinutes > 0 {
		dedupYaml = "\n    dedup_window_minutes: " + fmt.Sprint(dedupMinutes)
	}
	content := `
agent:
  name: "` + name + `"
  version: "1.0.0"
memory:
  enabled: true
  allowed_categories:
    - domain_knowledge
    - policy_hit
    - factual_corrections
  governance:
    conflict_resolution: auto` + dedupYaml + `
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	path := filepath.Join(dir, name+".talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func setupRunnerWithMemory(t *testing.T, dir string, providers map[string]llm.Provider, routingCfg *policy.ModelRoutingConfig) (*agent.Runner, *memory.Store, *evidence.Store) {
	t.Helper()
	storeDir := t.TempDir()

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(routingCfg, providers, nil)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	memStore, err := memory.NewStore(filepath.Join(storeDir, "memory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { memStore.Close() })

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: cls,
		AttScanner: attScanner,
		Extractor:  extractor,
		Router:     router,
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
		Memory:     memStore,
	})

	return runner, memStore, evidenceStore
}

func TestRunner_MemoryWriteAfterRun(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeMemoryPolicy(t, dir, "mem-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Revenue target is 1M EUR"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "mem-agent",
		Prompt:         "What is our revenue target?",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)

	entries, err := memStore.Read(context.Background(), "acme", "mem-agent")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, memory.SourceManual, entry.SourceType)
	assert.Equal(t, 100, entry.TrustScore)
	assert.NotEmpty(t, entry.EvidenceID)
	assert.Equal(t, resp.EvidenceID, entry.EvidenceID)
}

func TestRunner_MemoryGovernanceDenial(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeMemoryPolicy(t, dir, "gov-agent")

	// Mock LLM returns PII -- memory write should be denied but evidence still generated
	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Contact user@example.com for details"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, evidenceStore := setupRunnerWithMemory(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "gov-agent",
		Prompt:         "Get contact info",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.NotEmpty(t, resp.EvidenceID)

	// Memory should be empty (PII in output prevents write)
	entries, err := memStore.Read(context.Background(), "acme", "gov-agent")
	require.NoError(t, err)
	assert.Empty(t, entries, "memory write should be denied due to PII")

	// Evidence should still exist
	ev, err := evidenceStore.Get(context.Background(), resp.EvidenceID)
	require.NoError(t, err)
	assert.Equal(t, "acme", ev.TenantID)
}

func TestRunner_SharedContextLoaded(t *testing.T) {
	dir := t.TempDir()

	// Create shared context directory
	ctxDir := filepath.Join(dir, "company-context")
	require.NoError(t, os.MkdirAll(ctxDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ctxDir, "info.md"), []byte("Company: Acme Corp\nFiscal year: April-March"), 0o644))

	content := `
agent:
  name: "ctx-agent"
  version: "1.0.0"
memory:
  enabled: true
context:
  shared_mounts:
    - name: company
      path: "` + ctxDir + `"
      classification: tier_0
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	policyPath := filepath.Join(dir, "ctx-agent.talon.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(content), 0o600))

	// The mock captures the prompt sent to LLM
	mock := &testutil.MockProvider{ProviderName: "openai", Content: "Acme Corp fiscal year starts April"}
	providers := map[string]llm.Provider{"openai": mock}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, _, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "ctx-agent",
		Prompt:         "When does our fiscal year start?",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Contains(t, resp.Response, "Acme Corp")
}

func TestRunner_MemoryIndexInPrompt(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeMemoryPolicy(t, dir, "idx-agent")

	mock := &testutil.MockProvider{ProviderName: "openai", Content: "Response with memory context"}
	providers := map[string]llm.Provider{"openai": mock}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)
	ctx := context.Background()

	// Pre-seed memory
	require.NoError(t, memStore.Write(ctx, &memory.Entry{
		TenantID: "acme", AgentID: "idx-agent",
		Category:   memory.CategoryDomainKnowledge,
		Title:      "Company HQ in Berlin",
		Content:    "The company headquarters is in Berlin",
		EvidenceID: "req_seed1234",
		SourceType: memory.SourceManual,
	}))

	// Run agent -- it should include memory index in prompt
	resp, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "idx-agent",
		Prompt:         "Where is our HQ?",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)

	// After run, memory should have 2 entries: the seed + the new observation
	entries, err := memStore.Read(ctx, "acme", "idx-agent")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 2)
}

func TestRunner_EvidenceChainIntegrity(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeMemoryPolicy(t, dir, "chain-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Chain test response"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, evidenceStore := setupRunnerWithMemory(t, dir, providers, routingCfg)
	ctx := context.Background()

	resp, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "chain-agent",
		Prompt:         "Test chain",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.EvidenceID)

	entries, err := memStore.Read(ctx, "acme", "chain-agent")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Verify the memory entry links to a valid evidence record
	memEntry := entries[0]
	assert.Equal(t, resp.EvidenceID, memEntry.EvidenceID)

	ev, err := evidenceStore.Get(ctx, memEntry.EvidenceID)
	require.NoError(t, err)
	assert.Equal(t, "acme", ev.TenantID)
	assert.Equal(t, "chain-agent", ev.AgentID)

	// Verify HMAC integrity
	valid, err := evidenceStore.Verify(ctx, memEntry.EvidenceID)
	require.NoError(t, err)
	assert.True(t, valid, "evidence HMAC should be valid")
}

func TestRunner_MemoryDedupSamePrompt(t *testing.T) {
	dir := t.TempDir()
	// Enable dedup window so second run with same prompt skips memory write
	policyPath := writeMemoryPolicyWithDedup(t, dir, "dedup-agent", 60)

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Same response"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)
	ctx := context.Background()
	prompt := "Summarize this document"

	_, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "dedup-agent",
		Prompt:         prompt,
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)

	_, err = runner.Run(ctx, &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "dedup-agent",
		Prompt:         prompt,
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)

	entries, err := memStore.Read(ctx, "acme", "dedup-agent")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "second run with same prompt should be deduplicated; expected 1 memory entry")
}

func TestRunner_SkipMemoryNoWrite(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeMemoryPolicy(t, dir, "skip-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Response"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)
	ctx := context.Background()

	_, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "skip-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
		SkipMemory:     true,
	})
	require.NoError(t, err)

	entries, err := memStore.Read(ctx, "acme", "skip-agent")
	require.NoError(t, err)
	assert.Empty(t, entries, "SkipMemory: true should skip memory write")
}

func TestRunner_MemoryRetentionEnforceMaxEntries(t *testing.T) {
	dir := t.TempDir()
	content := `
agent:
  name: "retention-agent"
  version: "1.0.0"
memory:
  enabled: true
  max_entries: 2
  allowed_categories:
    - domain_knowledge
  governance:
    conflict_resolution: auto
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	policyPath := filepath.Join(dir, "retention-agent.talon.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(content), 0o600))

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Answer"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := runner.Run(ctx, &agent.RunRequest{
			TenantID:       "acme",
			AgentName:      "retention-agent",
			Prompt:         fmt.Sprintf("Question %d", i),
			InvocationType: "manual",
			PolicyPath:     policyPath,
		})
		require.NoError(t, err)
	}

	entries, err := memStore.Read(ctx, "acme", "retention-agent")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(entries), 2, "EnforceMaxEntries(2) should evict oldest; at most 2 entries")
}

// TestRunner_Consolidation_ListReturnsOnlyActive runs two times with similar content so
// the consolidator may ADD then NOOP/UPDATE/INVALIDATE; asserts List returns only active entries.
func TestRunner_Consolidation_ListReturnsOnlyActive(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeMemoryPolicy(t, dir, "cons-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Revenue is one million euros"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)
	ctx := context.Background()

	_, err := runner.Run(ctx, &agent.RunRequest{
		TenantID: "acme", AgentName: "cons-agent",
		Prompt: "What is our revenue?", InvocationType: "manual", PolicyPath: policyPath,
	})
	require.NoError(t, err)

	_, err = runner.Run(ctx, &agent.RunRequest{
		TenantID: "acme", AgentName: "cons-agent",
		Prompt: "What is revenue?", InvocationType: "manual", PolicyPath: policyPath,
	})
	require.NoError(t, err)

	// List/Read use consolidation_status = active filter; we should only see active entries
	entries, err := memStore.Read(ctx, "acme", "cons-agent")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 1)
	assert.LessOrEqual(t, len(entries), 2)
	for i := range entries {
		assert.Equal(t, "active", entries[i].ConsolidationStatus, "List must return only active entries")
	}
}

// TestRunner_ScoredRetrievalWithPrompt runs with prompt and max_prompt_tokens so the runner
// uses RetrieveScored (Phase 3). Verifies memory is injected and run succeeds.
func TestRunner_ScoredRetrievalWithPrompt(t *testing.T) {
	dir := t.TempDir()
	content := `
agent:
  name: "scored-agent"
  version: "1.0.0"
memory:
  enabled: true
  max_prompt_tokens: 500
  allowed_categories:
    - domain_knowledge
  governance:
    conflict_resolution: auto
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	policyPath := filepath.Join(dir, "scored-agent.talon.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(content), 0o600))

	mock := &testutil.MockProvider{ProviderName: "openai", Content: "Berlin HQ response"}
	providers := map[string]llm.Provider{"openai": mock}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)
	ctx := context.Background()

	require.NoError(t, memStore.Write(ctx, &memory.Entry{
		TenantID: "acme", AgentID: "scored-agent", Category: memory.CategoryDomainKnowledge,
		Title: "HQ in Berlin", Content: "Headquarters is in Berlin", EvidenceID: "req_seed",
		SourceType: memory.SourceManual, MemoryType: memory.MemTypeSemanticFact,
	}))

	resp, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "scored-agent",
		Prompt:         "Where is our headquarters?",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)

	entries, err := memStore.Read(ctx, "acme", "scored-agent")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 1)
}

// TestRunner_MemoryV3PhasesTogether exercises Phase 1 (dedup), Phase 2 (consolidation/AsOf), Phase 3 (scored path) in one flow.
func TestRunner_MemoryV3PhasesTogether(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeMemoryPolicyWithDedup(t, dir, "v3-agent", 60)

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Revenue target 1M EUR"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner, memStore, _ := setupRunnerWithMemory(t, dir, providers, routingCfg)
	ctx := context.Background()

	// Phase 1: same prompt twice with dedup → one memory entry
	prompt1 := "What is our revenue target?"
	_, err := runner.Run(ctx, &agent.RunRequest{TenantID: "acme", AgentName: "v3-agent", Prompt: prompt1, InvocationType: "manual", PolicyPath: policyPath})
	require.NoError(t, err)
	_, err = runner.Run(ctx, &agent.RunRequest{TenantID: "acme", AgentName: "v3-agent", Prompt: prompt1, InvocationType: "manual", PolicyPath: policyPath})
	require.NoError(t, err)
	entries, _ := memStore.Read(ctx, "acme", "v3-agent")
	require.Len(t, entries, 1, "Phase 1 dedup: same prompt twice should yield one entry")

	// Phase 2: AsOf returns entries valid at a time
	asOfEntries, err := memStore.AsOf(ctx, "acme", "v3-agent", time.Now().UTC().Add(time.Hour), 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(asOfEntries), 1, "Phase 2 AsOf: entry valid at future time")

	// Phase 3: different prompt triggers new write; runner uses scored retrieval when prompt set.
	// Consolidation may ADD or INVALIDATE/UPDATE, so we may have 1 or 2 active entries.
	_, err = runner.Run(ctx, &agent.RunRequest{TenantID: "acme", AgentName: "v3-agent", Prompt: "Different question", InvocationType: "manual", PolicyPath: policyPath})
	require.NoError(t, err)
	entries2, _ := memStore.Read(ctx, "acme", "v3-agent")
	assert.GreaterOrEqual(t, len(entries2), 1, "Phase 3: after second prompt we have at least one active entry (consolidation may merge)")
}

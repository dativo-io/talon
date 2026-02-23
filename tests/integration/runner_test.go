//go:build integration

package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// recordingHook captures every invocation for test assertions.
type recordingHook struct {
	point   agent.HookPoint
	mu      sync.Mutex
	calls   []recordedCall
	abortAt int // abort after N calls (-1 = never)
}

type recordedCall struct {
	Stage   agent.HookPoint
	Payload json.RawMessage
}

func newRecordingHook(point agent.HookPoint) *recordingHook {
	return &recordingHook{point: point, abortAt: -1}
}

func (h *recordingHook) Point() agent.HookPoint { return h.point }
func (h *recordingHook) Execute(_ context.Context, data *agent.HookData) (*agent.HookResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, recordedCall{Stage: data.Stage, Payload: data.Payload})
	if h.abortAt >= 0 && len(h.calls) > h.abortAt {
		return &agent.HookResult{Continue: false}, nil
	}
	return &agent.HookResult{Continue: true}, nil
}

func (h *recordingHook) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

func (h *recordingHook) lastPayload() map[string]interface{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.calls) == 0 {
		return nil
	}
	var m map[string]interface{}
	_ = json.Unmarshal(h.calls[len(h.calls)-1].Payload, &m)
	return m
}

func TestRunner_FullPipeline_Success(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "test-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Hello from mock LLM!"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "test-agent",
		Prompt:         "What is Go?",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Equal(t, "Hello from mock LLM!", resp.Response)
	assert.NotEmpty(t, resp.EvidenceID)
	assert.Greater(t, resp.DurationMS, int64(0))
	assert.InDelta(t, 0.001, resp.Cost, 0.01)
}

func TestRunner_DryRun(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "test-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "should not be called"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "test-agent",
		Prompt:         "Test dry run",
		InvocationType: "manual",
		DryRun:         true,
		PolicyPath:     policyPath,
	})

	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Empty(t, resp.Response, "dry run should not produce LLM output")
	assert.Empty(t, resp.EvidenceID)
}

func TestRunner_PolicyDeny(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteStrictPolicy(t, dir, "strict-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "should not be called"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "strict-agent",
		Prompt:         "Test policy deny",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	require.NoError(t, err)
	assert.False(t, resp.PolicyAllow)
	assert.NotEmpty(t, resp.DenyReason)
}

func TestRunner_WithAttachments(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "attach-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Processed attachment"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "attach-agent",
		Prompt:         "Summarize this document",
		InvocationType: "manual",
		PolicyPath:     policyPath,
		Attachments: []agent.Attachment{
			{Filename: "readme.txt", Content: []byte("This is a safe text document.")},
		},
	})

	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Equal(t, "Processed attachment", resp.Response)
}

func TestRunner_LLMError(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "err-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{
			ProviderName: "openai",
			Err:          assert.AnError,
		},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	_, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "err-agent",
		Prompt:         "Test LLM error",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "calling LLM")
}

func TestRunner_DefaultPolicyPathUsesPolicyDir(t *testing.T) {
	dir := t.TempDir()
	WriteTestPolicy(t, dir, "default-path-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "policy from policyDir"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "default-path-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Equal(t, "policy from policyDir", resp.Response)
}

func TestRunner_MissingPolicy(t *testing.T) {
	dir := t.TempDir()

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "x"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	_, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "missing-agent",
		Prompt:         "Test missing policy",
		InvocationType: "manual",
		PolicyPath:     filepath.Join(dir, "nonexistent.talon.yaml"),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading policy")
}

func TestRunner_PIIInInput(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "pii-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Processed PII input"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "pii-agent",
		Prompt:         "My IBAN is DE89370400440532013000 and email is user@example.com",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.NotEmpty(t, resp.EvidenceID)
}

func TestRunner_TenantKeyFromVault(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "vault-agent")

	operatorProvider := &testutil.MockProvider{ProviderName: "openai", Content: "operator fallback response"}
	providers := map[string]llm.Provider{
		"openai": operatorProvider,
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	err = secretsStore.Set(context.Background(), "openai-api-key", []byte("sk-tenant-acme-key"), secrets.ACL{})
	require.NoError(t, err)

	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers, nil),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "vault-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	auditLog, err2 := secretsStore.AuditLog(context.Background(), "acme", "openai-api-key", 10)
	require.NoError(t, err2)

	found := false
	for _, entry := range auditLog {
		if entry.TenantID == "acme" && entry.SecretName == "openai-api-key" && entry.Allowed {
			found = true
			break
		}
	}
	assert.True(t, found, "vault should have an audit record for acme's openai-api-key access")

	_ = resp
	_ = err
}

func TestRunner_VaultKeyACLDenied_FallsBackToOperator(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "acl-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "operator fallback"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	err = secretsStore.Set(context.Background(), "openai-api-key", []byte("sk-restricted"),
		secrets.ACL{Agents: []string{"sales-bot"}})
	require.NoError(t, err)

	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers, nil),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "acl-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Equal(t, "operator fallback", resp.Response)
}

func TestRunner_NoRouteAvailable(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "noroute-agent")

	providers := map[string]llm.Provider{}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	_, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "noroute-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "routing LLM")
}

func TestRunner_PlanReviewGate_ReturnsPlanPending(t *testing.T) {
	dir := t.TempDir()
	policyContent := `
agent:
  name: "review-agent"
  version: "1.0.0"
compliance:
  human_oversight: "always"
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
	policyPath := filepath.Join(dir, "review-agent.talon.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(policyContent), 0o644))

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	planStore, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "should not be called"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}
	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:    dir,
		Classifier:   classifier.MustNewScanner(),
		AttScanner:   attachment.MustNewScanner(),
		Extractor:    attachment.NewExtractor(10),
		Router:       llm.NewRouter(routingCfg, providers, nil),
		Secrets:      secretsStore,
		Evidence:     evidenceStore,
		PlanReview:   planStore,
		ToolRegistry: tools.NewRegistry(),
	})

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "review-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)

	assert.True(t, resp.PolicyAllow)
	assert.NotEmpty(t, resp.PlanPending, "PlanPending must be set when plan review gate triggers")
	assert.Empty(t, resp.Response, "LLM must not be called when gated")
}

func TestRunner_HooksFireAtPipelineStages(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "hooks-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "hooked response"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	postPolicy := newRecordingHook(agent.HookPostPolicy)
	preLLM := newRecordingHook(agent.HookPreLLM)
	postLLM := newRecordingHook(agent.HookPostLLM)
	postEvidence := newRecordingHook(agent.HookPostEvidence)

	registry := agent.NewHookRegistry()
	registry.Register(postPolicy)
	registry.Register(preLLM)
	registry.Register(postLLM)
	registry.Register(postEvidence)

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers, nil),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
		Hooks:      registry,
	})

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "hooks-agent",
		Prompt:         "test hooks",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.Equal(t, "hooked response", resp.Response)

	assert.Equal(t, 1, postPolicy.callCount(), "HookPostPolicy should fire once")
	pp := postPolicy.lastPayload()
	assert.Equal(t, "allow", pp["decision"])
	assert.NotNil(t, pp["tier"])

	assert.Equal(t, 1, preLLM.callCount(), "HookPreLLM should fire once")
	pl := preLLM.lastPayload()
	assert.NotEmpty(t, pl["model"])

	assert.Equal(t, 1, postLLM.callCount(), "HookPostLLM should fire once")
	plPost := postLLM.lastPayload()
	assert.NotEmpty(t, plPost["model"])
	assert.NotNil(t, plPost["input_tokens"])
	assert.NotNil(t, plPost["output_tokens"])

	assert.Equal(t, 1, postEvidence.callCount(), "HookPostEvidence should fire once")
	pe := postEvidence.lastPayload()
	assert.NotEmpty(t, pe["evidence_id"])
	assert.NotNil(t, pe["cost"])
}

func TestRunner_HookAbortBlocksPipeline(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "abort-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "should not reach LLM"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	abortHook := &recordingHook{point: agent.HookPreLLM, abortAt: 0}

	registry := agent.NewHookRegistry()
	registry.Register(abortHook)

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers, nil),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
		Hooks:      registry,
	})

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "abort-agent",
		Prompt:         "test abort",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.False(t, resp.PolicyAllow)
	assert.Contains(t, resp.DenyReason, "blocked by pre_llm hook")
	assert.Empty(t, resp.Response, "LLM should not be called when hook aborts")
}

func TestRunner_NilHooksDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "nohooks-agent")

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "no hooks response"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := SetupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "nohooks-agent",
		Prompt:         "test nil hooks",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.Equal(t, "no hooks response", resp.Response)
	assert.True(t, resp.PolicyAllow)
}

// TestCostDegradation_EndToEnd seeds evidence so daily cost exceeds the degradation
// threshold, then runs the pipeline and asserts the run used the fallback model and
// evidence records degraded=true and original_model.
func TestCostDegradation_EndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Policy: daily=10 EUR, degradation at 50%, fallback gpt-4o-mini; tier0 primary gpt-4
	policyContent := `
agent:
  name: deg-agent
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
    daily: 10.0
    monthly: 500.0
    degradation:
      enabled: true
      threshold_percent: 50.0
      fallback_model: gpt-4o-mini
  model_routing:
    tier_0:
      primary: gpt-4
    tier_1:
      primary: gpt-4
    tier_2:
      primary: gpt-4
`
	policyPath := filepath.Join(dir, "deg-agent.talon.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(policyContent), 0o644))

	pol, err := policy.LoadPolicy(ctx, policyPath, false, dir)
	require.NoError(t, err)
	costLimits := pol.Policies.CostLimits
	require.NotNil(t, costLimits)
	require.NotNil(t, costLimits.Degradation)
	require.True(t, costLimits.Degradation.Enabled)

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	// Seed today's cost so 6/10 = 60% >= 50% threshold
	gen := evidence.NewGenerator(evidenceStore)
	_, err = gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  "seed-1",
		TenantID:       "acme",
		AgentID:        "deg-agent",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Cost:           6.0,
		InputPrompt:    "seed",
		OutputResponse: "seed",
	})
	require.NoError(t, err)

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "degraded response"},
	}
	router := llm.NewRouter(pol.Policies.ModelRouting, providers, costLimits)

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     router,
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	resp, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "deg-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	require.NotEmpty(t, resp.EvidenceID, "run should produce evidence")

	ev, err := evidenceStore.Get(ctx, resp.EvidenceID)
	require.NoError(t, err)
	assert.True(t, ev.Execution.Degraded, "evidence should record cost degradation")
	assert.Equal(t, "gpt-4", ev.Execution.OriginalModel, "original model should be primary")
	assert.Equal(t, "gpt-4o-mini", ev.Execution.ModelUsed, "model used should be fallback")
}

// TestTenantIsolation_FullStack runs two tenants through the same runner and evidence/secrets
// stores, then asserts cost totals, evidence list, and secrets access are isolated by tenant.
func TestTenantIsolation_FullStack(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "iso-agent")

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "ok"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}
	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers, nil),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	// Run as tenant acme
	respA, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "iso-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	require.True(t, respA.PolicyAllow)
	require.NotEmpty(t, respA.EvidenceID)

	// Run as tenant globex
	respB, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:       "globex",
		AgentName:      "iso-agent",
		Prompt:         "Hi",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	require.True(t, respB.PolicyAllow)
	require.NotEmpty(t, respB.EvidenceID)

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	// Cost isolation: each tenant sees only their own cost
	costAcme, err := evidenceStore.CostTotal(ctx, "acme", "", dayStart, dayEnd)
	require.NoError(t, err)
	costGlobex, err := evidenceStore.CostTotal(ctx, "globex", "", dayStart, dayEnd)
	require.NoError(t, err)
	assert.InDelta(t, 0.001, costAcme, 0.0001, "acme cost should be single run")
	assert.InDelta(t, 0.001, costGlobex, 0.0001, "globex cost should be single run")

	// List isolation: each tenant's index only contains their evidence
	idxAcme, err := evidenceStore.ListIndex(ctx, "acme", "", dayStart, dayEnd, 10, "")
	require.NoError(t, err)
	idxGlobex, err := evidenceStore.ListIndex(ctx, "globex", "", dayStart, dayEnd, 10, "")
	require.NoError(t, err)
	assert.Len(t, idxAcme, 1, "acme should see one evidence record")
	assert.Len(t, idxGlobex, 1, "globex should see one evidence record")
	assert.Equal(t, "acme", idxAcme[0].TenantID)
	assert.Equal(t, respA.EvidenceID, idxAcme[0].ID)
	assert.Equal(t, "globex", idxGlobex[0].TenantID)
	assert.Equal(t, respB.EvidenceID, idxGlobex[0].ID)

	// Secrets isolation: secret restricted to acme is not accessible by globex
	err = secretsStore.Set(ctx, "acme-only-key", []byte("secret-value"), secrets.ACL{Tenants: []string{"acme"}})
	require.NoError(t, err)
	_, err = secretsStore.Get(ctx, "acme-only-key", "acme", "iso-agent")
	assert.NoError(t, err)
	_, err = secretsStore.Get(ctx, "acme-only-key", "globex", "iso-agent")
	assert.ErrorIs(t, err, secrets.ErrSecretAccessDenied)
}

// TestRunner_ConcurrentTenants runs multiple tenants in parallel to detect cross-tenant
// contamination or data races. Run with: go test -race -tags=integration -run TestRunner_ConcurrentTenants
func TestRunner_ConcurrentTenants(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "concurrent-agent")

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "ok"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}
	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers, nil),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	const numTenants = 8
	const runsPerTenant = 3
	var wg sync.WaitGroup
	evidenceByTenant := make(map[string][]string)
	var mu sync.Mutex

	for i := 0; i < numTenants; i++ {
		tenantID := "tenant-" + string(rune('A'+i))
		wg.Add(1)
		go func(tid string) {
			defer wg.Done()
			var ids []string
			for j := 0; j < runsPerTenant; j++ {
				resp, err := runner.Run(ctx, &agent.RunRequest{
					TenantID:       tid,
					AgentName:      "concurrent-agent",
					Prompt:         tid + " run " + string(rune('0'+j)),
					InvocationType: "manual",
					PolicyPath:     policyPath,
				})
				if err != nil {
					t.Errorf("tenant %s run %d: %v", tid, j, err)
					return
				}
				if !resp.PolicyAllow || resp.EvidenceID == "" {
					t.Errorf("tenant %s run %d: unexpected response", tid, j)
					return
				}
				ids = append(ids, resp.EvidenceID)
			}
			mu.Lock()
			evidenceByTenant[tid] = ids
			mu.Unlock()
		}(tenantID)
	}
	wg.Wait()

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	mu.Lock()
	defer mu.Unlock()
	for tid, ids := range evidenceByTenant {
		assert.Len(t, ids, runsPerTenant, "tenant %s should have %d evidence IDs", tid, runsPerTenant)
		cost, err := evidenceStore.CostTotal(ctx, tid, "", dayStart, dayEnd)
		require.NoError(t, err)
		expectedCost := float64(runsPerTenant) * 0.001
		assert.InDelta(t, expectedCost, cost, 0.0001, "tenant %s cost", tid)
		idx, err := evidenceStore.ListIndex(ctx, tid, "", dayStart, dayEnd, 20, "")
		require.NoError(t, err)
		assert.Len(t, idx, runsPerTenant, "tenant %s index count", tid)
		for _, ev := range idx {
			assert.Equal(t, tid, ev.TenantID, "evidence tenant must match")
		}
	}
}

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

const (
	testEncryptionKey = "12345678901234567890123456789012" // 32 bytes
	testSigningKey    = "test-signing-key-1234567890123456"
)

// mockProvider implements llm.Provider for testing without real LLM calls.
type mockProvider struct {
	name    string
	content string
	err     error
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Generate(_ context.Context, req *llm.Request) (*llm.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &llm.Response{
		Content:      m.content,
		FinishReason: "stop",
		InputTokens:  10,
		OutputTokens: 20,
		Model:        req.Model,
	}, nil
}
func (m *mockProvider) EstimateCost(_ string, _, _ int) float64 { return 0.001 }

// writeTestPolicy creates a minimal valid .talon.yaml in the given dir and
// returns its path. The policy sets very high cost limits so requests pass.
func writeTestPolicy(t *testing.T, dir, name string) string {
	t.Helper()
	policyContent := `
agent:
  name: "` + name + `"
  version: "1.0.0"
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
	require.NoError(t, os.WriteFile(path, []byte(policyContent), 0o644))
	return path
}

// writeStrictPolicy creates a .talon.yaml that denies high-cost requests.
func writeStrictPolicy(t *testing.T, dir, name string) string {
	t.Helper()
	policyContent := `
agent:
  name: "` + name + `"
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 0.0001
    daily: 0.0001
    monthly: 0.0001
  model_routing:
    tier_0:
      primary: "gpt-4"
`
	path := filepath.Join(dir, name+".talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte(policyContent), 0o644))
	return path
}

func setupRunner(t *testing.T, policyDir string, providers map[string]llm.Provider, routingCfg *policy.ModelRoutingConfig) *Runner {
	t.Helper()

	dir := t.TempDir()

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(routingCfg, providers)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	return NewRunner(RunnerConfig{
		PolicyDir:  policyDir,
		Classifier: cls,
		AttScanner: attScanner,
		Extractor:  extractor,
		Router:     router,
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})
}

func TestRunner_FullPipeline_Success(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir, "test-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "Hello from mock LLM!"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &RunRequest{
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
	assert.InDelta(t, 0.001, resp.CostEUR, 0.01)
}

func TestRunner_DryRun(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir, "test-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "should not be called"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &RunRequest{
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
	policyPath := writeStrictPolicy(t, dir, "strict-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "should not be called"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &RunRequest{
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
	policyPath := writeTestPolicy(t, dir, "attach-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "Processed attachment"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &RunRequest{
		TenantID:       "acme",
		AgentName:      "attach-agent",
		Prompt:         "Summarize this document",
		InvocationType: "manual",
		PolicyPath:     policyPath,
		Attachments: []Attachment{
			{Filename: "readme.txt", Content: []byte("This is a safe text document.")},
		},
	})

	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Equal(t, "Processed attachment", resp.Response)
}

func TestRunner_LLMError(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir, "err-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{
			name: "openai",
			err:  assert.AnError,
		},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	_, err := runner.Run(context.Background(), &RunRequest{
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
	writeTestPolicy(t, dir, "default-path-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "policy from policyDir"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	// No PolicyPath: runner must resolve policyDir/AgentName.talon.yaml
	resp, err := runner.Run(context.Background(), &RunRequest{
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
		"openai": &mockProvider{name: "openai", content: "x"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	_, err := runner.Run(context.Background(), &RunRequest{
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
	policyPath := writeTestPolicy(t, dir, "pii-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "Processed PII input"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	resp, err := runner.Run(context.Background(), &RunRequest{
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
	policyPath := writeTestPolicy(t, dir, "vault-agent")

	// Operator provides a fallback provider with a dummy key
	operatorProvider := &mockProvider{name: "openai", content: "operator fallback response"}
	providers := map[string]llm.Provider{
		"openai": operatorProvider,
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	// Tenant "acme" stores their OpenAI key in the vault
	err = secretsStore.Set(context.Background(), "openai-api-key", []byte("sk-tenant-acme-key"), secrets.ACL{})
	require.NoError(t, err)

	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	resp, err := runner.Run(context.Background(), &RunRequest{
		TenantID:       "acme",
		AgentName:      "vault-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	// The runner should have resolved the key from vault. Since
	// NewProviderWithKey creates a real OpenAIProvider (which will fail
	// against a real API), but the mock fallback is what the Router
	// returned. The vault resolution replaces the mock, so the call
	// goes to a real OpenAI client — which will fail because "sk-tenant-acme-key"
	// is not a valid key. This confirms the vault path was taken.
	//
	// In a real scenario the vault would contain a valid key.
	// For this test, we verify the vault access was logged.
	auditLog, err2 := secretsStore.AuditLog(context.Background(), "openai-api-key", 10)
	require.NoError(t, err2)

	// The vault was accessed for the tenant's key
	found := false
	for _, entry := range auditLog {
		if entry.TenantID == "acme" && entry.SecretName == "openai-api-key" && entry.Allowed {
			found = true
			break
		}
	}
	assert.True(t, found, "vault should have an audit record for acme's openai-api-key access")

	// The run itself may fail (real OpenAI client with fake key) or succeed
	// (if the test mock intercepts). Either way, the vault resolution happened.
	_ = resp
	_ = err
}

func TestRunner_VaultKeyACLDenied_FallsBackToOperator(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir, "acl-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "operator fallback"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	// Store key with restrictive ACL — only "sales-bot" agent can access
	err = secretsStore.Set(context.Background(), "openai-api-key", []byte("sk-restricted"),
		secrets.ACL{Agents: []string{"sales-bot"}})
	require.NoError(t, err)

	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	// "acl-agent" is NOT in the ACL → vault returns access denied →
	// runner falls back to the operator mock provider
	resp, err := runner.Run(context.Background(), &RunRequest{
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
	policyPath := writeTestPolicy(t, dir, "noroute-agent")

	// No providers registered — router.Route will fail
	providers := map[string]llm.Provider{}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)

	_, err := runner.Run(context.Background(), &RunRequest{
		TenantID:       "acme",
		AgentName:      "noroute-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "routing LLM")
}

// TestRunner_PlanReviewGate_ReturnsPlanPending proves Step 4.5 (EU AI Act Art. 14) is wired:
// when policy has human_oversight: "always" and runner has PlanReviewStore, Run returns
// PlanPending and does not call the LLM.
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
	planStore, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "should not be called"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}
	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:    dir,
		Classifier:   classifier.MustNewScanner(),
		AttScanner:   attachment.MustNewScanner(),
		Extractor:    attachment.NewExtractor(10),
		Router:       llm.NewRouter(routingCfg, providers),
		Secrets:      secretsStore,
		Evidence:     evidenceStore,
		PlanReview:   planStore,
		ToolRegistry: tools.NewRegistry(),
	})

	resp, err := runner.Run(context.Background(), &RunRequest{
		TenantID:       "acme",
		AgentName:      "review-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)

	// Gate triggered: execution stopped for human review, no LLM call
	assert.True(t, resp.PolicyAllow)
	assert.NotEmpty(t, resp.PlanPending, "PlanPending must be set when plan review gate triggers")
	assert.Empty(t, resp.Response, "LLM must not be called when gated")
}

// recordingHook captures every invocation for test assertions.
type recordingHook struct {
	point   HookPoint
	mu      sync.Mutex
	calls   []recordedCall
	abortAt int // abort after N calls (-1 = never)
}

type recordedCall struct {
	Stage   HookPoint
	Payload json.RawMessage
}

func newRecordingHook(point HookPoint) *recordingHook {
	return &recordingHook{point: point, abortAt: -1}
}

func (h *recordingHook) Point() HookPoint { return h.point }
func (h *recordingHook) Execute(_ context.Context, data *HookData) (*HookResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, recordedCall{Stage: data.Stage, Payload: data.Payload})
	if h.abortAt >= 0 && len(h.calls) > h.abortAt {
		return &HookResult{Continue: false}, nil
	}
	return &HookResult{Continue: true}, nil
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

// TestRunner_HooksFireAtPipelineStages verifies that hooks registered at key
// pipeline points (post-policy, pre-llm, post-llm, post-evidence) receive
// stage-appropriate JSON payloads during a successful run.
func TestRunner_HooksFireAtPipelineStages(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir, "hooks-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "hooked response"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	postPolicy := newRecordingHook(HookPostPolicy)
	preLLM := newRecordingHook(HookPreLLM)
	postLLM := newRecordingHook(HookPostLLM)
	postEvidence := newRecordingHook(HookPostEvidence)

	registry := NewHookRegistry()
	registry.Register(postPolicy)
	registry.Register(preLLM)
	registry.Register(postLLM)
	registry.Register(postEvidence)

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
		Hooks:      registry,
	})

	resp, err := runner.Run(context.Background(), &RunRequest{
		TenantID:       "acme",
		AgentName:      "hooks-agent",
		Prompt:         "test hooks",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.Equal(t, "hooked response", resp.Response)

	// Verify each hook fired exactly once with stage-appropriate payloads.
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
	assert.NotNil(t, pe["cost_eur"])
}

// TestRunner_HookAbortBlocksPipeline verifies that a hook returning
// Continue=false at HookPreLLM prevents the LLM call.
func TestRunner_HookAbortBlocksPipeline(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir, "abort-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "should not reach LLM"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	abortHook := &recordingHook{point: HookPreLLM, abortAt: 0}

	registry := NewHookRegistry()
	registry.Register(abortHook)

	storeDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(storeDir, "secrets.db"), testEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(storeDir, "evidence.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, providers),
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
		Hooks:      registry,
	})

	resp, err := runner.Run(context.Background(), &RunRequest{
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

// TestRunner_NilHooksDoesNotPanic verifies that a Runner with no hooks
// (nil HookRegistry) works without panics — backward compatibility.
func TestRunner_NilHooksDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir, "nohooks-agent")

	providers := map[string]llm.Provider{
		"openai": &mockProvider{name: "openai", content: "no hooks response"},
	}
	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}

	runner := setupRunner(t, dir, providers, routingCfg)
	// setupRunner does NOT set Hooks — confirm nil hooks is safe.

	resp, err := runner.Run(context.Background(), &RunRequest{
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

package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestEntityNames(t *testing.T) {
	tests := []struct {
		name     string
		entities []classifier.PIIEntity
		want     []string
	}{
		{
			name:     "empty",
			entities: nil,
			want:     nil,
		},
		{
			name: "deduplicates types",
			entities: []classifier.PIIEntity{
				{Type: "EMAIL_ADDRESS", Value: "a@b.com"},
				{Type: "EMAIL_ADDRESS", Value: "c@d.com"},
				{Type: "PHONE_NUMBER", Value: "+49123456"},
			},
			want: []string{"EMAIL_ADDRESS", "PHONE_NUMBER"},
		},
		{
			name: "single entity",
			entities: []classifier.PIIEntity{
				{Type: "IBAN_CODE", Value: "DE89370400440532013000"},
			},
			want: []string{"IBAN_CODE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := entityNames(tt.entities)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestComplianceFromPolicy(t *testing.T) {
	t.Run("nil compliance", func(t *testing.T) {
		pol := &policy.Policy{}
		c := complianceFromPolicy(pol)
		assert.Nil(t, c.Frameworks)
		assert.Empty(t, c.DataLocation)
	})

	t.Run("with compliance", func(t *testing.T) {
		pol := &policy.Policy{
			Compliance: &policy.ComplianceConfig{
				Frameworks:    []string{"gdpr", "nis2"},
				DataResidency: "eu-west-1",
			},
		}
		c := complianceFromPolicy(pol)
		assert.Equal(t, []string{"gdpr", "nis2"}, c.Frameworks)
		assert.Equal(t, "eu-west-1", c.DataLocation)
	})
}

func TestFormatMemoryIndexForPrompt(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got := formatMemoryIndexForPrompt(nil)
		assert.Empty(t, got)
		got = formatMemoryIndexForPrompt([]memory.IndexEntry{})
		assert.Empty(t, got)
	})
	t.Run("single entry", func(t *testing.T) {
		entries := []memory.IndexEntry{
			{
				ID:              "mem_1",
				Category:        memory.CategoryDomainKnowledge,
				Title:           "A learning",
				ObservationType: memory.ObsLearning,
				TrustScore:      70,
				ReviewStatus:    "auto_approved",
				Timestamp:       time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			},
		}
		got := formatMemoryIndexForPrompt(entries)
		assert.Contains(t, got, "[AGENT MEMORY INDEX]")
		assert.Contains(t, got, "[END MEMORY INDEX]")
		assert.Contains(t, got, "mem_1")
		assert.Contains(t, got, "domain_knowledge")
		assert.Contains(t, got, "✓")
	})
	t.Run("pending_review excluded from prompt", func(t *testing.T) {
		entries := []memory.IndexEntry{
			{
				ID:              "mem_2",
				Category:        memory.CategoryPolicyHit,
				Title:           "Denied",
				ObservationType: memory.ObsDecision,
				TrustScore:      40,
				ReviewStatus:    "pending_review",
				Timestamp:       time.Date(2025, 1, 16, 0, 0, 0, 0, time.UTC),
			},
		}
		got := formatMemoryIndexForPrompt(entries)
		assert.Empty(t, got, "pending_review entries should not appear in prompt")
	})
	t.Run("mix of approved and pending", func(t *testing.T) {
		entries := []memory.IndexEntry{
			{
				ID: "mem_approved", Category: memory.CategoryDomainKnowledge, Title: "Approved",
				TrustScore: 70, ReviewStatus: "auto_approved",
				Timestamp: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			},
			{
				ID: "mem_pending", Category: memory.CategoryPolicyHit, Title: "Pending",
				TrustScore: 40, ReviewStatus: "pending_review",
				Timestamp: time.Date(2025, 1, 16, 0, 0, 0, 0, time.UTC),
			},
		}
		got := formatMemoryIndexForPrompt(entries)
		assert.Contains(t, got, "mem_approved")
		assert.NotContains(t, got, "mem_pending")
	})
}

func TestCompressObservation(t *testing.T) {
	resp := &RunResponse{ModelUsed: "gpt-4", CostEUR: 0.002, DurationMS: 100}
	got := compressObservation(resp, "Short content")
	assert.Contains(t, got, "Model: gpt-4")
	assert.Contains(t, got, "EUR0.0020")
	assert.Contains(t, got, "100ms")
	assert.Contains(t, got, "Short content")

	resp.DenyReason = "budget exceeded"
	got = compressObservation(resp, "x")
	assert.Contains(t, got, "Denied: budget exceeded")

	long := string(make([]byte, 2000))
	got = compressObservation(resp, long)
	assert.Contains(t, got, "...")
	assert.LessOrEqual(t, len(got), 2000+100)
}

func TestCompressTitle(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		resp := &RunResponse{DenyReason: "PII detected"}
		got := compressTitle(resp, "any")
		assert.Equal(t, "Denied: PII detected", got)
	})
	t.Run("first sentence under 80", func(t *testing.T) {
		resp := &RunResponse{}
		got := compressTitle(resp, "First line. Second line.")
		assert.Equal(t, "First line", got) // stops before the period (IndexAny)
	})
	t.Run("truncate at 80", func(t *testing.T) {
		resp := &RunResponse{}
		long := strings.Repeat("a", 90)
		got := compressTitle(resp, long)
		assert.LessOrEqual(t, len(got), 81)
		assert.Equal(t, 80, len(got))
	})
	t.Run("short passthrough", func(t *testing.T) {
		resp := &RunResponse{}
		got := compressTitle(resp, "Short")
		assert.Equal(t, "Short", got)
	})
}

func TestInferCategory(t *testing.T) {
	assert.Equal(t, memory.CategoryPolicyHit, inferCategory(&RunResponse{DenyReason: "denied"}))
	assert.Equal(t, memory.CategoryDomainKnowledge, inferCategory(&RunResponse{}))
}

func TestInferObservationType(t *testing.T) {
	assert.Equal(t, memory.ObsDecision, inferObservationType(&RunResponse{DenyReason: "x"}))
	assert.Equal(t, memory.ObsLearning, inferObservationType(&RunResponse{}))
}

func TestMemoryMode(t *testing.T) {
	t.Run("nil memory config", func(t *testing.T) {
		assert.Equal(t, "disabled", memoryMode(&policy.Policy{}))
	})
	t.Run("disabled", func(t *testing.T) {
		assert.Equal(t, "disabled", memoryMode(&policy.Policy{
			Memory: &policy.MemoryConfig{Enabled: false},
		}))
	})
	t.Run("default is active", func(t *testing.T) {
		assert.Equal(t, "active", memoryMode(&policy.Policy{
			Memory: &policy.MemoryConfig{Enabled: true},
		}))
	})
	t.Run("shadow", func(t *testing.T) {
		assert.Equal(t, "shadow", memoryMode(&policy.Policy{
			Memory: &policy.MemoryConfig{Enabled: true, Mode: "shadow"},
		}))
	})
	t.Run("explicit active", func(t *testing.T) {
		assert.Equal(t, "active", memoryMode(&policy.Policy{
			Memory: &policy.MemoryConfig{Enabled: true, Mode: "active"},
		}))
	})
	t.Run("unknown mode defaults to shadow", func(t *testing.T) {
		// Typo like "shadown" must not default to "active"; fail closed to shadow.
		assert.Equal(t, "shadow", memoryMode(&policy.Policy{
			Memory: &policy.MemoryConfig{Enabled: true, Mode: "shadown"},
		}))
	})
}

func TestFilterByPromptCategories(t *testing.T) {
	entries := []memory.IndexEntry{
		{ID: "mem_1", Category: memory.CategoryDomainKnowledge},
		{ID: "mem_2", Category: memory.CategoryPolicyHit},
		{ID: "mem_3", Category: memory.CategoryDomainKnowledge},
		{ID: "mem_4", Category: memory.CategoryErrorRecovery},
	}

	t.Run("filter to domain_knowledge only", func(t *testing.T) {
		got := filterByPromptCategories(entries, []string{memory.CategoryDomainKnowledge})
		assert.Len(t, got, 2)
		for _, e := range got {
			assert.Equal(t, memory.CategoryDomainKnowledge, e.Category)
		}
	})
	t.Run("multiple categories", func(t *testing.T) {
		got := filterByPromptCategories(entries, []string{memory.CategoryDomainKnowledge, memory.CategoryPolicyHit})
		assert.Len(t, got, 3)
	})
	t.Run("empty categories returns none", func(t *testing.T) {
		got := filterByPromptCategories(entries, []string{})
		assert.Empty(t, got)
	})
}

func TestFilterOutPendingReview(t *testing.T) {
	entries := []memory.IndexEntry{
		{ID: "mem_1", ReviewStatus: "auto_approved"},
		{ID: "mem_2", ReviewStatus: "pending_review"},
		{ID: "mem_3", ReviewStatus: "auto_approved"},
		{ID: "mem_4", ReviewStatus: ""},
	}

	got := filterOutPendingReview(entries)
	assert.Len(t, got, 3)
	ids := make([]string, len(got))
	for i := range got {
		ids[i] = got[i].ID
	}
	assert.NotContains(t, ids, "mem_2")
	assert.Contains(t, ids, "mem_1")
	assert.Contains(t, ids, "mem_3")
	assert.Contains(t, ids, "mem_4")
}

func TestCapMemoryByTokens(t *testing.T) {
	// Index-line estimate is (len(Title)+len(Category)+40)/4; TokenCount is ignored (prompt uses one line per entry).
	shortTitle := "E1"
	longTitle := strings.Repeat("a", 356)
	entries := []memory.IndexEntry{
		{ID: "mem_1", Title: longTitle, Category: "test"},
		{ID: "mem_2", Title: longTitle, Category: "test"},
		{ID: "mem_3", Title: shortTitle, Category: "test"},
		{ID: "mem_4", Title: shortTitle, Category: "test"},
	}

	t.Run("all fit", func(t *testing.T) {
		got := capMemoryByTokens(entries, 500)
		assert.Len(t, got, 4)
	})
	t.Run("cap at 2", func(t *testing.T) {
		got := capMemoryByTokens(entries, 200)
		assert.Len(t, got, 2, "first two entries ~100 tokens each = 200; third would exceed budget")
	})
	t.Run("at least one", func(t *testing.T) {
		got := capMemoryByTokens(entries, 10)
		assert.Len(t, got, 1)
	})
	t.Run("empty", func(t *testing.T) {
		got := capMemoryByTokens(nil, 100)
		assert.Empty(t, got)
	})
}

func TestSourceTypeFromInvocation(t *testing.T) {
	assert.Equal(t, memory.SourceManual, sourceTypeFromInvocation("manual"))
	assert.Equal(t, memory.SourceAgentRun, sourceTypeFromInvocation("scheduled"))
	assert.Equal(t, memory.SourceWebhook, sourceTypeFromInvocation("webhook:jira"))
	assert.Equal(t, memory.SourceAgentRun, sourceTypeFromInvocation(""))
	assert.Equal(t, memory.SourceAgentRun, sourceTypeFromInvocation("other"))
}

func TestPlanReviewConfigFromPolicy(t *testing.T) {
	assert.Nil(t, planReviewConfigFromPolicy(nil))
	cfg := &policy.PlanReviewConfig{
		RequireForTools:  true,
		RequireForTier:   "tier_2",
		CostThresholdEUR: 1.5,
		TimeoutMinutes:   10,
		NotifyWebhook:    "https://example.com/hook",
	}
	got := planReviewConfigFromPolicy(cfg)
	require.NotNil(t, got)
	assert.True(t, got.RequireForTools)
	assert.Equal(t, "tier_2", got.RequireForTier)
	assert.Equal(t, 1.5, got.CostThresholdEUR)
	assert.Equal(t, 10, got.TimeoutMinutes)
	assert.Equal(t, "https://example.com/hook", got.NotifyWebhook)
}

func TestNewRunner(t *testing.T) {
	cls := classifier.MustNewScanner()
	dir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	r := NewRunner(RunnerConfig{
		PolicyDir:         dir,
		DefaultPolicyPath: "agent.talon.yaml",
		Classifier:        cls,
		Router:            llm.NewRouter(nil, map[string]llm.Provider{"ollama": nil}, nil),
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
	})
	require.NotNil(t, r)
}

func TestRunFromTrigger_usesDefaultPolicyPath(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteTestPolicyFile(t, dir, "test-agent")
	require.FileExists(t, policyPath)

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "ok"},
	}
	routing := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}
	router := llm.NewRouter(routing, providers, nil)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:         dir,
		DefaultPolicyPath: policyPath,
		Classifier:        cls,
		AttScanner:        attScanner,
		Extractor:         extractor,
		Router:            router,
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = runner.RunFromTrigger(ctx, "test-agent", "Say hello", "scheduled")
	require.NoError(t, err)
}

func TestRun_PolicyDeny(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteStrictPolicyFile(t, dir, "deny-agent")
	require.FileExists(t, policyPath)

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "should not run"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:         dir,
		DefaultPolicyPath: policyPath,
		Classifier:        cls,
		AttScanner:        attScanner,
		Extractor:         extractor,
		Router:            router,
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "acme",
		AgentName:      "deny-agent",
		Prompt:         "expensive query",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.False(t, resp.PolicyAllow)
	assert.NotEmpty(t, resp.DenyReason)
}

func TestRun_WithAttachments(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteTestPolicyFile(t, dir, "attach-agent")
	require.FileExists(t, policyPath)

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "from attachment"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:         dir,
		DefaultPolicyPath: policyPath,
		Classifier:        cls,
		AttScanner:        attScanner,
		Extractor:         extractor,
		Router:            router,
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "acme",
		AgentName:      "attach-agent",
		Prompt:         "Summarize this",
		InvocationType: "manual",
		PolicyPath:     policyPath,
		Attachments:    []Attachment{{Filename: "note.txt", Content: []byte("Q4 revenue: 1M EUR.")}},
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Contains(t, resp.Response, "from attachment")
}

// echoTool implements tools.Tool for tests; echoes params back.
type echoTool struct{}

func (e *echoTool) Name() string                 { return "echo" }
func (e *echoTool) Description() string          { return "Echo" }
func (e *echoTool) InputSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (e *echoTool) Execute(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
	return params, nil
}

func TestRun_WithToolInvocations(t *testing.T) {
	dir := t.TempDir()
	// Policy must allow the tool in capabilities.allowed_tools
	policyPath := filepath.Join(dir, "tool-agent.talon.yaml")
	policyYAML := `
agent:
  name: "tool-agent"
  version: "1.0.0"
capabilities:
  allowed_tools: ["echo"]
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
	require.NoError(t, os.WriteFile(policyPath, []byte(policyYAML), 0o600))

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "ok"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	reg := tools.NewRegistry()
	reg.Register(&echoTool{})

	runner := NewRunner(RunnerConfig{
		PolicyDir:         dir,
		DefaultPolicyPath: policyPath,
		Classifier:        cls,
		AttScanner:        attScanner,
		Extractor:         extractor,
		Router:            router,
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
		ToolRegistry:      reg,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "acme",
		AgentName:      "tool-agent",
		Prompt:         "Hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
		ToolInvocations: []ToolInvocation{
			{Name: "echo", Params: []byte(`{"x":1}`)},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Contains(t, resp.ToolsCalled, "echo")
}

func TestAllowedBudgetAlertURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"https allowed", "https://hooks.example.com/alerts", true},
		{"https with path", "https://api.eu.example.com/webhook/budget", true},
		{"http localhost", "http://localhost:9090/hook", true},
		{"http 127.0.0.1", "http://127.0.0.1:8080/cb", true},
		{"http subdomain localhost", "http://api.localhost/hook", true},
		{"empty", "", false},
		{"invalid url", "://no-scheme", false},
		{"no host", "https://", false},
		{"http non-loopback rejected", "http://evil.internal/hook", false},
		{"http private host rejected", "http://10.0.0.1/hook", false},
		{"ftp rejected", "ftp://files.example.com/x", false},
		{"javascript rejected", "javascript:alert(1)", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allowedBudgetAlertURL(tt.url)
			assert.Equal(t, tt.want, got, "allowedBudgetAlertURL(%q)", tt.url)
		})
	}
}

func TestActiveRunTracker(t *testing.T) {
	tracker := &ActiveRunTracker{}
	assert.Equal(t, 0, tracker.Count("tenant-a"))

	tracker.Increment("tenant-a")
	assert.Equal(t, 1, tracker.Count("tenant-a"))
	tracker.Increment("tenant-a")
	assert.Equal(t, 2, tracker.Count("tenant-a"))
	assert.Equal(t, 0, tracker.Count("tenant-b"))

	tracker.Decrement("tenant-a")
	assert.Equal(t, 1, tracker.Count("tenant-a"))
	tracker.Decrement("tenant-a")
	assert.Equal(t, 0, tracker.Count("tenant-a"))
	tracker.Decrement("tenant-a") // idempotent at zero
	assert.Equal(t, 0, tracker.Count("tenant-a"))

	tracker.Increment("tenant-b")
	assert.Equal(t, 1, tracker.Count("tenant-b"))
	tracker.Decrement("tenant-b")
	assert.Equal(t, 0, tracker.Count("tenant-b"))
}

func TestEmitBudgetAlertIfNeeded(t *testing.T) {
	ctx := context.Background()
	// Nil limits: no-op
	emitBudgetAlertIfNeeded(ctx, "t1", 10, 100, nil)

	// Below threshold: no fire
	emitBudgetAlertIfNeeded(ctx, "t1", 1, 50, &policy.CostLimitsConfig{Daily: 100, Monthly: 1000})

	// At or above 80%: fires log; webhook URL rejected (no outbound HTTP) so postBudgetAlert bails in test
	emitBudgetAlertIfNeeded(ctx, "t1", 90, 0, &policy.CostLimitsConfig{
		Daily: 100, Monthly: 1000,
		BudgetAlertWebhook: "http://rejected.invalid/hook", // not localhost, so allowedBudgetAlertURL rejects
	})
	// Monthly at 80%
	emitBudgetAlertIfNeeded(ctx, "t2", 0, 900, &policy.CostLimitsConfig{
		Daily: 100, Monthly: 1000,
		BudgetAlertWebhook: "ftp://no",
	})
}

func TestBoolToDecision(t *testing.T) {
	assert.Equal(t, "allow", boolToDecision(true))
	assert.Equal(t, "deny", boolToDecision(false))
}

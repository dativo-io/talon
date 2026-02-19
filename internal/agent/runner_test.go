package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	t.Run("pending_review uses question mark", func(t *testing.T) {
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
		assert.Contains(t, got, "?")
		assert.Contains(t, got, "pending_review")
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

func TestSourceTypeFromInvocation(t *testing.T) {
	assert.Equal(t, memory.SourceAgentRun, sourceTypeFromInvocation("manual"))
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

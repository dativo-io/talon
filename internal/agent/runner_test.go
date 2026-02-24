package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestInferCategoryTypeAndMemType(t *testing.T) {
	tests := []struct {
		name    string
		resp    *RunResponse
		wantCat string
		wantObs string
		wantMem string
	}{
		{
			name:    "deny → policy_hit + episodic",
			resp:    &RunResponse{DenyReason: "budget exceeded"},
			wantCat: memory.CategoryPolicyHit,
			wantObs: memory.ObsDecision,
			wantMem: memory.MemTypeEpisodic,
		},
		{
			name:    "tool use → tool_approval + episodic",
			resp:    &RunResponse{ToolsCalled: []string{"search"}},
			wantCat: memory.CategoryToolApproval,
			wantObs: memory.ObsToolUse,
			wantMem: memory.MemTypeEpisodic,
		},
		{
			name:    "high cost → cost_decision + episodic",
			resp:    &RunResponse{Cost: 0.15},
			wantCat: memory.CategoryCostDecision,
			wantObs: memory.ObsDecision,
			wantMem: memory.MemTypeEpisodic,
		},
		{
			name:    "content prefer → user_preferences + semantic",
			resp:    &RunResponse{Response: "User said they prefer dark mode"},
			wantCat: memory.CategoryUserPreferences,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeSemanticFact,
		},
		{
			name:    "content procedure → procedure_improvements + procedural",
			resp:    &RunResponse{Response: "Step 1: do X. Procedure for onboarding."},
			wantCat: memory.CategoryProcedureImprovements,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeProcedural,
		},
		{
			name:    "content correction → factual_corrections + semantic",
			resp:    &RunResponse{Response: "Actually the date was wrong, updated to 2024"},
			wantCat: memory.CategoryFactualCorrections,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeSemanticFact,
		},
		{
			name:    "default → domain_knowledge + semantic",
			resp:    &RunResponse{Response: "General reply with no keywords"},
			wantCat: memory.CategoryDomainKnowledge,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeSemanticFact,
		},
		// Bare "like" was removed: common phrases must not be classified as user_preferences
		{
			name:    "looks like → domain_knowledge not user_preferences",
			resp:    &RunResponse{Response: "It looks like the request was successful."},
			wantCat: memory.CategoryDomainKnowledge,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeSemanticFact,
		},
		{
			name:    "likely / likewise → domain_knowledge not user_preferences",
			resp:    &RunResponse{Response: "This is likely correct. Likewise for the other case."},
			wantCat: memory.CategoryDomainKnowledge,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeSemanticFact,
		},
		{
			name:    "would like to → domain_knowledge not user_preferences",
			resp:    &RunResponse{Response: "The user would like to receive a summary."},
			wantCat: memory.CategoryDomainKnowledge,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeSemanticFact,
		},
		{
			name:    "explicit I like → user_preferences",
			resp:    &RunResponse{Response: "User said: I like getting reports in PDF."},
			wantCat: memory.CategoryUserPreferences,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeSemanticFact,
		},
		{
			name:    "best practice → procedure_improvements",
			resp:    &RunResponse{Response: "Best practice: run validation before deploy."},
			wantCat: memory.CategoryProcedureImprovements,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeProcedural,
		},
		{
			name:    "no longer → factual_corrections",
			resp:    &RunResponse{Response: "The budget is no longer 1M; it was updated to 2M."},
			wantCat: memory.CategoryFactualCorrections,
			wantObs: memory.ObsLearning,
			wantMem: memory.MemTypeSemanticFact,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat, obs, mem := inferCategoryTypeAndMemType(tt.resp)
			assert.Equal(t, tt.wantCat, cat)
			assert.Equal(t, tt.wantObs, obs)
			assert.Equal(t, tt.wantMem, mem)
		})
	}
}

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
	t.Run("entries ordered by trust descending so highest-trust context appears first", func(t *testing.T) {
		// When multiple entries are injected, highest-trust should appear first so the model prioritizes it.
		entries := []memory.IndexEntry{
			{
				ID: "mem_low", Category: memory.CategoryDomainKnowledge, Title: "Low trust", TrustScore: 70,
				ReviewStatus: "auto_approved", Timestamp: time.Date(2025, 1, 14, 0, 0, 0, 0, time.UTC),
			},
			{
				ID: "mem_high", Category: memory.CategoryDomainKnowledge, Title: "High trust", TrustScore: 90,
				ReviewStatus: "auto_approved", Timestamp: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			},
			{
				ID: "mem_mid", Category: memory.CategoryDomainKnowledge, Title: "Mid trust", TrustScore: 80,
				ReviewStatus: "auto_approved", Timestamp: time.Date(2025, 1, 16, 0, 0, 0, 0, time.UTC),
			},
		}
		got := formatMemoryIndexForPrompt(entries)
		require.NotEmpty(t, got)
		// Highest trust (90) must appear before lowest (70) in the prompt.
		pos90 := strings.Index(got, "trust:90")
		pos70 := strings.Index(got, "trust:70")
		require.Greater(t, pos90, -1, "output should contain trust:90")
		require.Greater(t, pos70, -1, "output should contain trust:70")
		assert.Less(t, pos90, pos70, "highest-trust entry (trust:90) should appear before lowest (trust:70) so model sees best context first")
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
	resp := &RunResponse{ModelUsed: "gpt-4", Cost: 0.002, DurationMS: 100}
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
	// Memory should be complete: newline must not cut the title and drop units (e.g. "2" without "M").
	t.Run("newline must not cut title so unit is preserved", func(t *testing.T) {
		resp := &RunResponse{}
		// Model sometimes replies "EUR 2\nMillion." — title must include "2 Million", not just "EUR 2"
		got := compressTitle(resp, "Your Q4 revenue target for the Acme Suite is EUR 2\nMillion.")
		assert.Contains(t, got, "2 Million", "title must be complete and include unit after newline")
		assert.NotEqual(t, "Your Q4 revenue target for the Acme Suite is EUR 2", got, "must not stop at newline and drop Million")
	})
	t.Run("number and unit on separate lines", func(t *testing.T) {
		resp := &RunResponse{}
		got := compressTitle(resp, "Target is EUR 2\nM.")
		assert.Contains(t, got, "2", got)
		assert.Contains(t, got, "M", "unit M must not be dropped when on next line")
	})
	t.Run("first sentence over 80 chars after normalizing newlines", func(t *testing.T) {
		resp := &RunResponse{}
		// First sentence (up to .) is under 80 when newlines are spaces; total length > 80
		s := "Short prefix. " + strings.Repeat("x", 70)
		got := compressTitle(resp, s)
		assert.Equal(t, "Short prefix", got)
	})
}

func TestInferCategory(t *testing.T) {
	assert.Equal(t, memory.CategoryPolicyHit, inferCategory(&RunResponse{DenyReason: "denied"}))
	assert.Equal(t, memory.CategoryDomainKnowledge, inferCategory(&RunResponse{}))
}

// TestLegacyAllowedCategoriesAcceptInferredSubtypes ensures that when a policy has
// only allowed_categories: [domain_knowledge, policy_hit], memory writes for runs
// that inferCategoryTypeAndMemType classifies as tool_approval, cost_decision,
// user_preferences, or procedure_improvements are accepted by ValidateWrite (no
// silent memory loss).
func TestLegacyAllowedCategoriesAcceptInferredSubtypes(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := memory.NewStore(filepath.Join(dir, "mem.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	gov := memory.NewGovernance(store, classifier.MustNewScanner())

	legacyPol := &policy.Policy{
		Memory: &policy.MemoryConfig{
			Enabled:           true,
			MaxEntrySizeKB:    10,
			AllowedCategories: []string{"domain_knowledge", "policy_hit"},
		},
		Policies: policy.PoliciesConfig{},
	}
	engine, err := policy.NewEngine(ctx, legacyPol)
	require.NoError(t, err)

	responses := []*RunResponse{
		{ToolsCalled: []string{"search"}},              // → tool_approval
		{Cost: 0.15, Response: "Used expensive model"}, // → cost_decision
		{Response: "I prefer bullet points"},           // → user_preferences
		{Response: "Step 1: do X. Step 2: do Y"},       // → procedure_improvements
	}
	for _, resp := range responses {
		category, _, _ := inferCategoryTypeAndMemType(resp)
		entry := &memory.Entry{
			Category:   category,
			Title:      "Test",
			Content:    "Safe content without PII",
			SourceType: memory.SourceAgentRun,
			TenantID:   "acme", AgentID: "test",
		}
		err := gov.ValidateWrite(ctx, entry, legacyPol, engine)
		assert.NoError(t, err, "legacy policy must allow inferred category %q", category)
	}
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

func TestSafePolicyPathUnder(t *testing.T) {
	dir := t.TempDir()
	dirAbs, _ := filepath.Abs(dir)

	tests := []struct {
		name      string
		policyDir string
		path      string
		wantErr   bool
	}{
		{"relative_under", dir, "agent.talon.yaml", false},
		{"relative_under_subdir", dir, "sub/agent.talon.yaml", false},
		{"traversal_escape", dir, "../../../etc/passwd.talon.yaml", true},
		{"traversal_double_dot", dir, "sub/../../../etc/passwd.talon.yaml", true},
		{"absolute_under", dirAbs, filepath.Join(dirAbs, "a.talon.yaml"), false},
		{"absolute_outside", dirAbs, filepath.Clean(filepath.Join(dirAbs, "..", "outside.talon.yaml")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := safePolicyPathUnder(tt.policyDir, tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "policy path")
				return
			}
			require.NoError(t, err)
			assert.True(t, filepath.IsAbs(got), "expected absolute path")
			rel, err := filepath.Rel(tt.policyDir, got)
			require.NoError(t, err)
			assert.False(t, strings.HasPrefix(rel, ".."), "path must be under policy dir")
		})
	}
}

// TestRun_acceptsAbsolutePolicyPathOutsidePolicyDir ensures that when PolicyPath is an
// absolute path (e.g. from --policy or serve config / Docker volume), the runner accepts it
// even though it is outside policyDir. This fixes serve chat completions and talon run --policy
// when the policy file lives outside CWD.
func TestRun_acceptsAbsolutePolicyPathOutsidePolicyDir(t *testing.T) {
	// Policy file in its own temp dir (simulates e.g. /etc/talon/policies)
	policyDir := t.TempDir()
	policyPath := testutil.WriteTestPolicyFile(t, policyDir, "out-of-cwd-agent")
	require.FileExists(t, policyPath)
	absPath, err := filepath.Abs(policyPath)
	require.NoError(t, err)
	// Runner with policyDir "." so absPath is outside it
	runDir := t.TempDir()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(runDir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(runDir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

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

	runner := NewRunner(RunnerConfig{
		PolicyDir:         ".", // as in serve and run
		DefaultPolicyPath: "",
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
		TenantID:       "default",
		AgentName:      "out-of-cwd-agent",
		Prompt:         "hello",
		InvocationType: "manual",
		PolicyPath:     absPath, // absolute path outside policyDir "."
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
}

// TestRun_rejectsAgentNameAsAbsolutePath ensures that when PolicyPath is empty, the path is
// derived from AgentName and must not be treated as a trusted absolute path. An agent name
// starting with "/" (e.g. from a future HTTP handler) would otherwise bypass safePolicyPathUnder.
func TestRun_rejectsAgentNameAsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteTestPolicyFile(t, dir, "agent")
	require.FileExists(t, policyPath)
	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

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

	runner := NewRunner(RunnerConfig{
		PolicyDir:         dir,
		DefaultPolicyPath: "",
		Classifier:        cls,
		AttScanner:        attScanner,
		Extractor:         extractor,
		Router:            router,
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// PolicyPath empty, AgentName starts with "/" -> must reject (would bypass safePolicyPathUnder)
	_, err = runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "/etc/foo",
		Prompt:         "hello",
		InvocationType: "manual",
		PolicyPath:     "", // empty so path would become AgentName + ".talon.yaml"
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy path")
	assert.True(t, strings.Contains(err.Error(), "must not be an absolute path") ||
		strings.Contains(err.Error(), "must not start with path separator"),
		"error should reject absolute or path-separator agent name: %s", err.Error())
}

// TestValidateAgentNameForPolicyPath checks that when PolicyPath is empty, unsafe agent names are rejected.
func TestValidateAgentNameForPolicyPath(t *testing.T) {
	tests := []struct {
		name      string
		agentName string
		wantErr   bool
	}{
		{"ok", "my-agent", false},
		{"ok_simple", "agent", false},
		{"empty", "", true},
		{"starts_with_slash", "/etc/foo", true},
		{"contains_slash", "foo/bar", true},
		{"double_dot", "..", true},
		{"starts_with_dotdot", "../x", true},
		{"contains_dotdot", "a/../b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAgentNameForPolicyPath(tt.agentName)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "agent name")
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestRun_rejectsEmptyAgentNameWhenNoPolicyPath ensures Run rejects empty AgentName when PolicyPath is empty.
func TestRun_rejectsEmptyAgentNameWhenNoPolicyPath(t *testing.T) {
	dir := t.TempDir()
	_ = testutil.WriteTestPolicyFile(t, dir, "agent")
	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	cls := classifier.MustNewScanner()
	runner := NewRunner(RunnerConfig{
		PolicyDir:         dir,
		DefaultPolicyPath: "",
		Classifier:        cls,
		Router:            llm.NewRouter(nil, map[string]llm.Provider{"openai": &testutil.MockProvider{}}, nil),
		Secrets:           secretsStore,
		Evidence:          evidenceStore,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "",
		Prompt:         "hello",
		InvocationType: "manual",
		PolicyPath:     "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy path")
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestPlanReviewConfigFromPolicy(t *testing.T) {
	assert.Nil(t, planReviewConfigFromPolicy(nil))
	cfg := &policy.PlanReviewConfig{
		RequireForTools: true,
		RequireForTier:  "tier_2",
		CostThreshold:   1.5,
		TimeoutMinutes:  10,
		NotifyWebhook:   "https://example.com/hook",
	}
	got := planReviewConfigFromPolicy(cfg)
	require.NotNil(t, got)
	assert.True(t, got.RequireForTools)
	assert.Equal(t, "tier_2", got.RequireForTier)
	assert.Equal(t, 1.5, got.CostThreshold)
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

func TestRun_BlockOnPII_PromptPII(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteBlockOnPIIPolicyFile(t, dir, "block-pii-agent", true)
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
		AgentName:      "block-pii-agent",
		Prompt:         "summarize this for user@example.com",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.False(t, resp.PolicyAllow)
	assert.Contains(t, resp.DenyReason, "PII")
}

func TestRun_BlockOnPII_NoBlockWhenFalse(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteBlockOnPIIPolicyFile(t, dir, "allow-pii-agent", false)
	require.FileExists(t, policyPath)

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "summary done"},
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
		AgentName:      "allow-pii-agent",
		Prompt:         "summarize for user@example.com",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Contains(t, resp.Response, "summary done")
}

func TestRun_BlockOnPII_AttachmentPII(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteBlockOnPIIPolicyFile(t, dir, "block-pii-att-agent", true)
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

	// Prompt has no PII; attachment (CSV) contains email and IBAN
	csvWithPII := []byte("name,email,iban\nJane Doe,jane@acme.de,DE89370400440532013000")
	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "acme",
		AgentName:      "block-pii-att-agent",
		Prompt:         "Summarize this document",
		InvocationType: "manual",
		PolicyPath:     policyPath,
		Attachments:    []Attachment{{Filename: "data.csv", Content: csvWithPII}},
	})
	require.NoError(t, err)
	assert.False(t, resp.PolicyAllow)
	assert.Contains(t, resp.DenyReason, "PII")
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

func TestBudgetAlertClaimFire(t *testing.T) {
	// First claim for (t1, daily) succeeds
	assert.True(t, budgetAlertClaimFire("t1", "daily"))

	// Second claim within cooldown fails (deduplication)
	assert.False(t, budgetAlertClaimFire("t1", "daily"))

	// Different tenant or alert type can still claim
	assert.True(t, budgetAlertClaimFire("t2", "daily"))
	assert.True(t, budgetAlertClaimFire("t1", "monthly"))

	// Concurrent callers: only one should get true per (tenant, alertType)
	var wg sync.WaitGroup
	results := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- budgetAlertClaimFire("concurrent-tenant", "daily")
		}()
	}
	wg.Wait()
	close(results)
	var trues int
	for v := range results {
		if v {
			trues++
		}
	}
	assert.Equal(t, 1, trues, "exactly one concurrent caller should claim fire per (tenant, alertType)")
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

// writeAgenticLoopPolicy writes a .talon.yaml with allowed_tools and resource_limits for agentic loop tests.
// When maxToolCallsPerRun is 0 we emit 999 (schema requires >= 1 when set).
func writeAgenticLoopPolicy(t *testing.T, dir, agentName string, maxIterations, maxToolCallsPerRun int, maxCostPerRun float64) string {
	t.Helper()
	if maxIterations <= 0 {
		maxIterations = 10
	}
	m := maxToolCallsPerRun
	if m <= 0 {
		m = 999
	}
	policyYAML := `
agent:
  name: "` + agentName + `"
  version: "1.0.0"
capabilities:
  allowed_tools: ["echo"]
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  resource_limits:
    max_iterations: ` + fmt.Sprintf("%d", maxIterations) + `
    max_tool_calls_per_run: ` + fmt.Sprintf("%d", m) + `
    max_cost_per_run: ` + fmt.Sprintf("%.3f", maxCostPerRun) + `
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	path := filepath.Join(dir, agentName+".talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte(policyYAML), 0o600))
	return path
}

func TestRun_AgenticLoop_SingleIteration(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeAgenticLoopPolicy(t, dir, "loop-agent", 10, 0, 0)

	// First response: one tool call (echo). Second: final text answer.
	mock := &testutil.ToolCallMockProvider{
		Responses: []*llm.Response{
			{
				Content:      "",
				FinishReason: "tool_calls",
				InputTokens:  10,
				OutputTokens: 20,
				Model:        "gpt-4",
				ToolCalls: []llm.ToolCall{
					{ID: "tc-1", Name: "echo", Arguments: map[string]interface{}{"q": "hello"}},
				},
			},
			{
				Content:      "Done.",
				FinishReason: "stop",
				InputTokens:  15,
				OutputTokens: 5,
				Model:        "gpt-4",
			},
		},
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": mock}, nil)

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
		TenantID:   "acme",
		AgentName:  "loop-agent",
		Prompt:     "Use echo then answer.",
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Contains(t, resp.ToolsCalled, "echo")
	assert.Equal(t, "Done.", resp.Response)
	assert.Equal(t, 2, mock.CallCount)
	ev, err := evidenceStore.Get(ctx, resp.EvidenceID)
	require.NoError(t, err)
	steps, err := evidenceStore.ListStepsByCorrelationID(ctx, ev.CorrelationID)
	require.NoError(t, err)
	// One llm_call step, one tool_call step, then second llm_call
	assert.GreaterOrEqual(t, len(steps), 2)
}

func TestRun_AgenticLoop_MultipleIterations(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeAgenticLoopPolicy(t, dir, "multi-agent", 10, 0, 0)

	mock := &testutil.ToolCallMockProvider{
		Responses: []*llm.Response{
			{
				FinishReason: "tool_calls", InputTokens: 10, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{{ID: "tc-1", Name: "echo", Arguments: map[string]interface{}{"a": "1"}}},
			},
			{
				FinishReason: "tool_calls", InputTokens: 15, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{{ID: "tc-2", Name: "echo", Arguments: map[string]interface{}{"b": "2"}}},
			},
			{Content: "Final.", FinishReason: "stop", InputTokens: 15, OutputTokens: 5, Model: "gpt-4"},
		},
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": mock}, nil)

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
		TenantID:   "acme",
		AgentName:  "multi-agent",
		Prompt:     "Echo twice then answer.",
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Len(t, resp.ToolsCalled, 2)
	assert.Equal(t, "Final.", resp.Response)
	assert.Equal(t, 3, mock.CallCount)
	ev, err := evidenceStore.Get(ctx, resp.EvidenceID)
	require.NoError(t, err)
	steps, err := evidenceStore.ListStepsByCorrelationID(ctx, ev.CorrelationID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(steps), 4) // 2 llm_call + 2 tool_call
}

func TestRun_AgenticLoop_MaxIterationsBreak(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeAgenticLoopPolicy(t, dir, "cap-agent", 2, 0, 0) // max 2 iterations

	// Every response returns tool calls; loop should stop after iteration 2.
	mock := &testutil.ToolCallMockProvider{
		Responses: []*llm.Response{
			{
				FinishReason: "tool_calls", InputTokens: 10, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{{ID: "tc-1", Name: "echo", Arguments: map[string]interface{}{}}},
			},
			{
				FinishReason: "tool_calls", InputTokens: 15, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{{ID: "tc-2", Name: "echo", Arguments: map[string]interface{}{}}},
			},
			{
				Content: "Would continue.", FinishReason: "tool_calls", InputTokens: 15, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{{ID: "tc-3", Name: "echo", Arguments: map[string]interface{}{}}},
			},
		},
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": mock}, nil)

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
		TenantID:   "acme",
		AgentName:  "cap-agent",
		Prompt:     "Echo.",
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	// Loop stops at iteration 2; last LLM response (iteration 2) is used as final content
	assert.Equal(t, 2, mock.CallCount)
}

func TestRun_AgenticLoop_ToolDeniedByPolicy(t *testing.T) {
	dir := t.TempDir()
	// Policy allows only "echo"; we'll use a mock that returns a different tool name so it gets denied.
	policyPath := writeAgenticLoopPolicy(t, dir, "deny-tool-agent", 10, 0, 0)

	mock := &testutil.ToolCallMockProvider{
		Responses: []*llm.Response{
			{
				FinishReason: "tool_calls", InputTokens: 10, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{{ID: "tc-1", Name: "forbidden_tool", Arguments: map[string]interface{}{}}},
			},
			{Content: "I see the tool was denied.", FinishReason: "stop", InputTokens: 20, OutputTokens: 10, Model: "gpt-4"},
		},
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": mock}, nil)

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
		TenantID:   "acme",
		AgentName:  "deny-tool-agent",
		Prompt:     "Call forbidden_tool.",
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	// forbidden_tool not in allowed_tools so not executed; error result sent to LLM; loop continues to final answer
	assert.NotContains(t, resp.ToolsCalled, "forbidden_tool")
	assert.Equal(t, "I see the tool was denied.", resp.Response)
	assert.Equal(t, 2, mock.CallCount)
}

func TestRun_AgenticLoop_NonOpenAI_FallsBackToSingleCall(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeAgenticLoopPolicy(t, dir, "anthropic-agent", 10, 0, 0)

	// Provider named "anthropic" -> no agentic loop even with tools and max_iterations
	mock := &testutil.MockProvider{ProviderName: "anthropic", Content: "single call response"}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "claude-3-sonnet"},
		Tier1: &policy.TierConfig{Primary: "claude-3-sonnet"},
		Tier2: &policy.TierConfig{Primary: "claude-3-sonnet"},
	}, map[string]llm.Provider{"anthropic": mock}, nil)

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
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
		TenantID:   "acme",
		AgentName:  "anthropic-agent",
		Prompt:     "Hello",
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Equal(t, "single call response", resp.Response)
	// No agentic loop: one LLM call only (MockProvider doesn't track count; we just assert single response)
	assert.Empty(t, resp.ToolsCalled)
}

func TestRun_AgenticLoop_MaxToolCallsPerRun(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeAgenticLoopPolicy(t, dir, "max-tools-agent", 10, 1, 0) // max 1 tool call per run

	// First response has exactly one tool call; after executing it we hit the limit, so no second iteration.
	mock := &testutil.ToolCallMockProvider{
		Responses: []*llm.Response{
			{
				FinishReason: "tool_calls", InputTokens: 10, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{
					{ID: "tc-1", Name: "echo", Arguments: map[string]interface{}{}},
				},
			},
			{Content: "Done.", FinishReason: "stop", InputTokens: 15, OutputTokens: 5, Model: "gpt-4"},
		},
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": mock}, nil)

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
		TenantID:   "acme",
		AgentName:  "max-tools-agent",
		Prompt:     "Echo twice.",
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.Len(t, resp.ToolsCalled, 1)
}

// TestRun_AgenticLoop_MaxToolCallsPerRun_WithinSingleResponse verifies that when the LLM returns
// multiple tool calls in one response, we enforce max_tool_calls_per_run within that batch
// (not only between iterations). With limit 1 and 5 tool calls in one response, only 1 runs.
func TestRun_AgenticLoop_MaxToolCallsPerRun_WithinSingleResponse(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeAgenticLoopPolicy(t, dir, "max-one-agent", 10, 1, 0) // max 1 tool call per run

	mock := &testutil.ToolCallMockProvider{
		Responses: []*llm.Response{
			{
				FinishReason: "tool_calls", InputTokens: 10, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{
					{ID: "tc-1", Name: "echo", Arguments: map[string]interface{}{"n": float64(1)}},
					{ID: "tc-2", Name: "echo", Arguments: map[string]interface{}{"n": float64(2)}},
					{ID: "tc-3", Name: "echo", Arguments: map[string]interface{}{"n": float64(3)}},
					{ID: "tc-4", Name: "echo", Arguments: map[string]interface{}{"n": float64(4)}},
					{ID: "tc-5", Name: "echo", Arguments: map[string]interface{}{"n": float64(5)}},
				},
			},
			{Content: "Done.", FinishReason: "stop", InputTokens: 15, OutputTokens: 5, Model: "gpt-4"},
		},
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": mock}, nil)

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
		TenantID:   "acme",
		AgentName:  "max-one-agent",
		Prompt:     "Echo five times.",
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	// Only one tool call must have been executed despite five in the response.
	assert.Len(t, resp.ToolsCalled, 1, "max_tool_calls_per_run=1 must cap executions within a single LLM response")
}

func TestRun_AgenticLoop_MaxCostPerRun(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeAgenticLoopPolicy(t, dir, "max-cost-agent", 10, 0, 0.001) // max 0.001 EUR per run

	mock := &testutil.ToolCallMockProvider{
		EstimateCostPerCall: 0.001, // each LLM call costs 0.001; after first call we're at limit
		Responses: []*llm.Response{
			{
				FinishReason: "tool_calls", InputTokens: 10, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{{ID: "tc-1", Name: "echo", Arguments: map[string]interface{}{}}},
			},
			{Content: "Second.", FinishReason: "stop", InputTokens: 15, OutputTokens: 5, Model: "gpt-4"},
		},
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": mock}, nil)

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
		TenantID:   "acme",
		AgentName:  "max-cost-agent",
		Prompt:     "Echo then answer.",
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	// First LLM call costs 0.001; after that cost >= max_cost_per_run so loop stops before second call
	assert.Equal(t, 1, mock.CallCount)
}

// TestRun_AgenticLoop_MidLoopFailureEvidence verifies that when the LLM fails on iteration N > 1,
// the error evidence record includes accumulated Cost, Tokens, and ToolsCalled from prior iterations.
// This ensures CostTotal and /status do not underreport costs for failed agentic runs.
func TestRun_AgenticLoop_MidLoopFailureEvidence(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeAgenticLoopPolicy(t, dir, "midloop-fail-agent", 10, 0, 0)

	errMidLoop := fmt.Errorf("mock LLM failure on second call")
	mock := &testutil.ToolCallMockProvider{
		Responses: []*llm.Response{
			{
				FinishReason: "tool_calls", InputTokens: 10, OutputTokens: 20, Model: "gpt-4",
				ToolCalls: []llm.ToolCall{{ID: "tc-1", Name: "echo", Arguments: map[string]interface{}{"q": "hi"}}},
			},
			// Second call will not be reached; we return ErrOnCall before returning this
			{Content: "Final.", FinishReason: "stop", InputTokens: 15, OutputTokens: 5, Model: "gpt-4"},
		},
		ErrOnCall:           2,
		Err:                 errMidLoop,
		EstimateCostPerCall: 0.002,
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": mock}, nil)

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
		TenantID:   "acme",
		AgentName:  "midloop-fail-agent",
		Prompt:     "Use echo then answer.",
		PolicyPath: policyPath,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, errMidLoop)
	assert.Nil(t, resp)

	// Evidence was still generated for the failed run; it must include cost, tokens, and tools from iteration 1
	from := time.Now().Add(-2 * time.Second)
	to := time.Now().Add(2 * time.Second)
	list, err := evidenceStore.List(ctx, "acme", "midloop-fail-agent", from, to, 5)
	require.NoError(t, err)
	require.NotEmpty(t, list, "expected one evidence record for the failed run")
	ev := list[0]
	assert.NotEmpty(t, ev.Execution.Error, "evidence should record the LLM error")
	assert.Greater(t, ev.Execution.Cost, 0.0, "evidence must include accumulated cost from iteration 1")
	assert.Greater(t, ev.Execution.Tokens.Input, 0, "evidence must include accumulated input tokens")
	assert.Greater(t, ev.Execution.Tokens.Output, 0, "evidence must include accumulated output tokens")
	assert.Contains(t, ev.Execution.ToolsCalled, "echo", "evidence must include tools called before the failure")
}

func TestBuildLLMTools(t *testing.T) {
	dir := t.TempDir()
	cls := classifier.MustNewScanner()
	reg := tools.NewRegistry()
	reg.Register(&echoTool{})

	runnerWithReg := NewRunner(RunnerConfig{
		PolicyDir: dir, Classifier: cls,
		Router:       llm.NewRouter(nil, map[string]llm.Provider{"openai": &testutil.MockProvider{}}, nil),
		Evidence:     mustEvidenceStore(t, dir),
		ToolRegistry: reg,
	})
	runnerNoReg := NewRunner(RunnerConfig{
		PolicyDir: dir, Classifier: cls,
		Router:   llm.NewRouter(nil, map[string]llm.Provider{"openai": &testutil.MockProvider{}}, nil),
		Evidence: mustEvidenceStore(t, dir),
	})

	tests := []struct {
		name     string
		r        *Runner
		pol      *policy.Policy
		wantNil  bool
		wantLen  int
		wantName string
	}{
		{"nil registry", runnerNoReg, &policy.Policy{Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"echo"}}}, true, 0, ""},
		{"nil capabilities", runnerWithReg, &policy.Policy{}, true, 0, ""},
		{"empty allowed_tools", runnerWithReg, &policy.Policy{Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{}}}, true, 0, ""},
		{"matching tools", runnerWithReg, &policy.Policy{Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"echo"}}}, false, 1, "echo"},
		{"non-matching tools", runnerWithReg, &policy.Policy{Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"other"}}}, true, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.buildLLMTools(tt.pol)
			if tt.wantNil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Len(t, got, tt.wantLen)
				if tt.wantName != "" {
					assert.Equal(t, tt.wantName, got[0].Name)
				}
			}
		})
	}
}

func mustEvidenceStore(t *testing.T, dir string) *evidence.Store {
	t.Helper()
	s, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"short unchanged", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"long truncated", "hello world", 5, "hello..."},
		{"empty", "", 5, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evidence.TruncateForSummary(tt.s, tt.maxLen)
			assert.Equal(t, tt.want, got)
		})
	}
}

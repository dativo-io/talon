package agent

import (
	"context"
	"os"
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
	"github.com/dativo-io/talon/internal/policy"
	talonprompt "github.com/dativo-io/talon/internal/prompt"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// TestPromptStore_RedactedInput_StoresRedactedPrompt verifies that when input PII
// redaction is active and include_prompts=true, the prompt version store persists
// the redacted (post-PII-removal) prompt — not the original.
// This aligns with GDPR Art. 5(1)(c) data minimization.
func TestPromptStore_RedactedInput_StoresRedactedPrompt(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteInputRedactWithAuditPolicyFile(t, dir, "test-agent", false)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })
	promptStore, err := talonprompt.NewStore(filepath.Join(dir, "prompts.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = promptStore.Close() })

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Response about the person"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	runner := NewRunner(RunnerConfig{
		PolicyDir:   dir,
		Classifier:  classifier.MustNewScanner(),
		AttScanner:  attachment.MustNewScanner(),
		Extractor:   attachment.NewExtractor(10),
		Router:      router,
		Secrets:     secretsStore,
		Evidence:    evidenceStore,
		PromptStore: promptStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	originalPrompt := "Please summarise the file for user@company.eu"

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         originalPrompt,
		InvocationType: "manual",
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow, "request should be allowed")

	versions, err := promptStore.List(ctx, "default", "test-agent", 10)
	require.NoError(t, err)
	require.Len(t, versions, 1, "exactly one prompt version should be stored")

	stored := versions[0].Content
	assert.NotContains(t, stored, "user@company.eu",
		"stored prompt must NOT contain original PII (data minimization)")
	assert.True(t, strings.Contains(stored, "[EMAIL") || strings.Contains(stored, "[REDACTED"),
		"stored prompt should contain a redacted placeholder, got: %s", stored)
}

// TestPromptStore_IncludeOriginalPrompts_StoresBoth verifies that when
// include_original_prompts=true, BOTH the redacted and original prompts are persisted.
func TestPromptStore_IncludeOriginalPrompts_StoresBoth(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteInputRedactWithAuditPolicyFile(t, dir, "test-agent", true)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })
	promptStore, err := talonprompt.NewStore(filepath.Join(dir, "prompts.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = promptStore.Close() })

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Response about the person"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	runner := NewRunner(RunnerConfig{
		PolicyDir:   dir,
		Classifier:  classifier.MustNewScanner(),
		AttScanner:  attachment.MustNewScanner(),
		Extractor:   attachment.NewExtractor(10),
		Router:      router,
		Secrets:     secretsStore,
		Evidence:    evidenceStore,
		PromptStore: promptStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	originalPrompt := "Please summarise the file for user@company.eu"

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         originalPrompt,
		InvocationType: "manual",
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)

	versions, err := promptStore.List(ctx, "default", "test-agent", 10)
	require.NoError(t, err)
	require.Len(t, versions, 2, "both redacted and original prompts should be stored")

	var hasRedacted, hasOriginal bool
	for _, v := range versions {
		if v.Content == originalPrompt {
			hasOriginal = true
		}
		if !strings.Contains(v.Content, "user@company.eu") && v.Content != originalPrompt {
			hasRedacted = true
		}
	}
	assert.True(t, hasOriginal,
		"original (pre-redaction) prompt should be stored when include_original_prompts=true")
	assert.True(t, hasRedacted,
		"redacted prompt should also be stored")
}

// TestPromptStore_NoRedaction_StoresOriginal verifies that when input redaction is
// NOT active, the original prompt is stored (no difference between original and redacted).
func TestPromptStore_NoRedaction_StoresOriginal(t *testing.T) {
	dir := t.TempDir()
	policyContent := `
agent:
  name: "test-agent"
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
audit:
  log_level: detailed
  include_prompts: true
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test-agent.talon.yaml"), []byte(policyContent), 0o600))

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })
	promptStore, err := talonprompt.NewStore(filepath.Join(dir, "prompts.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = promptStore.Close() })

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Hello!"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	runner := NewRunner(RunnerConfig{
		PolicyDir:   dir,
		Classifier:  classifier.MustNewScanner(),
		AttScanner:  attachment.MustNewScanner(),
		Extractor:   attachment.NewExtractor(10),
		Router:      router,
		Secrets:     secretsStore,
		Evidence:    evidenceStore,
		PromptStore: promptStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         "What is the weather in Berlin?",
		InvocationType: "manual",
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)

	versions, err := promptStore.List(ctx, "default", "test-agent", 10)
	require.NoError(t, err)
	require.Len(t, versions, 1)
	assert.Equal(t, "What is the weather in Berlin?", versions[0].Content,
		"when no redaction occurs, original prompt is stored")
}

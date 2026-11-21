package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestRun_OutputPII_BlockOnPII(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteOutputScanPolicyFile(t, dir, "test-agent", false, true)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Please contact user@company.eu for details"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	runner := NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     router,
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         "show me contact info",
		InvocationType: "manual",
	})
	require.NoError(t, err)
	assert.False(t, resp.PolicyAllow, "output containing PII must be blocked when output_scan + block_on_pii")
	assert.Contains(t, resp.DenyReason, "Output contains PII")
}

func TestRun_OutputPII_RedactPII(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteOutputScanPolicyFile(t, dir, "test-agent", true, false)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "Please contact user@company.eu for details"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	runner := NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     router,
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         "show me contact info",
		InvocationType: "manual",
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow, "redact_pii should allow the response through")
	assert.NotContains(t, resp.Response, "user@company.eu", "PII must be redacted from output")
}

// --- Category 3: Evidence on Early Termination ---

func TestRun_CircuitBreakerDeny_RecordsEvidence(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteTestPolicyFile(t, dir, "test-agent")

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	providers := map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "ok"},
	}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	cb := NewCircuitBreaker(1, time.Minute)
	cb.RecordPolicyDenial("default", "test-agent")
	cb.RecordPolicyDenial("default", "test-agent")

	runner := NewRunner(RunnerConfig{
		PolicyDir:      dir,
		Classifier:     classifier.MustNewScanner(),
		AttScanner:     attachment.MustNewScanner(),
		Extractor:      attachment.NewExtractor(10),
		Router:         router,
		Secrets:        secretsStore,
		Evidence:       evidenceStore,
		CircuitBreaker: cb,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         "hello",
		InvocationType: "manual",
	})
	require.NoError(t, err)
	assert.False(t, resp.PolicyAllow, "circuit breaker should deny")

	from := time.Now().Add(-time.Minute)
	to := time.Now().Add(time.Minute)
	records, err := evidenceStore.List(ctx, "default", "", from, to, 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(records), 1, "circuit breaker deny must produce an evidence record")
}

func TestRun_PolicyLoadFailure_RecordsEvidence(t *testing.T) {
	dir := t.TempDir()
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Evidence:   evidenceStore,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "nonexistent-agent",
		Prompt:         "hello",
		InvocationType: "manual",
	})
	require.Error(t, err, "missing policy file should cause error")

	from := time.Now().Add(-time.Minute)
	to2 := time.Now().Add(time.Minute)
	records, err := evidenceStore.List(ctx, "default", "", from, to2, 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(records), 1, "policy load failure must produce an evidence record")
}

// --- Category 4: Tool Result Sandboxing ---

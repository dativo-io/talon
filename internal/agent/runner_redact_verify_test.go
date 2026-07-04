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
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// sloppyRedactorFacade simulates a probabilistic external engine whose
// redaction is best-effort: Analyze reliably detects the marker email, but
// RedactText returns the text UNCHANGED. Only the post-redaction VerifyEgress
// pass can catch this — which is exactly what these tests prove the runner does.
type sloppyRedactorFacade struct{}

const sloppyMarker = "hans.mueller@example.de"

func (f *sloppyRedactorFacade) Analyze(_ context.Context, text string) (*classifier.Classification, error) {
	idx := strings.Index(text, sloppyMarker)
	if idx < 0 {
		return &classifier.Classification{Entities: []classifier.PIIEntity{}}, nil
	}
	entities := []classifier.PIIEntity{{
		Type: "email", Value: sloppyMarker, Position: idx, Confidence: 0.9, Sensitivity: 1,
	}}
	return &classifier.Classification{HasPII: true, Entities: entities, Tier: classifier.DetermineTier(entities)}, nil
}

func (f *sloppyRedactorFacade) Detector() string { return "sloppy-engine" }

func (f *sloppyRedactorFacade) RedactText(_ context.Context, text string) (string, error) {
	return text, nil // "redacts" nothing — the failure mode under test
}

func (f *sloppyRedactorFacade) VerifyEgress(ctx context.Context, text string) error {
	return classifier.NewRedactGuard(f).Verify(ctx, text)
}

var _ classifier.Facade = (*sloppyRedactorFacade)(nil)

func setupRunnerWithClassifier(t *testing.T, dir string, provider llm.Provider, cls classifier.Facade) *Runner {
	t.Helper()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	providers := map[string]llm.Provider{"openai": provider}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	return NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: cls,
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     router,
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})
}

func TestRun_InputRedactionVerified_ResidualPIIFailsClosed(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteInputOutputRedactPolicyFile(t, dir, "test-agent", true, false)

	capProvider := &testutil.CapturingMockProvider{
		MockProvider: testutil.MockProvider{ProviderName: "openai", Content: "irrelevant"},
	}
	runner := setupRunnerWithClassifier(t, dir, capProvider, &sloppyRedactorFacade{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         "Please contact " + sloppyMarker + " today",
		InvocationType: "manual",
	})
	require.Error(t, err, "residual PII after input redaction must terminate the run fail-closed")
	assert.Contains(t, err.Error(), "fail-closed")
	assert.Empty(t, capProvider.GetLastPrompt(), "the unverified prompt must never reach the LLM")
}

func TestRun_OutputRedactionVerified_ResidualPIIDenied(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteInputOutputRedactPolicyFile(t, dir, "test-agent", false, true)

	provider := &testutil.MockProvider{ProviderName: "openai", Content: "Reach out to " + sloppyMarker + " for details"}
	runner := setupRunnerWithClassifier(t, dir, provider, &sloppyRedactorFacade{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         "clean prompt",
		InvocationType: "manual",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.PolicyAllow, "residual PII after output redaction must deny the run")
	assert.Contains(t, resp.DenyReason, "remains after redaction")
	assert.NotContains(t, resp.Response, sloppyMarker, "unverified output must not be surfaced")
}

func TestRun_RedactionVerified_BuiltinScannerStillPasses(t *testing.T) {
	// Regression guard: with the built-in engine, redaction produces clean
	// placeholders and the new verify pass must not reject legitimate runs.
	dir := t.TempDir()
	testutil.WriteInputOutputRedactPolicyFile(t, dir, "test-agent", true, true)

	capProvider := &testutil.CapturingMockProvider{
		MockProvider: testutil.MockProvider{ProviderName: "openai", Content: "Contact " + sloppyMarker + " for info"},
	}
	runner := setupRunner(t, dir, capProvider)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         piiPrompt,
		InvocationType: "manual",
	})
	require.NoError(t, err)
	assert.True(t, resp.PolicyAllow)
	assert.NotContains(t, resp.Response, sloppyMarker)
}

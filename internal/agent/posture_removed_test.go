package agent

import (
	"context"
	"path/filepath"
	"sync/atomic"
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

// countingProvider wraps the mock provider with a dispatch counter so a test
// can prove the provider was never reached (AGENTS.md: a denial response alone
// is not preventive-control proof).
type countingProvider struct {
	*testutil.MockProvider
	calls atomic.Int64
}

func (c *countingProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	c.calls.Add(1)
	return c.MockProvider.Generate(ctx, req)
}

// TestRun_PolicyDeny_ZeroProviderDispatch pins #442 for the native runtime:
// an OPA deny is authoritative. The removed audit.observation_only posture
// used to forward exactly this run to the provider.
func TestRun_PolicyDeny_ZeroProviderDispatch(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteStrictPolicyFile(t, dir, "deny-agent")

	prov := &countingProvider{MockProvider: &testutil.MockProvider{ProviderName: "openai", Content: "must not run"}}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, map[string]llm.Provider{"openai": prov}, nil)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	runner := NewRunner(RunnerConfig{
		PolicyDir: dir, DefaultPolicyPath: policyPath,
		Classifier: classifier.MustNewScanner(), AttScanner: attachment.MustNewScanner(),
		Extractor: attachment.NewExtractor(10), Router: router, Secrets: secretsStore, Evidence: evidenceStore,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := runner.Run(ctx, &RunRequest{TenantID: "acme", AgentName: "deny-agent", Prompt: "expensive query", InvocationType: "manual", PolicyPath: policyPath})
	require.NoError(t, err)
	assert.False(t, resp.PolicyAllow)
	assert.NotEmpty(t, resp.DenyReason)
	assert.Equal(t, int64(0), prov.calls.Load(), "a denied run must never reach the provider")

	records, err := evidenceStore.List(ctx, "acme", "deny-agent", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	for _, ev := range records {
		assert.False(t, ev.PolicyDecision.Allowed)
		assert.False(t, ev.ObservationModeOverride, "new evidence must not carry the legacy override flag")
		assert.Empty(t, ev.ShadowViolations)
	}
}

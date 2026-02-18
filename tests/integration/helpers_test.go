//go:build integration

package integration

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// WriteTestPolicy creates a minimal valid .talon.yaml in the given dir and returns its path.
func WriteTestPolicy(t *testing.T, dir, name string) string {
	return testutil.WriteTestPolicyFile(t, dir, name)
}

// WriteStrictPolicy creates a .talon.yaml that denies high-cost requests.
func WriteStrictPolicy(t *testing.T, dir, name string) string {
	return testutil.WriteStrictPolicyFile(t, dir, name)
}

// SetupRunner creates a Runner with real SQLite stores and classifier, for integration tests.
func SetupRunner(t *testing.T, policyDir string, providers map[string]llm.Provider, routingCfg *policy.ModelRoutingConfig) *agent.Runner {
	t.Helper()

	dir := t.TempDir()

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(10)
	router := llm.NewRouter(routingCfg, providers, nil)

	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secretsStore.Close() })

	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { evidenceStore.Close() })

	return agent.NewRunner(agent.RunnerConfig{
		PolicyDir:   policyDir,
		Classifier:  cls,
		AttScanner:  attScanner,
		Extractor:   extractor,
		Router:      router,
		Secrets:     secretsStore,
		Evidence:    evidenceStore,
	})
}

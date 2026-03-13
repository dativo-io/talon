//go:build integration

package integration

import (
	"context"
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
	"github.com/dativo-io/talon/internal/session"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestRunner_AssignsSessionIDToEvidence(t *testing.T) {
	dir := t.TempDir()
	policyPath := WriteTestPolicy(t, dir, "test-agent")

	evStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	defer evStore.Close()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	defer secretsStore.Close()
	require.NoError(t, secretsStore.Set(context.Background(), "openai-api-key", []byte("test-key"), secrets.ACL{
		Tenants: []string{"acme"},
		Agents:  []string{"test-agent"},
	}))
	sessionStore, err := session.NewStore(filepath.Join(dir, "evidence.db"))
	require.NoError(t, err)
	defer sessionStore.Close()

	pol, err := policy.LoadPolicy(context.Background(), policyPath, false, dir)
	require.NoError(t, err)
	router := llm.NewRouter(pol.Policies.ModelRouting, map[string]llm.Provider{
		"openai": &testutil.MockProvider{ProviderName: "openai", Content: "ok"},
	}, nil)

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:    dir,
		Classifier:   classifier.MustNewScanner(),
		AttScanner:   attachment.MustNewScanner(),
		Extractor:    attachment.NewExtractor(5),
		Router:       router,
		Secrets:      secretsStore,
		Evidence:     evStore,
		SessionStore: sessionStore,
	})

	resp, err := runner.Run(context.Background(), &agent.RunRequest{
		TenantID:       "acme",
		AgentName:      "test-agent",
		Prompt:         "hello",
		InvocationType: "manual",
		PolicyPath:     policyPath,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.SessionID)

	ev, err := evStore.Get(context.Background(), resp.EvidenceID)
	require.NoError(t, err)
	require.Equal(t, resp.SessionID, ev.SessionID)
}

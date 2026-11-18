package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

var printedKeyRe = regexp.MustCompile(`talon_uc_[0-9a-f]{48}`)

func setupAddFleet(t *testing.T) (cfg *config.Config, agentsDir string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("TALON_SIGNING_KEY", testutil.TestSigningKey)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("TALON_GATEWAY_CONFIG", filepath.Join(dir, "absent.talon.config.yaml"))
	agentsDir = filepath.Join(dir, "agents")
	t.Setenv("TALON_AGENTS_DIR", agentsDir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "data"), 0o700))
	d := filepath.Join(agentsDir, "support")
	require.NoError(t, os.MkdirAll(d, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte("agent:\n  name: support\n  version: \"1.0.0\"\n  key:\n    secret_name: support-talon-key\npolicies:\n  cost_limits: {}\n"), 0o600))
	cfg, err := config.Load()
	require.NoError(t, err)
	return cfg, agentsDir
}

func resetAgentsAddFlags(t *testing.T) {
	t.Helper()
	agentsAddTenant, agentsAddDescription, agentsAddOwner, agentsAddUseExisting, agentsAddDryRun = "default", "", "", false, false
	t.Cleanup(func() {
		agentsAddTenant, agentsAddDescription, agentsAddOwner, agentsAddUseExisting, agentsAddDryRun = "default", "", "", false, false
	})
}

func vaultValue(t *testing.T, cfg *config.Config, name string) (string, bool) {
	t.Helper()
	store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	require.NoError(t, err)
	defer store.Close()
	ok, err := secretExists(context.Background(), store, name)
	require.NoError(t, err)
	if !ok {
		return "", false
	}
	s, err := store.Get(context.Background(), name, "default", name)
	require.NoError(t, err)
	return string(s.Value), true
}

func TestAgentsAdd_FirstAndSecondUseCase(t *testing.T) {
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	ctx := context.Background()

	var out bytes.Buffer
	agentsAddTenant, agentsAddOwner = "acme", "support-ops@acme.example"
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
	key1 := printedKeyRe.FindString(out.String())
	require.NotEmpty(t, key1, out.String())
	require.Contains(t, out.String(), "talon agents show refund-bot --effective")
	stored, ok := vaultValue(t, cfg, "refund-bot-talon-key")
	require.True(t, ok)
	require.Equal(t, key1, stored, "the printed key is the stored key")

	content, err := os.ReadFile(filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml"))
	require.NoError(t, err)
	require.Contains(t, string(content), `tenant_id: "acme"`)
	require.Contains(t, string(content), `secret_name: "refund-bot-talon-key"`)
	require.Contains(t, string(content), "cost_limits: {}", "no budget of its own: the company defaults apply")
	require.NotContains(t, string(content), key1, "the key never lands in the file")

	out.Reset()
	agentsAddTenant, agentsAddOwner = "acme", ""
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "hr-copilot"))
	key2 := printedKeyRe.FindString(out.String())
	require.NotEmpty(t, key2)
	require.NotEqual(t, key1, key2)

	scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err, "the fleet validates with both new use cases")
	names := []string{}
	for i := range scan.Agents {
		names = append(names, scan.Agents[i].Name)
	}
	require.ElementsMatch(t, []string{"support", "refund-bot", "hr-copilot"}, names)
}

func TestAgentsAdd_RefusesWithoutWriting(t *testing.T) {
	ctx := context.Background()

	t.Run("an existing name", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		before, _ := os.ReadFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"))
		err := runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "support")
		require.ErrorContains(t, err, "already registered")
		after, _ := os.ReadFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"))
		require.Equal(t, before, after)
		_, ok := vaultValue(t, cfg, "support-talon-key")
		require.False(t, ok, "no key minted for a refused registration")
	})
	t.Run("an existing key is never regenerated", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		require.NoError(t, store.Set(ctx, "refund-bot-talon-key", []byte("in-use-key-0001"), secrets.ACL{}))
		require.NoError(t, store.Close())
		err = runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot")
		require.ErrorContains(t, err, "already exists")
		_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
		require.True(t, os.IsNotExist(statErr))
		v, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		require.Equal(t, "in-use-key-0001", v)

		// Binding it deliberately: no key generated or printed, value unchanged.
		agentsAddUseExisting = true
		var out bytes.Buffer
		require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
		require.Empty(t, printedKeyRe.FindString(out.String()))
		require.NotContains(t, out.String(), "in-use-key-0001")
		v, _ = vaultValue(t, cfg, "refund-bot-talon-key")
		require.Equal(t, "in-use-key-0001", v)
	})
	t.Run("an invalid existing fleet", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		bad := filepath.Join(agentsDir, "broken")
		require.NoError(t, os.MkdirAll(bad, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(bad, "agent.talon.yaml"), []byte("agent:\n  name: broken\n  typo_field: 1\n"), 0o600))
		err := runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot")
		require.ErrorContains(t, err, "does not validate")
		_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
		require.True(t, os.IsNotExist(statErr))
		_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
		require.False(t, ok)
	})
	t.Run("no agents_dir", func(t *testing.T) {
		cfg, _ := setupAddFleet(t)
		resetAgentsAddFlags(t)
		cfg.AgentsDir = ""
		require.ErrorContains(t, runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot"), "agents_dir is not configured")
	})
	t.Run("an invalid name", func(t *testing.T) {
		cfg, _ := setupAddFleet(t)
		resetAgentsAddFlags(t)
		for _, n := range []string{"Refund", "../escape", "a b", "", "-x"} {
			require.ErrorContains(t, runAgentsAdd(ctx, &bytes.Buffer{}, cfg, n), "invalid use case name", n)
		}
	})
	t.Run("an invalid company policy", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		gw := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(gw, []byte("gateway:\n  enabled: true\n  not_a_key: 1\n"), 0o600))
		t.Setenv("TALON_GATEWAY_CONFIG", gw)
		require.ErrorContains(t, runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot"), "present but invalid")
		_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
		require.True(t, os.IsNotExist(statErr))
	})
}

// A failure after the key was stored removes that key again: no orphaned
// credential, no half-registered use case.
func TestAgentsAdd_FailedWriteRemovesTheNewKey(t *testing.T) {
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	// A plain file where the use case's directory must go: MkdirAll fails
	// after the key was stored.
	require.NoError(t, os.WriteFile(filepath.Join(agentsDir, "refund-bot"), []byte("not a directory"), 0o600))
	err := runAgentsAdd(context.Background(), &bytes.Buffer{}, cfg, "refund-bot")
	require.Error(t, err)
	_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
	require.False(t, ok, "the key stored before the failed write is removed")
}

func TestAgentsAdd_DryRunWritesNothing(t *testing.T) {
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddDryRun = true
	var out bytes.Buffer
	require.NoError(t, runAgentsAdd(context.Background(), &out, cfg, "refund-bot"))
	require.Contains(t, out.String(), "Dry run")
	require.Empty(t, printedKeyRe.FindString(out.String()))
	_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
	require.True(t, os.IsNotExist(statErr))
	_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
	require.False(t, ok)
}

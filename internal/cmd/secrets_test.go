package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/spf13/cobra"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/secrets"
)

func TestSecretsCmd_HasSubcommands(t *testing.T) {
	expected := []string{"set", "list", "audit", "rotate", "delete"}
	registered := make(map[string]bool)
	for _, cmd := range secretsCmd.Commands() {
		registered[cmd.Name()] = true
	}
	for _, name := range expected {
		assert.True(t, registered[name], "secrets subcommand %q should be registered", name)
	}
}

func TestSecretsSetCmd_RequiresTwoArgs(t *testing.T) {
	assert.NotNil(t, secretsSetCmd.Args)
	err := secretsSetCmd.Args(secretsSetCmd, []string{"one"})
	assert.Error(t, err)
	err = secretsSetCmd.Args(secretsSetCmd, []string{"name", "value"})
	assert.NoError(t, err)
}

func TestSecretsRotateCmd_RequiresOneArg(t *testing.T) {
	assert.NotNil(t, secretsRotateCmd.Args)
	err := secretsRotateCmd.Args(secretsRotateCmd, []string{})
	assert.Error(t, err)
	err = secretsRotateCmd.Args(secretsRotateCmd, []string{"key-name"})
	assert.NoError(t, err)
}

func TestSecretsSetCmd_UseLine(t *testing.T) {
	assert.Equal(t, "set [name] [value]", secretsSetCmd.Use)
}

func TestSecretsListCmd_UseLine(t *testing.T) {
	assert.Equal(t, "list", secretsListCmd.Use)
}

func TestSecretsAuditCmd_UseLine(t *testing.T) {
	assert.Equal(t, "audit", secretsAuditCmd.Use)
}

func TestSecretsRotateCmd_UseLine(t *testing.T) {
	assert.Equal(t, "rotate [name]", secretsRotateCmd.Use)
}

func TestSecretsSetCmd_HasACLFlags(t *testing.T) {
	assert.NotNil(t, secretsSetCmd.Flags().Lookup("tenant"), "--tenant flag should be registered")
	assert.NotNil(t, secretsSetCmd.Flags().Lookup("agent"), "--agent flag should be registered")
}

// setSecretViaCLI runs the secrets set handler with the given ACL flag values
// against a temp data dir and returns the opened store for assertions.
func setSecretViaCLI(t *testing.T, tenants, agents []string) *secrets.SecretStore {
	t.Helper()
	t.Setenv("TALON_DATA_DIR", t.TempDir())
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")

	secretsSetTenants, secretsSetAgents = tenants, agents
	t.Cleanup(func() { secretsSetTenants, secretsSetAgents = nil, nil })

	secretsSetCmd.SetContext(context.Background())
	require.NoError(t, secretsSet(secretsSetCmd, []string{"provider-key", "v1"}))

	store, err := openSecretsStore()
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}

func TestSecretsSet_ScopedACL(t *testing.T) {
	store := setSecretViaCLI(t, []string{"acme"}, nil)
	ctx := context.Background()

	sec, err := store.Get(ctx, "provider-key", "acme", "any-agent")
	require.NoError(t, err, "listed tenant must be allowed")
	require.Equal(t, "v1", string(sec.Value))

	_, err = store.Get(ctx, "provider-key", "globex", "any-agent")
	require.Error(t, err, "tenant outside the ACL must be denied (#237)")
}

func TestSecretsSet_AgentScopedACL(t *testing.T) {
	store := setSecretViaCLI(t, nil, []string{"sales-*"})
	ctx := context.Background()

	_, err := store.Get(ctx, "provider-key", "any-tenant", "sales-bot")
	require.NoError(t, err, "glob-matched agent must be allowed")

	_, err = store.Get(ctx, "provider-key", "any-tenant", "ops-bot")
	require.Error(t, err, "agent outside the ACL must be denied (#237)")
}

func TestSecretsSet_DefaultAllowAllWithNotice(t *testing.T) {
	var stderr bytes.Buffer
	secretsSetCmd.SetErr(&stderr)
	t.Cleanup(func() { secretsSetCmd.SetErr(nil) })

	store := setSecretViaCLI(t, nil, nil)
	ctx := context.Background()

	_, err := store.Get(ctx, "provider-key", "any-tenant", "any-agent")
	require.NoError(t, err, "empty ACL keeps allow-all semantics")
	assert.Contains(t, stderr.String(), "allow-all ACL",
		"unscoped set must print the multi-tenant notice (#237)")
}

func TestOpenSecretsStore_DefaultKey(t *testing.T) {
	store, err := openSecretsStore()
	require.NoError(t, err)
	defer store.Close()
}

func TestOpenSecretsStore_CustomKey(t *testing.T) {
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	store, err := openSecretsStore()
	require.NoError(t, err)
	defer store.Close()
}

func TestOpenSecretsStore_InvalidKeyLength(t *testing.T) {
	t.Setenv("TALON_SECRETS_KEY", "too-short")
	_, err := openSecretsStore()
	require.Error(t, err)
}

// TestNoRunlessParentCommands is the #378 invariant: cobra prints help and
// exits 0 when a runless parent gets an unknown subcommand, so a typo'd
// destructive command looks successful to scripts. After hardening, every
// parent in the tree must be runnable, and unknown subcommands must error.
func TestNoRunlessParentCommands(t *testing.T) {
	hardenParentCommands(rootCmd)

	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.HasSubCommands() {
			assert.True(t, c.Runnable(),
				"parent command %q must be runnable so unknown subcommands exit non-zero (#378)", c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

func TestParentCommand_UnknownSubcommandErrors(t *testing.T) {
	hardenParentCommands(rootCmd)

	err := secretsCmd.RunE(secretsCmd, []string{"frobnicate"})
	require.Error(t, err, "unknown subcommand must exit non-zero (#378)")
	assert.Contains(t, err.Error(), "frobnicate")
	assert.Contains(t, err.Error(), "talon secrets")

	// Bare invocation keeps the help behavior (exit 0).
	secretsCmd.SetOut(&bytes.Buffer{})
	assert.NoError(t, secretsCmd.RunE(secretsCmd, nil))
}

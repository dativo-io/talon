package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretsCmd_HasSubcommands(t *testing.T) {
	expected := []string{"set", "list", "audit", "rotate"}
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

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditCmd_HasSubcommands(t *testing.T) {
	expected := []string{"list", "verify"}
	registered := make(map[string]bool)
	for _, cmd := range auditCmd.Commands() {
		registered[cmd.Name()] = true
	}
	for _, name := range expected {
		assert.True(t, registered[name], "audit subcommand %q should be registered", name)
	}
}

func TestAuditVerifyCmd_RequiresOneArg(t *testing.T) {
	assert.NotNil(t, auditVerifyCmd.Args)
	err := auditVerifyCmd.Args(auditVerifyCmd, []string{})
	assert.Error(t, err)
	err = auditVerifyCmd.Args(auditVerifyCmd, []string{"ev_123"})
	assert.NoError(t, err)
}

func TestAuditListCmd_Flags(t *testing.T) {
	flags := []string{"tenant", "agent", "limit"}
	for _, name := range flags {
		flag := auditListCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "audit list flag %q should be registered", name)
	}
}

func TestAuditListCmd_LimitDefault(t *testing.T) {
	flag := auditListCmd.Flags().Lookup("limit")
	require.NotNil(t, flag)
	assert.Equal(t, "20", flag.DefValue)
}

func TestOpenEvidenceStore_DefaultKey(t *testing.T) {
	home, _ := os.UserHomeDir()
	talonDir := filepath.Join(home, ".talon")
	_ = os.MkdirAll(talonDir, 0o755)

	store, err := openEvidenceStore()
	require.NoError(t, err)
	defer store.Close()
}

func TestOpenEvidenceStore_CustomKey(t *testing.T) {
	home, _ := os.UserHomeDir()
	talonDir := filepath.Join(home, ".talon")
	_ = os.MkdirAll(talonDir, 0o755)

	t.Setenv("TALON_SIGNING_KEY", "custom-key-for-evidence-signing!")
	store, err := openEvidenceStore()
	require.NoError(t, err)
	defer store.Close()
}

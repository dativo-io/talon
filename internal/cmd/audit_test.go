package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
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

func TestRenderAuditList(t *testing.T) {
	var buf bytes.Buffer
	ts := time.Date(2025, 2, 18, 10, 0, 0, 0, time.UTC)
	index := []evidence.Index{
		{ID: "ev_1", Timestamp: ts, TenantID: "acme", AgentID: "agent", ModelUsed: "gpt-4", CostEUR: 0.01, DurationMS: 100, Allowed: true, HasError: false},
		{ID: "ev_2", Timestamp: ts, TenantID: "acme", AgentID: "agent", ModelUsed: "gpt-4", CostEUR: 0.02, DurationMS: 200, Allowed: false, HasError: true},
	}
	renderAuditList(&buf, index)
	out := buf.String()
	assert.Contains(t, out, "Evidence Records (showing 2)")
	assert.Contains(t, out, "ev_1")
	assert.Contains(t, out, "ev_2")
	assert.Contains(t, out, "acme")
	assert.Contains(t, out, "0.0100")
	assert.Contains(t, out, "0.0200")
}

func TestRenderVerifyResult(t *testing.T) {
	var bufValid, bufInvalid bytes.Buffer
	renderVerifyResult(&bufValid, "ev_abc", true)
	renderVerifyResult(&bufInvalid, "ev_xyz", false)
	assert.Contains(t, bufValid.String(), "VALID")
	assert.Contains(t, bufValid.String(), "ev_abc")
	assert.Contains(t, bufInvalid.String(), "INVALID")
	assert.Contains(t, bufInvalid.String(), "ev_xyz")
}

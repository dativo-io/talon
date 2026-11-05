package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/testutil/acme"
)

// PR #526 review P2: the offline commands resolve the company action policy
// exactly as serve does — absent file: none; present but invalid: an error,
// never "validated without it".
func TestOfflineServeContext_CompanyPolicyResolution(t *testing.T) {
	t.Run("absent gateway config → no company policy, no error", func(t *testing.T) {
		t.Setenv("TALON_GATEWAY_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
		osc, err := offlineServeContextFromGateway()
		require.NoError(t, err)
		require.Nil(t, osc.Company)
	})
	t.Run("valid company policy → compiled into the offline context", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(p, []byte(acme.CompanyPolicyYAML(1)), 0o600))
		t.Setenv("TALON_GATEWAY_CONFIG", p)
		osc, err := offlineServeContextFromGateway()
		require.NoError(t, err)
		require.NotNil(t, osc.Company)
		require.Equal(t, []string{acme.DeleteAction}, osc.Company.ForbiddenActions)
		require.Contains(t, osc.Company.Rules, acme.CompanyRuleID)
	})
	t.Run("present but invalid → error naming the file (fail closed)", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(p, []byte(acme.CompanyPolicyYAMLMalformed), 0o600))
		t.Setenv("TALON_GATEWAY_CONFIG", p)
		_, err := offlineServeContextFromGateway()
		require.Error(t, err)
		require.Contains(t, err.Error(), p)
		require.Contains(t, err.Error(), "present but invalid")
	})
	t.Run("talon validate exits non-zero on a present but invalid company policy", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "talon.config.yaml")
		require.NoError(t, os.WriteFile(p, []byte(acme.CompanyPolicyYAMLMalformed), 0o600))
		agentPath := filepath.Join(dir, "agent.talon.yaml")
		require.NoError(t, os.WriteFile(agentPath, []byte(acme.AgentYAML(acme.Support, "http://127.0.0.1:1")), 0o600))
		t.Setenv("TALON_GATEWAY_CONFIG", p)
		t.Setenv("TALON_DATA_DIR", dir)
		validateFile, validateDir = agentPath, ""
		rootCmd.SetArgs([]string{"validate", "-f", agentPath})
		err := rootCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "present but invalid")
	})
}

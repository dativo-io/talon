package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoctorCmd_ShowsConfigChecks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	var buf bytes.Buffer
	doctorCmd.SetOut(&buf)
	doctorCmd.SetErr(&buf)
	doctorCmd.SetArgs(nil)
	rootCmd.SetArgs([]string{"doctor"})

	err := rootCmd.Execute()

	out := buf.String()
	assert.Contains(t, out, "data_dir_writable")
	assert.Contains(t, out, dir)

	// Without policy file and without LLM key, doctor fails
	if err != nil {
		assert.Contains(t, err.Error(), "doctor checks failed")
		return
	}
}

func TestDoctorCmd_PassesWithPolicyAndEnvKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("OPENAI_API_KEY", "sk-test-key-for-doctor")

	policyPath := filepath.Join(dir, "agent.talon.yaml")
	policyYAML := `
agent:
  name: test
  description: test
  version: "1.0.0"
  model_tier: 0
policies:
  cost_limits: {}
  model_routing:
    tier_0:
      primary: gpt-4o-mini
      location: any
`
	require.NoError(t, os.WriteFile(policyPath, []byte(policyYAML), 0o600))

	prevWd, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prevWd) })

	var buf bytes.Buffer
	doctorCmd.SetOut(&buf)
	doctorCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"doctor", "--skip-upstream"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "data_dir_writable")
	assert.Contains(t, out, "policy_valid")
	assert.Contains(t, out, "llm_keys")
	assert.Contains(t, out, "evidence_db")
	assert.Contains(t, out, "passed")
}

func TestDoctorCmd_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	var buf bytes.Buffer
	doctorCmd.SetOut(&buf)
	doctorCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"doctor", "--format", "json", "--skip-upstream"})

	_ = rootCmd.Execute()

	out := buf.String()
	assert.Contains(t, out, `"status"`)
	assert.Contains(t, out, `"checks"`)
	assert.Contains(t, out, `"summary"`)
}

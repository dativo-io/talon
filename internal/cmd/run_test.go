package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestRunCmd_Flags(t *testing.T) {
	expected := map[string]string{
		"agent":   "default",
		"tenant":  "default",
		"dry-run": "false",
		"policy":  "",
	}

	for name, wantDefault := range expected {
		flag := runCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "run flag %q should be registered", name)
		if flag != nil {
			assert.Equal(t, wantDefault, flag.DefValue, "run flag %q default", name)
		}
	}
}

func TestRunCmd_RequiresExactlyOneArg(t *testing.T) {
	assert.NotNil(t, runCmd.Args, "run command should have an Args validator")
	err := runCmd.Args(runCmd, []string{})
	assert.Error(t, err)
	err = runCmd.Args(runCmd, []string{"a", "b"})
	assert.Error(t, err)
	err = runCmd.Args(runCmd, []string{"hello"})
	assert.NoError(t, err)
}

func TestRunCmd_UseLine(t *testing.T) {
	assert.Equal(t, "run [prompt]", runCmd.Use)
}

func TestBuildProviders_Empty(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_REGION", "")

	cfg := &config.Config{OllamaBaseURL: "http://localhost:11434"}
	providers := buildProviders(cfg)
	// openai and anthropic are always registered (empty key) so vault-only keys work
	assert.Contains(t, providers, "openai")
	assert.Contains(t, providers, "anthropic")
	assert.Contains(t, providers, "ollama")
	assert.NotContains(t, providers, "bedrock")
}

func TestBuildProviders_WithEnvVars(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test123")
	t.Setenv("ANTHROPIC_API_KEY", "ant-test123")
	t.Setenv("AWS_REGION", "eu-west-1")

	cfg := &config.Config{OllamaBaseURL: "http://localhost:11434"}
	providers := buildProviders(cfg)
	assert.Contains(t, providers, "openai")
	assert.Contains(t, providers, "anthropic")
	assert.Contains(t, providers, "ollama")
	assert.Contains(t, providers, "bedrock")
}

func TestBuildProviders_OllamaCustomURL(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_REGION", "")

	cfg := &config.Config{OllamaBaseURL: "http://custom:11434"}
	providers := buildProviders(cfg)
	assert.Contains(t, providers, "ollama")
}

func TestValidatePolicyFile_Valid(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteTestPolicyFile(t, dir, "valid-agent")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := validatePolicyFile(ctx, policyPath, dir)
	require.NoError(t, err)
}

func TestValidatePolicyFile_InvalidPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmp := t.TempDir()
	err := validatePolicyFile(ctx, filepath.Join(tmp, "nonexistent.talon.yaml"), tmp)
	require.Error(t, err)
}

func TestValidatePolicyFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte("agent:\n  name: [unclosed"), 0o600))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := validatePolicyFile(ctx, path, dir)
	require.Error(t, err)
}

func TestLoadRoutingAndCostLimits_Valid(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteTestPolicyFile(t, dir, "routing-agent")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	routing, costLimits := loadRoutingAndCostLimits(ctx, policyPath, dir)
	require.NotNil(t, routing)
	require.NotNil(t, costLimits)
	assert.NotNil(t, routing.Tier0)
	assert.Equal(t, "gpt-4", routing.Tier0.Primary)
	assert.Equal(t, 100.0, costLimits.PerRequest)
}

func TestLoadRoutingAndCostLimits_MissingFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmp := t.TempDir()
	routing, costLimits := loadRoutingAndCostLimits(ctx, filepath.Join(tmp, "nonexistent.talon.yaml"), tmp)
	assert.Nil(t, routing)
	assert.Nil(t, costLimits)
}

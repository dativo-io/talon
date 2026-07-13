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

func TestBuildProviders_EUStrictFiltersNonSovereignProviders(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_REGION", "eu-west-1")

	cfg := &config.Config{
		OllamaBaseURL: "http://localhost:11434",
		Sovereignty:   &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	providers := buildProviders(cfg)
	// US providers are filtered out under eu_strict.
	assert.NotContains(t, providers, "openai")
	assert.NotContains(t, providers, "anthropic")
	// LOCAL and EU-region-capable providers remain available.
	assert.Contains(t, providers, "ollama")
	assert.Contains(t, providers, "bedrock")
}

func TestBuildProviders_EUStrictExcludesBedrockUSRegion(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_REGION", "us-east-1")

	cfg := &config.Config{
		OllamaBaseURL: "http://localhost:11434",
		Sovereignty:   &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
	}
	providers := buildProviders(cfg)
	assert.NotContains(t, providers, "bedrock", "us-east-1 Bedrock must be excluded under eu_strict")
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

// TestCLIAgentScanAndResolve (#267): the CLI resolves its agent from the
// scanned fleet source — an explicit policy file yields a one-agent catalog
// whose name the "default" sentinel resolves to; explicit names must exist.
func TestCLIAgentScanAndResolve(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("explicit file: default sentinel resolves to the file's agent", func(t *testing.T) {
		dir := t.TempDir()
		policyPath := testutil.WriteTestPolicyFile(t, dir, "custom-name")
		scan, err := cliAgentScan(ctx, &config.Config{DefaultPolicy: "unused"}, policyPath)
		require.NoError(t, err)
		ra, err := resolveCatalogAgent(scan, "default")
		require.NoError(t, err)
		assert.Equal(t, "custom-name", ra.Name)
		require.NotNil(t, ra.Policy)
		require.NotNil(t, ra.Policy.Policies.ModelRouting, "routing config travels in the catalog agent")
		assert.Equal(t, "gpt-4", ra.Policy.Policies.ModelRouting.Tier0.Primary)
	})

	t.Run("explicit other name errors listing discovered agents", func(t *testing.T) {
		dir := t.TempDir()
		policyPath := testutil.WriteTestPolicyFile(t, dir, "policy-agent")
		scan, err := cliAgentScan(ctx, &config.Config{}, policyPath)
		require.NoError(t, err)
		_, err = resolveCatalogAgent(scan, "my-agent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "policy-agent")
	})

	t.Run("missing file gets the friendly init hint", func(t *testing.T) {
		tmp := t.TempDir()
		_, err := cliAgentScan(ctx, &config.Config{}, filepath.Join(tmp, "nonexistent.talon.yaml"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "talon init")
	})

	t.Run("agents_dir mode discovers the fleet; ambiguous default errors", func(t *testing.T) {
		dir := t.TempDir()
		agentsDir := filepath.Join(dir, "agents")
		for _, name := range []string{"support", "coding"} {
			sub := filepath.Join(agentsDir, name)
			require.NoError(t, os.MkdirAll(sub, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(sub, "agent.talon.yaml"),
				[]byte("agent:\n  name: "+name+"\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 5\n"), 0o600))
		}
		scan, err := cliAgentScan(ctx, &config.Config{AgentsDir: agentsDir}, "")
		require.NoError(t, err)
		require.Len(t, scan.Agents, 2)

		_, err = resolveCatalogAgent(scan, "default")
		require.Error(t, err, "two agents cannot resolve the default sentinel")
		assert.Contains(t, err.Error(), "--agent")

		ra, err := resolveCatalogAgent(scan, "coding")
		require.NoError(t, err)
		assert.Equal(t, "coding", ra.Name)
	})
}

// TestLoadPricingTable_ResolvesRelativeToBaseDir ensures the pricing file path
// is resolved relative to baseDir (policy directory), so cost estimation works
// when CWD differs from the project directory.
func TestLoadPricingTable_ResolvesRelativeToBaseDir(t *testing.T) {
	dir := t.TempDir()
	pricingDir := filepath.Join(dir, "pricing")
	require.NoError(t, os.MkdirAll(pricingDir, 0o755))
	minimalPricing := `
version: "1"
providers:
  openai:
    models:
      gpt-4o:
        input_per_1m: 2.50
        output_per_1m: 10.00
`
	require.NoError(t, os.WriteFile(filepath.Join(pricingDir, "models.yaml"), []byte(minimalPricing), 0o600))

	cfg := &config.Config{}
	table := loadPricingTable(cfg, dir)
	require.NotNil(t, table)
	assert.Greater(t, table.ModelCount("openai"), 0)
	cost, known := table.Estimate("openai", "gpt-4o", 1000, 1000)
	assert.True(t, known)
	assert.Greater(t, cost, 0.0)
}

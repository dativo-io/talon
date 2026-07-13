package doctor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
)

func TestRun_ConfigCategory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("OPENAI_API_KEY", "sk-test-key")

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

	ctx := context.Background()
	report := Run(ctx, Options{SkipUpstream: true})

	configChecks := 0
	for _, c := range report.Checks {
		if c.Category == "config" {
			configChecks++
		}
	}
	assert.GreaterOrEqual(t, configChecks, 4, "should have at least 4 config checks")
	assert.GreaterOrEqual(t, report.Summary.Pass, 3)
}

func TestRun_GatewayCategory_WithConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	gwCfgPath := filepath.Join(dir, "talon.config.yaml")
	gwYAML := `gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
  organization_policy:
    defaults:
      pii_action: "warn"
    constraints:
      forbidden_tools: ["rm_rf", "delete_*"]
`
	require.NoError(t, os.WriteFile(gwCfgPath, []byte(gwYAML), 0o600))

	ctx := context.Background()
	report := Run(ctx, Options{GatewayConfigPath: gwCfgPath, SkipUpstream: true})

	gatewayChecks := 0
	for _, c := range report.Checks {
		if c.Category == "gateway" {
			gatewayChecks++
		}
	}
	assert.GreaterOrEqual(t, gatewayChecks, 3, "should have gateway config, mode, and agent-identity checks")

	found := false
	for _, c := range report.Checks {
		if c.Name == "gateway_mode" {
			found = true
			assert.Equal(t, "pass", c.Status)
			assert.Contains(t, c.Message, "shadow")
		}
	}
	assert.True(t, found, "should include gateway_mode check")
}

// TestGatewayIdentityParity (#279 review): every condition that makes
// `talon serve --gateway` refuse to start must FAIL the doctor identity
// check — doctor must never bless a gateway that cannot start. The same
// preflight (GatewayIdentityPreflight) backs `talon enforce enable`.
func TestGatewayIdentityParity(t *testing.T) {
	findIdentity := func(report *Report) *CheckResult {
		for i := range report.Checks {
			if report.Checks[i].Name == "gateway_agent_identity" {
				return &report.Checks[i]
			}
		}
		return nil
	}
	gwYAML := `gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
`
	setup := func(t *testing.T) (dir, gwCfgPath string) {
		t.Helper()
		dir = t.TempDir()
		t.Setenv("TALON_DATA_DIR", dir)
		gwCfgPath = filepath.Join(dir, "talon.config.yaml")
		require.NoError(t, os.WriteFile(gwCfgPath, []byte(gwYAML), 0o600))
		prevWd, _ := os.Getwd()
		require.NoError(t, os.Chdir(dir))
		t.Cleanup(func() { _ = os.Chdir(prevWd) })
		return dir, gwCfgPath
	}
	agentYAML := func(keyed bool) string {
		y := "agent:\n  name: parity-agent\n  description: t\n  version: \"1.0.0\"\n"
		if keyed {
			y += "  key:\n    secret_name: parity-agent-talon-key\n"
		}
		return y + "policies:\n  cost_limits: {}\n"
	}
	run := func(gwCfgPath string) *Report {
		return Run(context.Background(), Options{GatewayConfigPath: gwCfgPath, SkipUpstream: true})
	}

	t.Run("missing agent policy fails", func(t *testing.T) {
		_, gwCfgPath := setup(t)
		c := findIdentity(run(gwCfgPath))
		require.NotNil(t, c)
		assert.Equal(t, "fail", c.Status, "gateway startup would refuse — doctor must too: %s", c.Message)
	})

	t.Run("missing key binding fails", func(t *testing.T) {
		dir, gwCfgPath := setup(t)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.talon.yaml"), []byte(agentYAML(false)), 0o600))
		c := findIdentity(run(gwCfgPath))
		require.NotNil(t, c)
		assert.Equal(t, "fail", c.Status, "unkeyed agent: %s", c.Message)
		assert.Contains(t, c.Message, "key binding")
	})

	t.Run("unminted key secret fails", func(t *testing.T) {
		dir, gwCfgPath := setup(t)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.talon.yaml"), []byte(agentYAML(true)), 0o600))
		c := findIdentity(run(gwCfgPath))
		require.NotNil(t, c)
		assert.Equal(t, "fail", c.Status, "unminted secret: %s", c.Message)
	})

	// The preflight must validate the FULL identity — including the policy
	// override, whose semantic validation happens at registry build. This
	// egress rule is agent-SCHEMA-valid (tier is the only required field)
	// but gateway-invalid (a rule needs allowed_providers or
	// allowed_regions), so a reduced-identity preflight would pass while
	// `talon serve --gateway` fails (#279 review round 3).
	t.Run("schema-valid but gateway-invalid egress override fails", func(t *testing.T) {
		dir, gwCfgPath := setup(t)
		agentDoc := agentYAML(true) + "  egress:\n    rules:\n      - tier: 2\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.talon.yaml"), []byte(agentDoc), 0o600))

		cfg, err := config.Load()
		require.NoError(t, err)
		store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		require.NoError(t, store.Set(context.Background(), "parity-agent-talon-key", []byte("tk-parity-eg"), secrets.ACL{}))
		require.NoError(t, store.Close())

		c := findIdentity(run(gwCfgPath))
		require.NotNil(t, c)
		assert.Equal(t, "fail", c.Status,
			"gateway startup rejects this override at registry build — doctor must too: %s", c.Message)
		assert.Contains(t, c.Message, "egress")
	})

	t.Run("minted key passes; admin collision fails", func(t *testing.T) {
		dir, gwCfgPath := setup(t)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.talon.yaml"), []byte(agentYAML(true)), 0o600))

		cfg, err := config.Load()
		require.NoError(t, err)
		store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		require.NoError(t, store.Set(context.Background(), "parity-agent-talon-key", []byte("tk-parity-1"), secrets.ACL{}))
		require.NoError(t, store.Close())

		c := findIdentity(run(gwCfgPath))
		require.NotNil(t, c)
		assert.Equal(t, "pass", c.Status, "minted key must pass: %s", c.Message)

		t.Setenv("TALON_ADMIN_KEY", "tk-parity-1")
		c = findIdentity(run(gwCfgPath))
		require.NotNil(t, c)
		assert.Equal(t, "fail", c.Status, "admin-key collision must fail: %s", c.Message)
		assert.Contains(t, c.Message, "TALON_ADMIN_KEY")

		_ = dir
	})
}

func TestRun_GatewayCategory_SkippedWithoutConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	ctx := context.Background()
	report := Run(ctx, Options{SkipUpstream: true})

	for _, c := range report.Checks {
		assert.NotEqual(t, "gateway", c.Category, "should skip gateway checks without config")
	}
}

func TestRun_InvalidGatewayConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	gwCfgPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(gwCfgPath, []byte("invalid yaml: ["), 0o644))

	ctx := context.Background()
	report := Run(ctx, Options{GatewayConfigPath: gwCfgPath, SkipUpstream: true})

	found := false
	for _, c := range report.Checks {
		if c.Name == "gateway_config_valid" {
			found = true
			assert.Equal(t, "fail", c.Status)
		}
	}
	assert.True(t, found)
}

// TestDoctorGatewaySovereigntyFromGatewayConfig_WhenOperatorSovereigntyEmpty is
// the regression for the "doctor sovereignty merge is fragile" bug: even when
// the operator config already carries a weak/empty sovereignty block, the
// stronger air_gap block declared in --gateway-config must be honored, so a
// non-EU gateway upstream is flagged.
func TestDoctorGatewaySovereigntyFromGatewayConfig_WhenOperatorSovereigntyEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")

	// Operator config carries an empty/standard sovereignty block (the case that
	// previously masked the gateway file's air_gap declaration).
	viper.Set("sovereignty", map[string]interface{}{"deployment_mode": "standard"})
	t.Cleanup(func() {
		viper.Reset()
		viper.SetEnvPrefix("TALON")
		viper.AutomaticEnv()
		viper.SetDefault(config.KeyDefaultPolicy, config.DefaultPolicy)
		viper.SetDefault(config.KeyMaxAttachmentMB, config.DefaultMaxAttachMB)
		viper.SetDefault(config.KeyOllamaBaseURL, config.DefaultOllamaURL)
	})

	gwCfgPath := filepath.Join(dir, "talon.config.airgap.yaml")
	gwYAML := `sovereignty:
  deployment_mode: air_gap
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      region: "US"
      secret_name: "openai-api-key"
  organization_policy:
    defaults:
      pii_action: "warn"
    constraints:
      forbidden_tools: ["rm_rf"]
`
	require.NoError(t, os.WriteFile(gwCfgPath, []byte(gwYAML), 0o600))

	gwCfg, err := gateway.LoadGatewayConfig(gwCfgPath)
	require.NoError(t, err)

	res := checkAirGapFromGateway(gwCfg, gwCfgPath)
	assert.Equal(t, "pass", res.Status,
		"air_gap crypto keys are set; provider exclusions are non-fatal")

	sov := checkSovereigntyFromGateway(gwCfg, gwCfgPath)
	assert.Equal(t, "fail", sov.Status,
		"US-only gateway under eu_strict has no routable EU/LOCAL provider")
}

func TestDoctorGatewaySovereignty_MixedProvidersWarns(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	t.Setenv("OPENAI_API_KEY", "")

	viper.Set("sovereignty", map[string]interface{}{"mode": "eu_strict"})
	t.Cleanup(func() {
		viper.Reset()
		viper.SetEnvPrefix("TALON")
		viper.AutomaticEnv()
		viper.SetDefault(config.KeyDefaultPolicy, config.DefaultPolicy)
		viper.SetDefault(config.KeyMaxAttachmentMB, config.DefaultMaxAttachMB)
		viper.SetDefault(config.KeyOllamaBaseURL, config.DefaultOllamaURL)
	})

	gwCfgPath := filepath.Join(dir, "talon.config.yaml")
	gwYAML := `sovereignty:
  mode: eu_strict
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      region: "US"
      secret_name: "openai-api-key"
    ollama:
      enabled: true
      base_url: "http://127.0.0.1:11434"
      region: "LOCAL"
      secret_name: "ollama-api-key"
  organization_policy:
    defaults:
      pii_action: "warn"
    constraints:
      forbidden_tools: ["rm_rf"]
`
	require.NoError(t, os.WriteFile(gwCfgPath, []byte(gwYAML), 0o600))

	gwCfg, err := gateway.LoadGatewayConfig(gwCfgPath)
	require.NoError(t, err)

	sov := checkSovereigntyFromGateway(gwCfg, gwCfgPath)
	assert.Equal(t, "warn", sov.Status)
	assert.Contains(t, sov.Message, "openai")
}

// TestDoctorGatewaySovereignty_NativeProviderDoesNotMaskGateway is the
// regression for the "doctor mixes native and gateway routability" bug: a
// gateway config whose providers are all excluded must fail even when an
// unrelated compliant native provider (here Bedrock in an EU region) is
// configured. Gateway routability is evaluated independently of native.
func TestDoctorGatewaySovereignty_NativeProviderDoesNotMaskGateway(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	// A compliant native provider (Bedrock in an EU region) is configured.
	t.Setenv("AWS_REGION", "eu-central-1")

	viper.Set("sovereignty", map[string]interface{}{"mode": "eu_strict"})
	t.Cleanup(func() {
		viper.Reset()
		viper.SetEnvPrefix("TALON")
		viper.AutomaticEnv()
		viper.SetDefault(config.KeyDefaultPolicy, config.DefaultPolicy)
		viper.SetDefault(config.KeyMaxAttachmentMB, config.DefaultMaxAttachMB)
		viper.SetDefault(config.KeyOllamaBaseURL, config.DefaultOllamaURL)
	})

	gwCfgPath := filepath.Join(dir, "talon.config.yaml")
	gwYAML := `sovereignty:
  mode: eu_strict
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      region: "US"
      secret_name: "openai-api-key"
  organization_policy:
    defaults:
      pii_action: "warn"
    constraints:
      forbidden_tools: ["rm_rf"]
`
	require.NoError(t, os.WriteFile(gwCfgPath, []byte(gwYAML), 0o600))

	gwCfg, err := gateway.LoadGatewayConfig(gwCfgPath)
	require.NoError(t, err)

	sov := checkSovereigntyFromGateway(gwCfg, gwCfgPath)
	assert.Equal(t, "fail", sov.Status,
		"gateway has no compliant provider; a compliant native provider must not mask it")
	assert.Contains(t, sov.Message, "gateway")
}

// TestCheckLLMKeys_RecognizesLocalProviders guards the air-gap operator path:
// an Ollama-only deployment declares a local provider in llm.providers and must
// satisfy the LLM-provider check without any cloud key set.
func TestCheckLLMKeys_RecognizesLocalProviders(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_PROFILE", "")

	cfg := &config.Config{LLM: &config.LLMConfig{
		Providers: map[string]config.LLMProviderConfig{
			"ollama": {Type: "ollama", Enabled: true},
		},
	}}
	res := checkLLMKeys(cfg)
	assert.Equal(t, "pass", res.Status)
	assert.Contains(t, res.Message, "ollama")

	// No providers and no cloud key → still fails closed.
	assert.Equal(t, "fail", checkLLMKeys(&config.Config{}).Status)
}

// TestCheckPolicy_MissingFileWarnsNotFails ensures a missing agent policy is
// advisory (gateway-only deployments need no agent.talon.yaml), not a failure.
func TestCheckPolicy_MissingFileWarnsNotFails(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DefaultPolicy: filepath.Join(dir, "does-not-exist.talon.yaml")}
	res := checkPolicy(cfg)
	assert.Equal(t, "warn", res.Status)
}

func TestCheckResult_StatusValues(t *testing.T) {
	statuses := []string{"pass", "warn", "fail"}
	for _, s := range statuses {
		cr := CheckResult{Status: s, Name: "test_" + s}
		assert.NotEmpty(t, cr.Status)
	}
}

func TestReport_SummaryCalculation(t *testing.T) {
	report := &Report{
		Checks: []CheckResult{
			{Status: "pass", Name: "a"},
			{Status: "pass", Name: "b"},
			{Status: "warn", Name: "c"},
			{Status: "fail", Name: "d"},
		},
	}
	for _, c := range report.Checks {
		switch c.Status {
		case "pass":
			report.Summary.Pass++
		case "warn":
			report.Summary.Warn++
		case "fail":
			report.Summary.Fail++
		}
	}

	assert.Equal(t, 2, report.Summary.Pass)
	assert.Equal(t, 1, report.Summary.Warn)
	assert.Equal(t, 1, report.Summary.Fail)
}

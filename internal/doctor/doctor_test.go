package doctor

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/registration"
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
	assert.GreaterOrEqual(t, gatewayChecks, 2, "should have gateway config and agent-identity checks")

	for _, c := range report.Checks {
		assert.NotEqual(t, "gateway_mode", c.Name, "no selectable enforcement posture is reported (#442)")
	}
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
	t.Setenv("TALON_GATEWAY_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	assert.Equal(t, "fail", checkLLMKeys(&config.Config{}).Status)
}

// The production pilot profile declares its provider under gateway.providers
// with a vault-backed credential: that is a configured provider, not "no LLM
// provider". A disabled gateway or a disabled provider is not.
func TestCheckLLMKeys_RecognizesGatewayProviders(t *testing.T) {
	for _, k := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_PROFILE"} {
		t.Setenv(k, "")
	}
	write := func(body string) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TALON_GATEWAY_CONFIG", p)
	}
	write("gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      secret_name: openai-api-key\n      base_url: \"https://api.openai.com\"\n")
	res := checkLLMKeys(&config.Config{})
	assert.Equal(t, "pass", res.Status)
	assert.Contains(t, res.Message, "openai (gateway.providers)")

	write("gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: false\n      secret_name: openai-api-key\n      base_url: \"https://api.openai.com\"\n")
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

// TestGatewayIdentityPreflight_AgentsDir (#267): in agents_dir mode the
// preflight runs the SAME recursive scan + full-set registry dry-run serve
// startup runs — a condition that would refuse startup must fail here too.
func TestGatewayIdentityPreflight_AgentsDir(t *testing.T) {
	writeAgent := func(t *testing.T, agentsDir, sub, name, secret string) string {
		t.Helper()
		d := filepath.Join(agentsDir, sub)
		require.NoError(t, os.MkdirAll(d, 0o755))
		y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
		if secret != "" {
			y += "  key:\n    secret_name: " + secret + "\n"
		}
		y += "policies:\n  cost_limits: {}\n"
		p := filepath.Join(d, "agent.talon.yaml")
		require.NoError(t, os.WriteFile(p, []byte(y), 0o600))
		return p
	}
	setup := func(t *testing.T) (dataDir, agentsDir string) {
		t.Helper()
		dataDir = t.TempDir()
		agentsDir = filepath.Join(dataDir, "agents")
		require.NoError(t, os.MkdirAll(agentsDir, 0o755))
		t.Setenv("TALON_DATA_DIR", dataDir)
		t.Setenv("TALON_AGENTS_DIR", agentsDir)
		return dataDir, agentsDir
	}
	mint := func(t *testing.T, names ...string) {
		t.Helper()
		cfg, err := config.Load()
		require.NoError(t, err)
		store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		defer store.Close()
		for _, n := range names {
			require.NoError(t, store.Set(context.Background(), n, []byte("tk-"+n), secrets.ACL{}))
		}
	}

	t.Run("two keyed agents pass the full dry-run", func(t *testing.T) {
		_, agentsDir := setup(t)
		writeAgent(t, agentsDir, "support", "support", "support-key")
		writeAgent(t, agentsDir, "coding", "coding", "coding-key")
		mint(t, "support-key", "coding-key")

		summary, secretName, err := GatewayIdentityPreflight(context.Background())
		require.NoError(t, err)
		assert.Contains(t, summary, "2 agent(s)")
		assert.Empty(t, secretName)
	})

	t.Run("one broken file fails the whole preflight", func(t *testing.T) {
		_, agentsDir := setup(t)
		writeAgent(t, agentsDir, "support", "support", "support-key")
		mint(t, "support-key")
		broken := filepath.Join(agentsDir, "bad")
		require.NoError(t, os.MkdirAll(broken, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(broken, "agent.talon.yaml"), []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))

		_, _, err := GatewayIdentityPreflight(context.Background())
		require.Error(t, err, "serve startup would refuse this directory — doctor must too")
	})

	t.Run("duplicate names fail", func(t *testing.T) {
		_, agentsDir := setup(t)
		writeAgent(t, agentsDir, "a", "support", "key-a")
		writeAgent(t, agentsDir, "b", "support", "key-b")
		mint(t, "key-a", "key-b")

		_, _, err := GatewayIdentityPreflight(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate agent name")
	})

	t.Run("empty directory fails gateway preflight", func(t *testing.T) {
		setup(t)
		_, _, err := GatewayIdentityPreflight(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one keyed agent")
	})

	t.Run("unminted key in the set fails", func(t *testing.T) {
		_, agentsDir := setup(t)
		writeAgent(t, agentsDir, "support", "support", "support-key")
		writeAgent(t, agentsDir, "coding", "coding", "coding-key")
		mint(t, "support-key") // coding-key never minted

		_, _, err := GatewayIdentityPreflight(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "coding")
	})
}

// TestCheckConfigKeys pins #351: top-level talon.config.yaml keys no loader
// reads produce an advisory WARN naming each key with a hint — never a fail.
func TestCheckConfigKeys(t *testing.T) {
	t.Run("no config file loaded", func(t *testing.T) {
		r := checkConfigKeys("")
		assert.Equal(t, "pass", r.Status)
	})

	t.Run("clean config passes", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(p, []byte("log_level: info\nllm:\n  pricing_file: pricing/models.yaml\ngateway:\n  enabled: true\n"), 0o600))
		r := checkConfigKeys(p)
		assert.Equal(t, "pass", r.Status, r.Message)
	})

	t.Run("dead keys warn with hints", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(p, []byte("tenants:\n  - id: default\nevidence:\n  path: ~/.talon/evidence.db\nlog_lvel: info\n"), 0o600))
		r := checkConfigKeys(p)
		assert.Equal(t, "warn", r.Status, "dead keys are advisory, not fatal")
		assert.Contains(t, r.Message, "tenants")
		assert.Contains(t, r.Message, "agent.talon.yaml", "known dead keys carry their real surface")
		assert.Contains(t, r.Message, "data_dir", "evidence hint names the real state surface")
		assert.Contains(t, r.Message, `did you mean "log_level"?`, "typos get a nearest-key hint")
		assert.NotEmpty(t, r.Fix)
	})

	t.Run("unparseable config warns not fails", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(p, []byte("not: yaml: ["), 0o600))
		r := checkConfigKeys(p)
		assert.Equal(t, "warn", r.Status)
	})
}

// An intent record without a completion or rollback record is an
// interrupted `talon agents add`: doctor names it and says what to do; a
// terminal record clears the finding.
func TestRun_ReportsInterruptedRegistrations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", "doctor-test-signing-key-000000001")
	cfg, err := config.Load()
	require.NoError(t, err)
	find := func() CheckResult {
		for _, c := range Run(ctx, Options{}).Checks {
			if c.Name == "agent_registrations" {
				return c
			}
		}
		t.Fatal("no agent_registrations check")
		return CheckResult{}
	}
	require.Equal(t, "pass", find().Status)

	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	put := func(id, typ string) {
		require.NoError(t, store.Store(ctx, &evidence.Evidence{
			ID: id, CorrelationID: "al_corr", TenantID: "default", AgentID: "refund-bot", Timestamp: time.Now().UTC(), InvocationType: typ,
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: typ},
		}))
	}
	put("al_intent", registration.TypeIntent)

	// No registration is running (the lock is free): the intent without a
	// terminal record is an INTERRUPTED registration. The advice never
	// tells the operator to delete something.
	c := find()
	require.Equal(t, "warn", c.Status)
	require.Contains(t, c.Message, "INTERRUPTED")
	require.Contains(t, c.Message, "refund-bot (tenant default, intent al_intent")
	require.Contains(t, c.Fix, "talon agents add <name>")
	require.Contains(t, c.Fix, "removes ONLY what the signed intent proves")
	require.NotContains(t, c.Fix, "rm ")

	// A registration is running now (it holds the registration lock): the
	// same intent is work IN PROGRESS, not a fault and not an interruption
	// (#567 review).
	release, err := registration.Acquire(ctx, cfg.DataDir, time.Second)
	require.NoError(t, err)
	c = find()
	require.Equal(t, "pass", c.Status, "an active registration is not a problem to fix")
	require.Contains(t, c.Message, "IN PROGRESS")
	require.Contains(t, c.Message, "al_intent")
	require.NotContains(t, c.Message, "INTERRUPTED")
	require.Contains(t, c.Fix, "Nothing to do while it runs")
	release()
	require.Contains(t, find().Message, "INTERRUPTED", "once the registration is gone without a terminal record, it is interrupted")

	put("al_rollback", registration.TypeRolledBack)
	require.NoError(t, store.Close())
	require.Equal(t, "pass", find().Status)
}

// What is said for each thing that can be established about unresolved
// registrations: in progress, interrupted, unresolved when the lock cannot
// be probed, a partial list, and an intent that does not verify.
func TestRegistrationsResult_StatesAreKeptApart(t *testing.T) {
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	one := registration.Lookup{Complete: true, Unresolved: []registration.Unresolved{{Name: "refund-bot", Tenant: "acme", IntentID: "al_1", At: at, Verified: true}}}

	c := registrationsResult("agent_registrations", registration.Lookup{Complete: true}, registration.LockFree)
	require.Equal(t, "pass", c.Status)
	require.Equal(t, "No unresolved use-case registration.", c.Message)

	c = registrationsResult("agent_registrations", one, registration.LockUnknown)
	require.Equal(t, "warn", c.Status)
	require.Contains(t, c.Message, "UNRESOLVED")
	require.Contains(t, c.Message, "cannot be established")
	require.NotContains(t, c.Message, "INTERRUPTED")
	require.NotContains(t, c.Message, "IN PROGRESS")

	// A lookup that could not list everything never reads as "none".
	c = registrationsResult("agent_registrations", registration.Lookup{Complete: false}, registration.LockFree)
	require.Equal(t, "warn", c.Status)
	require.Contains(t, c.Message, "more unresolved registrations than one lookup reads")
	partial := one
	partial.Complete = false
	c = registrationsResult("agent_registrations", partial, registration.LockFree)
	require.Contains(t, c.Message, "INTERRUPTED")
	require.Contains(t, c.Message, "older ones are not")

	unverified := registration.Lookup{Complete: true, Unresolved: []registration.Unresolved{{Name: "refund-bot", Tenant: "acme", IntentID: "al_1", At: at}}}
	c = registrationsResult("agent_registrations", unverified, registration.LockFree)
	require.Contains(t, c.Message, "the intent record does NOT verify")
}

// #568 review. A restored installation that has not been resumed is visible
// in `talon doctor`, with what the hold covers and what it does not.
func TestCheckRecoveryHold(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{DataDir: t.TempDir(), SigningKey: "0123456789abcdef0123456789abcdef0123456789abcdef"}
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if got := checkRecoveryHold(cfg); got.Status != "pass" || got.Message != "No recovery hold." {
		t.Fatalf("a live installation: %+v", got)
	}
	if err := action.StampRecoveryHold(ctx, store.DB(), "bk_1", time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC), "cfg"); err != nil {
		t.Fatal(err)
	}
	got := checkRecoveryHold(cfg)
	if got.Status != "fail" {
		t.Fatalf("an installation on a restored backup must fail the check: %+v", got)
	}
	for _, want := range []string{"RECOVERY HOLD", "bk_1", "2026-11-20T10:00:00Z", "every Action Gateway claim is refused", "does not cover LLM gateway requests or MCP proxy tool calls"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("the message lacks %q: %s", want, got.Message)
		}
	}
	if !strings.Contains(got.Fix, "talon backup resume --reconciled") {
		t.Errorf("the fix must name the resume command: %s", got.Fix)
	}
	if _, err := action.ResumeRecovery(ctx, store.DB(), "operator", []string{"op-1"}, time.Now(), func(context.Context, *sql.Tx, []action.RecoveryHold) error { return nil }); err != nil {
		t.Fatal(err)
	}
	got = checkRecoveryHold(cfg)
	if got.Status != "pass" || !strings.Contains(got.Message, "1 operation id(s) are held for good") {
		t.Fatalf("after the resume: %+v", got)
	}
}

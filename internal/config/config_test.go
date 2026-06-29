package config

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/cryptoutil"
)

func resetViper(t *testing.T) {
	t.Helper()
	t.Setenv("TALON_SECRETS_KEY", "")
	t.Setenv("TALON_SIGNING_KEY", "")
	t.Setenv("TALON_DATA_DIR", "")
	t.Setenv("TALON_DEFAULT_POLICY", "")
	t.Setenv("TALON_MAX_ATTACHMENT_MB", "")
	t.Setenv("TALON_OLLAMA_BASE_URL", "")
	viper.Reset()
	viper.SetEnvPrefix("TALON")
	viper.AutomaticEnv()
	viper.SetDefault(KeyDefaultPolicy, DefaultPolicy)
	viper.SetDefault(KeyMaxAttachmentMB, DefaultMaxAttachMB)
	viper.SetDefault(KeyOllamaBaseURL, DefaultOllamaURL)
}

func TestLoad_Defaults(t *testing.T) {
	resetViper(t)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, DefaultPolicy, cfg.DefaultPolicy)
	assert.Equal(t, DefaultMaxAttachMB, cfg.MaxAttachmentMB)
	assert.Equal(t, DefaultOllamaURL, cfg.OllamaBaseURL)
	assert.True(t, cfg.UsingDefaultKeys(), "should report default keys when none are set")
	assert.Len(t, cfg.SecretsKey, 64, "derived key should be 64 hex chars")
	assert.Len(t, cfg.SigningKey, 64, "derived key should be 64 hex chars")
	assert.NotEqual(t, cfg.SecretsKey, cfg.SigningKey, "secrets and signing keys must differ")
}

func TestLoad_ExplicitKeys(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "abcdefghijklmnopqrstuvwxyz012345", cfg.SecretsKey)
	assert.Equal(t, "my-signing-key-at-least-32-chars!", cfg.SigningKey)
	assert.False(t, cfg.UsingDefaultKeys())
}

func TestLoad_InvalidSecretsKeyLength(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "too-short")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets_key")
}

func TestLoad_ExplicitKeysHex(t *testing.T) {
	resetViper(t)
	// 64 hex chars = 32 bytes when decoded (full AES-256 strength)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("TALON_SIGNING_KEY", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Len(t, cfg.SecretsKey, 64)
	assert.Len(t, cfg.SigningKey, 64)
	assert.False(t, cfg.UsingDefaultKeys())
}

func TestLoad_InvalidSigningKeyLength(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SIGNING_KEY", "short")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing_key")
}

func TestLoad_CustomDataDir(t *testing.T) {
	resetViper(t)
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, dir, cfg.DataDir)
}

func TestLoad_CustomMaxAttachmentMB(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_MAX_ATTACHMENT_MB", "25")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, 25, cfg.MaxAttachmentMB)
}

func TestLoad_CustomOllamaURL(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_OLLAMA_BASE_URL", "http://gpu-box:11434")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "http://gpu-box:11434", cfg.OllamaBaseURL)
}

func TestLoad_CustomDefaultPolicy(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_DEFAULT_POLICY", "custom.talon.yaml")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "custom.talon.yaml", cfg.DefaultPolicy)
}

func TestConfig_DBPaths(t *testing.T) {
	cfg := &Config{DataDir: "/data/talon"}
	assert.Equal(t, "/data/talon/secrets.db", cfg.SecretsDBPath())
	assert.Equal(t, "/data/talon/evidence.db", cfg.EvidenceDBPath())
}

func TestConfig_EnsureDataDir(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{DataDir: dir + "/nested/deep"}
	require.NoError(t, cfg.EnsureDataDir())
}

func TestDeriveDefaultKey_Deterministic(t *testing.T) {
	k1 := deriveDefaultKey("/home/user/.talon", "test-salt")
	k2 := deriveDefaultKey("/home/user/.talon", "test-salt")
	assert.Equal(t, k1, k2)
	assert.Len(t, k1, 64, "should be 64 hex chars (32 bytes)")
	assert.True(t, cryptoutil.IsHexString(k1), "should be valid hex")
}

func TestDeriveDefaultKey_DifferentSalts(t *testing.T) {
	paths := []string{
		"/data",
		"/home/user/.talon",
		"/Users/longusername/.talon",
		"/Users/verylongusername/custom-data-directory/.talon",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			k1 := deriveDefaultKey(path, "secrets-encryption")
			k2 := deriveDefaultKey(path, "evidence-signing--")
			assert.NotEqual(t, k1, k2, "different salts must produce different keys for path %q", path)
		})
	}
}

func TestDeriveDefaultKey_DifferentPaths(t *testing.T) {
	k1 := deriveDefaultKey("/home/alice/.talon", "salt")
	k2 := deriveDefaultKey("/home/bob/.talon", "salt")
	assert.NotEqual(t, k1, k2)
}

func TestLoad_WithoutLLMBlock(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Nil(t, cfg.LLM, "LLM should be nil when llm block is absent")
}

func TestLoad_WithLLMBlock(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")

	viper.Set("llm", map[string]interface{}{
		"routing": map[string]interface{}{
			"data_sovereignty_mode": "eu_strict",
		},
		"providers": map[string]interface{}{
			"openai": map[string]interface{}{
				"type":    "openai",
				"enabled": true,
			},
		},
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.LLM)
	assert.NotNil(t, cfg.LLM.Routing)
	assert.Equal(t, "eu_strict", cfg.LLM.Routing.DataSovereigntyMode)
	assert.NotEmpty(t, cfg.LLM.Providers)
	assert.Contains(t, cfg.LLM.Providers, "openai")
	assert.Equal(t, "openai", cfg.LLM.Providers["openai"].Type)
}

func TestLoad_WithoutComplianceBlock(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Nil(t, cfg.Compliance, "Compliance should be nil when compliance block is absent")
	assert.Empty(t, cfg.ControllerDeclarations().Name, "accessor returns zero value when absent")
}

func TestLoad_WithComplianceBlock(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")

	viper.Set("compliance", map[string]interface{}{
		"controller": map[string]interface{}{
			"name":        "Example GmbH",
			"contact":     "privacy@example.eu",
			"dpo_contact": "dpo@example.eu",
			"address":     "Examplestr. 1, 10115 Berlin",
		},
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Compliance)
	require.NotNil(t, cfg.Compliance.Controller)
	decl := cfg.ControllerDeclarations()
	assert.Equal(t, "Example GmbH", decl.Name)
	assert.Equal(t, "privacy@example.eu", decl.Contact)
	assert.Equal(t, "dpo@example.eu", decl.DPOContact)
	assert.Equal(t, "Examplestr. 1, 10115 Berlin", decl.Address)
}

func TestLoad_WithPartialComplianceBlock(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")

	viper.Set("compliance", map[string]interface{}{
		"controller": map[string]interface{}{
			"name": "Example GmbH",
		},
	})

	cfg, err := Load()
	require.NoError(t, err)
	decl := cfg.ControllerDeclarations()
	assert.Equal(t, "Example GmbH", decl.Name)
	assert.Empty(t, decl.Contact)
	assert.Empty(t, decl.DPOContact)
}

func TestExampleDockerComposeEnvKeys(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	composeFiles := []string{
		filepath.Join(repoRoot, "examples", "shortlist-demo", "docker-compose.yml"),
		filepath.Join(repoRoot, "examples", "docker-compose", "docker-compose.yml"),
	}
	secretsRE := regexp.MustCompile(`TALON_SECRETS_KEY=([^\s#]+)`)
	signingRE := regexp.MustCompile(`TALON_SIGNING_KEY=([^\s#]+)`)

	for _, path := range composeFiles {
		path := path
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			data, err := os.ReadFile(path)
			require.NoError(t, err)

			m := secretsRE.FindSubmatch(data)
			require.NotNil(t, m, "TALON_SECRETS_KEY in %s", path)
			resetViper(t)
			t.Setenv("TALON_SECRETS_KEY", string(m[1]))
			if sm := signingRE.FindSubmatch(data); sm != nil {
				t.Setenv("TALON_SIGNING_KEY", string(sm[1]))
			}
			_, err = Load()
			require.NoError(t, err, "compose env keys in %s", path)
		})
	}
}

func TestResolveSovereignty_AirGapImpliesEUStrict(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	viper.Set("sovereignty", map[string]interface{}{"deployment_mode": "air_gap"})

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, DataSovereigntyEUStrict, cfg.EffectiveSovereigntyMode())
	require.NotNil(t, cfg.LLM)
	require.NotNil(t, cfg.LLM.Routing)
	assert.Equal(t, DataSovereigntyEUStrict, cfg.LLM.Routing.DataSovereigntyMode)
}

func TestResolveSovereignty_ModeSupersedesRouting(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	viper.Set("sovereignty", map[string]interface{}{"mode": "eu_strict"})
	viper.Set("llm", map[string]interface{}{
		"routing": map[string]interface{}{"data_sovereignty_mode": "global"},
	})

	cfg, err := Load()
	require.NoError(t, err)
	// sovereignty.mode is the source of truth and overrides the conflicting routing value.
	assert.Equal(t, DataSovereigntyEUStrict, cfg.EffectiveSovereigntyMode())
	assert.Equal(t, DataSovereigntyEUStrict, cfg.LLM.Routing.DataSovereigntyMode)
}

func TestResolveSovereignty_InvalidMode(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	viper.Set("sovereignty", map[string]interface{}{"mode": "eu_only"})

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sovereignty.mode")
}

func TestResolveSovereignty_AirGapConflictsWithLooserMode(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	viper.Set("sovereignty", map[string]interface{}{
		"deployment_mode": "air_gap",
		"mode":            "global",
	})

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "air_gap")
}

func TestEffectiveSovereigntyMode_FallbackToRouting(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	viper.Set("llm", map[string]interface{}{
		"routing": map[string]interface{}{"data_sovereignty_mode": "eu_preferred"},
	})

	cfg, err := Load()
	require.NoError(t, err)
	assert.Nil(t, cfg.Sovereignty)
	assert.Equal(t, DataSovereigntyEUPreferred, cfg.EffectiveSovereigntyMode())
}

func TestResolveSovereignty_InvalidDeploymentMode(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SECRETS_KEY", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("TALON_SIGNING_KEY", "my-signing-key-at-least-32-chars!")
	viper.Set("sovereignty", map[string]interface{}{"deployment_mode": "offline"})

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deployment_mode")
}

// TestResolveSovereigntyForGateway_WeakOperatorBlockUpgradedByGatewayAirGap is
// the regression for the doctor/serve "merge is fragile" bug: a weak (standard)
// operator sovereignty block must NOT mask a stronger air_gap block declared in
// the gateway config file.
func TestResolveSovereigntyForGateway_WeakOperatorBlockUpgradedByGatewayAirGap(t *testing.T) {
	dir := t.TempDir()
	gwPath := filepath.Join(dir, "talon.config.airgap.yaml")
	require.NoError(t, os.WriteFile(gwPath, []byte("sovereignty:\n  deployment_mode: air_gap\n  allowed_egress_hosts: [\"llm.internal.example\"]\n"), 0o600))

	op := &Config{Sovereignty: &SovereigntyConfig{
		DeploymentMode:     SovereigntyModeStandard,
		AllowedEgressHosts: []string{"ops.internal.example"},
	}}
	require.NoError(t, ResolveSovereigntyForGateway(op, gwPath))

	assert.True(t, op.Sovereignty.AirGapEnabled(), "gateway air_gap must override operator standard")
	assert.Equal(t, DataSovereigntyEUStrict, op.EffectiveSovereigntyMode())
	require.NotNil(t, op.LLM)
	require.NotNil(t, op.LLM.Routing)
	assert.Equal(t, DataSovereigntyEUStrict, op.LLM.Routing.DataSovereigntyMode)
	// allowed_egress_hosts from both sources are unioned, not replaced.
	assert.Contains(t, op.Sovereignty.AllowedEgressHosts, "ops.internal.example")
	assert.Contains(t, op.Sovereignty.AllowedEgressHosts, "llm.internal.example")
}

func TestResolveSovereigntyForGateway_AirGapPlusOperatorGlobalErrors(t *testing.T) {
	dir := t.TempDir()
	gwPath := filepath.Join(dir, "talon.config.airgap.yaml")
	require.NoError(t, os.WriteFile(gwPath, []byte("sovereignty:\n  deployment_mode: air_gap\n"), 0o600))

	// Operator explicitly demands global; the gateway demands air_gap. This is a
	// genuine conflict (air_gap implies eu_strict) and must fail closed.
	op := &Config{Sovereignty: &SovereigntyConfig{SovereigntyMode: DataSovereigntyGlobal}}
	err := ResolveSovereigntyForGateway(op, gwPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "air_gap")
}

func TestResolveSovereigntyForGateway_NoGatewaySovereigntyIsNoop(t *testing.T) {
	dir := t.TempDir()
	gwPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(gwPath, []byte("gateway:\n  enabled: true\n"), 0o600))

	op := &Config{Sovereignty: &SovereigntyConfig{SovereigntyMode: DataSovereigntyEUPreferred}}
	require.NoError(t, ResolveSovereigntyForGateway(op, gwPath))
	assert.Equal(t, DataSovereigntyEUPreferred, op.EffectiveSovereigntyMode())
}

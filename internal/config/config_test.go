package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Len(t, cfg.SecretsKey, 32)
	assert.True(t, len(cfg.SigningKey) >= 32)
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
	assert.Contains(t, err.Error(), "secrets_key must be exactly 32 bytes")
}

func TestLoad_InvalidSigningKeyLength(t *testing.T) {
	resetViper(t)
	t.Setenv("TALON_SIGNING_KEY", "short")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing_key must be at least 32 bytes")
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
	assert.Len(t, k1, 32)
}

func TestDeriveDefaultKey_DifferentSalts(t *testing.T) {
	k1 := deriveDefaultKey("/data", "secrets-encryption")
	k2 := deriveDefaultKey("/data", "evidence-signing--")
	assert.NotEqual(t, k1, k2)
}

func TestDeriveDefaultKey_DifferentPaths(t *testing.T) {
	k1 := deriveDefaultKey("/home/alice/.talon", "salt")
	k2 := deriveDefaultKey("/home/bob/.talon", "salt")
	assert.NotEqual(t, k1, k2)
}

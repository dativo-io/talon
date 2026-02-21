// Package config holds OPERATOR-LEVEL configuration for a Talon installation.
//
// This is infrastructure config set by the DevOps/admin who deploys Talon,
// NOT tenant or end-user configuration. The boundary is:
//
//   - Operator config (this package): data directory, vault encryption key,
//     evidence signing key, Ollama URL, attachment limits, log settings.
//     Set via env vars (TALON_*) or config file (talon.config.yaml).
//
//   - Tenant config: LLM API keys, webhook tokens, per-agent credentials.
//     Stored ONLY in the encrypted secrets vault (internal/secrets).
//     Managed via "talon secrets set" or the HTTP API.
//     Every access is ACL-checked and audit-logged.
//
// Tenant credentials MUST NEVER appear in this config or in env vars
// in production. Env vars like OPENAI_API_KEY are supported solely as
// a quickstart fallback for single-tenant development; the runner logs
// a warning when they are used instead of vault-stored keys.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/dativo-io/talon/internal/cryptoutil"
)

// Viper keys. Each maps to an env var with the TALON_ prefix
// (e.g. "secrets_key" → TALON_SECRETS_KEY) and to a YAML field
// in talon.config.yaml (e.g. secrets_key: "...").
const (
	KeyDataDir         = "data_dir"
	KeySecretsKey      = "secrets_key"
	KeySigningKey      = "signing_key"
	KeyDefaultPolicy   = "default_policy"
	KeyMaxAttachmentMB = "max_attachment_mb"
	KeyOllamaBaseURL   = "ollama_base_url"
)

// Defaults that do NOT involve crypto material. Crypto keys intentionally
// have no baked-in defaults — when unset we generate a deterministic
// per-machine fallback and warn loudly.
const (
	DefaultPolicy      = "agent.talon.yaml"
	DefaultMaxAttachMB = 10
	DefaultOllamaURL   = "http://localhost:11434"
)

// Config holds resolved operator-level configuration for a Talon process.
// For tenant-level secrets (LLM API keys, webhook tokens), use the
// secrets vault (internal/secrets.SecretStore).
type Config struct {
	DataDir         string // Base directory for all state (~/.talon)
	SecretsKey      string // AES-256 encryption key for the vault (exactly 32 bytes)
	SigningKey      string // HMAC-SHA256 key for evidence signing (≥32 bytes)
	DefaultPolicy   string // Default policy filename
	MaxAttachmentMB int    // Maximum attachment size in MB
	OllamaBaseURL   string // Ollama API endpoint (operator infrastructure)

	usingDefaultSecretsKey bool
	usingDefaultSigningKey bool
}

// UsingDefaultKeys returns true if either crypto key fell back to
// a generated default. Commands should warn when this is the case.
func (c *Config) UsingDefaultKeys() bool {
	return c.usingDefaultSecretsKey || c.usingDefaultSigningKey
}

// UsingDefaultSecretsKey returns true if the secrets encryption key was derived (not set explicitly).
func (c *Config) UsingDefaultSecretsKey() bool {
	return c.usingDefaultSecretsKey
}

// UsingDefaultSigningKey returns true if the evidence signing key was derived (not set explicitly).
func (c *Config) UsingDefaultSigningKey() bool {
	return c.usingDefaultSigningKey
}

// SecretsDBPath returns the full path to the secrets SQLite database.
func (c *Config) SecretsDBPath() string {
	return filepath.Join(c.DataDir, "secrets.db")
}

// EvidenceDBPath returns the full path to the evidence SQLite database.
func (c *Config) EvidenceDBPath() string {
	return filepath.Join(c.DataDir, "evidence.db")
}

// MemoryDBPath returns the full path to the memory SQLite database.
func (c *Config) MemoryDBPath() string {
	return filepath.Join(c.DataDir, "memory.db")
}

// EnsureDataDir creates the data directory if it doesn't exist.
func (c *Config) EnsureDataDir() error {
	return os.MkdirAll(c.DataDir, 0o700)
}

// WarnIfDefaultKeys logs a warning when crypto keys are not explicitly set.
// Suppressed when TALON_QUICKSTART=1 or true (e.g. first-time exploration, demos).
func (c *Config) WarnIfDefaultKeys() {
	if isQuickstart() {
		return
	}
	if c.usingDefaultSecretsKey {
		log.Warn().Msg("Using generated default TALON_SECRETS_KEY — set via env var or config file for production")
	}
	if c.usingDefaultSigningKey {
		log.Warn().Msg("Using generated default TALON_SIGNING_KEY — set via env var or config file for production")
	}
}

func isQuickstart() bool {
	v := os.Getenv("TALON_QUICKSTART")
	return v == "1" || v == "true" || v == "TRUE"
}

func init() {
	viper.SetEnvPrefix("TALON")
	viper.AutomaticEnv()
	viper.SetDefault(KeyDefaultPolicy, DefaultPolicy)
	viper.SetDefault(KeyMaxAttachmentMB, DefaultMaxAttachMB)
	viper.SetDefault(KeyOllamaBaseURL, DefaultOllamaURL)
}

// Load reads configuration from Viper (which merges env vars, config
// file, and defaults) and returns a validated Config.
func Load() (*Config, error) {
	cfg := &Config{
		DataDir:         resolveDataDir(),
		SecretsKey:      viper.GetString(KeySecretsKey),
		SigningKey:      viper.GetString(KeySigningKey),
		DefaultPolicy:   viper.GetString(KeyDefaultPolicy),
		MaxAttachmentMB: viper.GetInt(KeyMaxAttachmentMB),
		OllamaBaseURL:   viper.GetString(KeyOllamaBaseURL),
	}

	if cfg.SecretsKey == "" {
		cfg.SecretsKey = deriveDefaultKey(cfg.DataDir, "secrets-encryption")
		cfg.usingDefaultSecretsKey = true
	}
	if cfg.SigningKey == "" {
		cfg.SigningKey = deriveDefaultKey(cfg.DataDir, "evidence-signing--")
		cfg.usingDefaultSigningKey = true
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

func resolveDataDir() string {
	if dir := viper.GetString(KeyDataDir); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".talon"
	}
	return filepath.Join(home, ".talon")
}

// deriveDefaultKey produces a deterministic 32-byte fallback key from the
// data directory path and a salt. Uses SHA-256 so the full salt always
// contributes to the output regardless of path length. This is NOT
// cryptographically strong — it exists solely so `talon init && talon run`
// works out of the box while still encrypting data at rest with a
// per-machine-unique key.
func deriveDefaultKey(dataDir, salt string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("talon:%s:%s", dataDir, salt)))
	return hex.EncodeToString(h[:])
}

func (c *Config) validate() error {
	if err := validateSecretsKey(c.SecretsKey); err != nil {
		return err
	}
	if err := validateSigningKey(c.SigningKey); err != nil {
		return err
	}
	if c.MaxAttachmentMB <= 0 {
		return fmt.Errorf("max_attachment_mb must be positive")
	}
	return nil
}

// validateSecretsKey accepts either 32 raw bytes or 64 hex characters (decodes to 32 bytes for AES-256).
func validateSecretsKey(key string) error {
	n := len(key)
	if n == 32 {
		return nil
	}
	if n == 64 && cryptoutil.IsHexString(key) {
		decoded, err := hex.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			return fmt.Errorf("secrets_key hex must decode to 32 bytes: %w", err)
		}
		return nil
	}
	return fmt.Errorf("secrets_key must be exactly 32 bytes or 64 hex characters (got %d); set TALON_SECRETS_KEY", n)
}

// validateSigningKey accepts either ≥32 raw bytes or ≥64 hex characters (decoded length ≥32 for HMAC-SHA256).
// Hex is checked first (disjoint from raw) so that hex format is validated; raw is accepted otherwise when n ≥ 32.
func validateSigningKey(key string) error {
	n := len(key)
	if n >= 64 && n%2 == 0 && cryptoutil.IsHexString(key) {
		decoded, err := hex.DecodeString(key)
		if err != nil || len(decoded) < 32 {
			return fmt.Errorf("signing_key hex must decode to at least 32 bytes: %w", err)
		}
		return nil
	}
	if n >= 32 {
		return nil
	}
	return fmt.Errorf("signing_key must be at least 32 bytes or 64+ hex characters (got %d); set TALON_SIGNING_KEY", n)
}

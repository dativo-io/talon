package llm

import (
	"context"
	"errors"
)

// ErrNoAPIKey is returned when no API key can be resolved for a provider.
var ErrNoAPIKey = errors.New("no API key available for provider")

// KeyResolver resolves an API key for a given LLM provider, scoped to
// the requesting tenant. This is the mechanism through which tenant
// credentials flow from the encrypted secrets vault into LLM providers
// at runtime — never baked in at startup.
//
// Implementations should try the vault first (tenant-scoped, ACL-checked,
// audit-logged) and fall back to operator-level env vars only for
// single-tenant development.
type KeyResolver func(ctx context.Context, providerName string) (string, error)

// NewProviderWithKey creates a fresh Provider for the named backend using
// the given API key. Returns nil for providers that don't use API keys
// (ollama, bedrock).
func NewProviderWithKey(providerName, apiKey string) Provider {
	switch providerName {
	case "openai":
		return NewOpenAIProvider(apiKey)
	case "anthropic":
		return NewAnthropicProvider(apiKey)
	default:
		return nil
	}
}

// ProviderUsesAPIKey reports whether the named provider requires an API key.
// Ollama (local) and Bedrock (IAM-based) do not.
func ProviderUsesAPIKey(providerName string) bool {
	switch providerName {
	case "openai", "anthropic":
		return true
	default:
		return false
	}
}

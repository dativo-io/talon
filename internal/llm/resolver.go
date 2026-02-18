package llm

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

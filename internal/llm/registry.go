package llm

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProviderFactory creates a Provider from raw config bytes.
// When configYAML is nil, the factory returns a minimal instance
// with valid Metadata() for wizard/compliance queries (no API calls possible).
type ProviderFactory func(configYAML []byte) (Provider, error)

var registry = map[string]ProviderFactory{}

// Register adds a provider factory to the registry.
// Call from an init() function in each provider package.
// Panics on duplicate registration (caught at startup, not runtime).
func Register(providerType string, factory ProviderFactory) {
	if _, exists := registry[providerType]; exists {
		panic(fmt.Sprintf("llm: provider type %q already registered", providerType))
	}
	registry[providerType] = factory
}

// NewProvider creates a provider instance from talon.config.yaml config bytes.
func NewProvider(providerType string, configYAML []byte) (Provider, error) {
	factory, ok := registry[providerType]
	if !ok {
		return nil, fmt.Errorf(
			"unknown provider type %q — available: %v\n"+
				"To add a provider: see docs/contributor/adding-a-provider.md",
			providerType, registeredTypes(),
		)
	}
	return factory(configYAML)
}

// ListForWizard returns all registered providers in wizard display order,
// excluding hidden providers.
// When euStrictFilter is true, providers with non-EU, non-LOCAL jurisdiction
// and no EU regions are excluded.
func ListForWizard(euStrictFilter bool) []ProviderMetadata {
	var result []ProviderMetadata
	for _, factory := range registry {
		p, err := factory(nil) // nil config — just read metadata
		if err != nil {
			continue
		}
		meta := p.Metadata()
		if meta.Wizard.Hidden {
			continue
		}
		if euStrictFilter {
			isEUOrLocal := meta.Jurisdiction == "EU" || meta.Jurisdiction == "LOCAL"
			hasEURegions := len(meta.EURegions) > 0
			if !isEUOrLocal && !hasEURegions {
				continue
			}
		}
		result = append(result, meta)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Wizard.Order != result[j].Wizard.Order {
			return result[i].Wizard.Order < result[j].Wizard.Order
		}
		return result[i].DisplayName < result[j].DisplayName
	})
	return result
}

// AllRegisteredProviders returns one instance per registered type.
// Used by compliance validation tests. Not used in production paths.
func AllRegisteredProviders() []Provider {
	var result []Provider
	for _, factory := range registry {
		p, err := factory(nil)
		if err != nil {
			continue
		}
		result = append(result, p)
	}
	return result
}

// JurisdictionForProvider returns the registered provider's jurisdiction
// ("EU", "US", "LOCAL", ...) from its static metadata, or "" when the
// provider type is not registered. No network calls.
func JurisdictionForProvider(providerType string) string {
	meta, ok := ProviderMetadataByType(providerType)
	if !ok {
		return ""
	}
	return meta.Jurisdiction
}

// RegionAwareProvider reports whether the provider type has a region dimension
// that affects data residency (e.g. Bedrock, Azure OpenAI, Vertex). For these
// providers the configured region — not just the jurisdiction — determines
// whether traffic stays in the EU.
func RegionAwareProvider(providerType string) bool {
	meta, ok := ProviderMetadataByType(providerType)
	if !ok {
		return false
	}
	return meta.Wizard.RequiresRegion || len(meta.EURegions) > 0
}

// IsEURegion reports whether the given configured region for a provider type is
// an EU region. It consults the provider's declared EURegions first, then the
// wizard AvailableRegions IsEU flags. Returns false for unknown providers,
// empty regions, or regions not declared as EU (fail closed).
func IsEURegion(providerType, region string) bool {
	meta, ok := ProviderMetadataByType(providerType)
	if !ok {
		return false
	}
	r := strings.TrimSpace(region)
	if r == "" {
		return false
	}
	for _, er := range meta.EURegions {
		if strings.EqualFold(er, r) {
			return true
		}
	}
	for _, ar := range meta.Wizard.AvailableRegions {
		if strings.EqualFold(ar.ID, r) {
			return ar.IsEU
		}
	}
	return false
}

// ProviderMetadataByType returns the static metadata for a registered provider
// type (jurisdiction, EU regions, etc.) without making network calls. The second
// return value is false when the provider type is not registered.
func ProviderMetadataByType(providerType string) (ProviderMetadata, bool) {
	factory, ok := registry[providerType]
	if !ok {
		return ProviderMetadata{}, false
	}
	p, err := factory(nil) // nil config — metadata only
	if err != nil || p == nil {
		return ProviderMetadata{}, false
	}
	return p.Metadata(), true
}

// RegisteredTypes returns the list of registered provider type names (sorted).
func RegisteredTypes() []string {
	return registeredTypes()
}

func registeredTypes() []string {
	types := make([]string, 0, len(registry))
	for t := range registry {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// resetRegistryForTest clears the registry. For use in tests only.
func resetRegistryForTest() {
	registry = map[string]ProviderFactory{}
}

// NewProviderWithKey creates a provider with the given API key. Used when resolving
// keys from the vault at request time. Only works for providers that use a single API key.
// Returns (nil, nil) for providers that don't use API keys (ollama, bedrock).
func NewProviderWithKey(providerType, apiKey string) (Provider, error) {
	cfg := map[string]string{"api_key": apiKey}
	cfgYAML, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	switch providerType {
	case "openai":
		return NewProvider("openai", cfgYAML)
	case "anthropic":
		return NewProvider("anthropic", cfgYAML)
	default:
		return nil, nil
	}
}

// ProviderUsesAPIKey reports whether the named provider requires an API key (from vault/env).
func ProviderUsesAPIKey(providerType string) bool {
	switch providerType {
	case "openai", "anthropic":
		return true
	default:
		return false
	}
}

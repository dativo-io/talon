package sovereignty

import (
	"fmt"
	"os"
	"strings"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/llm"
)

// operatorKeyedProviders maps an operator-level env var to the provider type it
// configures. When the env var is set the operator has explicitly declared that
// provider, so it must satisfy the sovereignty gate (fail closed).
var operatorKeyedProviders = []struct {
	env      string
	provider string
}{
	{env: "OPENAI_API_KEY", provider: "openai"},
	{env: "ANTHROPIC_API_KEY", provider: "anthropic"},
}

// AllowsProvider reports whether a provider type is permitted under the given
// data-sovereignty mode. Only eu_strict imposes a hard gate: a provider is
// allowed when its jurisdiction is EU or LOCAL, or it exposes at least one EU
// region (e.g. Bedrock eu-central-1, Azure westeurope). eu_preferred and global
// allow all providers (routing applies preference). Unknown provider types are
// allowed here and rejected by the registry's own validation.
func AllowsProvider(mode, providerType string) bool {
	switch mode {
	case config.DataSovereigntyEUStrict:
		meta, ok := llm.ProviderMetadataByType(providerType)
		if !ok {
			return true
		}
		j := strings.ToUpper(strings.TrimSpace(meta.Jurisdiction))
		return j == "EU" || j == "LOCAL" || len(meta.EURegions) > 0
	default:
		return true
	}
}

// ValidateSovereignty enforces the effective data-sovereignty mode against every
// declared provider (fail closed). For eu_strict, operator-keyed providers,
// llm.providers entries, and enabled gateway providers must all be EU/LOCAL (or
// EU-region capable). eu_preferred and global impose no hard provider gate.
// air_gap implies eu_strict via config resolution, so this also covers air-gap.
func ValidateSovereignty(op *config.Config, gw *gateway.GatewayConfig) error {
	if op == nil {
		return nil
	}
	mode := op.EffectiveSovereigntyMode()
	if mode != config.DataSovereigntyEUStrict {
		return nil
	}
	if err := validateOperatorProviders(op, mode); err != nil {
		return err
	}
	return validateGatewayProviders(gw, mode)
}

// validateOperatorProviders fails closed when an operator has explicitly
// configured a provider (via env key or the llm.providers block) that is not
// permitted under the sovereignty mode.
func validateOperatorProviders(op *config.Config, mode string) error {
	for _, kp := range operatorKeyedProviders {
		if os.Getenv(kp.env) == "" {
			continue
		}
		if !AllowsProvider(mode, kp.provider) {
			return fmt.Errorf(
				"sovereignty mode %s: %s is set but provider %q (%s jurisdiction) is not EU/LOCAL — remove the key or relax sovereignty.mode",
				mode, kp.env, kp.provider, llm.JurisdictionForProvider(kp.provider))
		}
	}
	if op.LLM != nil {
		for id := range op.LLM.Providers {
			if !AllowsProvider(mode, id) {
				return fmt.Errorf(
					"sovereignty mode %s: llm.providers includes %q (%s jurisdiction) which is not EU/LOCAL",
					mode, id, llm.JurisdictionForProvider(id))
			}
		}
	}
	return nil
}

// validateGatewayProviders fails closed when an enabled gateway upstream is
// declared in a region that is not permitted under the sovereignty mode.
func validateGatewayProviders(gw *gateway.GatewayConfig, mode string) error {
	if gw == nil {
		return nil
	}
	for name := range gw.Providers {
		p := gw.Providers[name]
		if !p.Enabled {
			continue
		}
		region := strings.ToUpper(strings.TrimSpace(p.Region))
		if region == "" {
			return fmt.Errorf("sovereignty mode %s: gateway provider %q region must be set (EU or LOCAL)", mode, name)
		}
		if region != "EU" && region != "LOCAL" {
			return fmt.Errorf("sovereignty mode %s: gateway provider %q region %q is not permitted (use EU or LOCAL)", mode, name, region)
		}
	}
	return nil
}

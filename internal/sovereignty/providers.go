package sovereignty

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/llm"
)

// ExclusionScope identifies where a declared provider was configured.
type ExclusionScope string

const (
	ExclusionScopeEnv          ExclusionScope = "env"
	ExclusionScopeLLMProviders ExclusionScope = "llm.providers"
	ExclusionScopeGateway      ExclusionScope = "gateway"
)

// Exclusion describes a provider explicitly declared by the operator that is
// excluded from routing under the effective sovereignty mode.
type Exclusion struct {
	Provider string
	Scope    ExclusionScope
	Reason   string
}

// Evaluation is the result of evaluating declared providers against the
// effective data-sovereignty mode.
type Evaluation struct {
	Excluded                  []Exclusion
	CompliantGatewayProviders []string
	HasRoutableProvider       bool
}

// operatorKeyedProviders maps an operator-level env var to the provider type it
// configures. When the env var is set the operator has explicitly declared that
// provider.
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
// rejected under eu_strict (fail closed).
func AllowsProvider(mode, providerType string) bool {
	switch mode {
	case config.DataSovereigntyEUStrict:
		meta, ok := llm.ProviderMetadataByType(providerType)
		if !ok {
			return false
		}
		j := strings.ToUpper(strings.TrimSpace(meta.Jurisdiction))
		return j == "EU" || j == "LOCAL" || len(meta.EURegions) > 0
	default:
		return true
	}
}

// EvaluateSovereignty classifies declared providers as compliant or excluded
// under the effective sovereignty mode. Under eu_strict, non-EU/LOCAL declared
// providers are excluded (non-fatal); eu_preferred and global impose no gate.
func EvaluateSovereignty(op *config.Config, gw *gateway.GatewayConfig) Evaluation {
	if op == nil {
		return Evaluation{HasRoutableProvider: true}
	}
	mode := op.EffectiveSovereigntyMode()
	if mode != config.DataSovereigntyEUStrict {
		return Evaluation{HasRoutableProvider: true}
	}

	eval := Evaluation{}
	evalExcluded, compliantOperator := evaluateOperatorProviders(op, mode)
	eval.Excluded = append(eval.Excluded, evalExcluded...)

	gwExcluded, compliantGW := evaluateGatewayProviders(gw, mode)
	eval.Excluded = append(eval.Excluded, gwExcluded...)
	eval.CompliantGatewayProviders = compliantGW

	eval.HasRoutableProvider = len(compliantGW) > 0 || compliantOperator
	if gw == nil && !eval.HasRoutableProvider {
		// Native run/plan always registers ollama (LOCAL) via buildProviders.
		eval.HasRoutableProvider = true
	}
	return eval
}

// LogSovereigntyExclusions emits ERROR logs and metrics for each declared
// provider excluded under eu_strict.
func LogSovereigntyExclusions(excluded []Exclusion) {
	for _, ex := range excluded {
		log.Error().
			Str("provider", ex.Provider).
			Str("scope", string(ex.Scope)).
			Str("reason", ex.Reason).
			Msg("provider excluded by sovereignty mode")
		RecordProviderExcluded(context.Background(), ex.Provider, string(ex.Scope))
	}
}

// ApplySovereigntyGate evaluates exclusions and logs them. Call before
// buildProviders in serve, run, and plan.
func ApplySovereigntyGate(op *config.Config, gw *gateway.GatewayConfig) Evaluation {
	eval := EvaluateSovereignty(op, gw)
	LogSovereigntyExclusions(eval.Excluded)
	return eval
}

func evaluateOperatorProviders(op *config.Config, mode string) (excluded []Exclusion, hasCompliant bool) {
	for _, kp := range operatorKeyedProviders {
		if os.Getenv(kp.env) == "" {
			continue
		}
		if AllowsProvider(mode, kp.provider) {
			hasCompliant = true
			continue
		}
		excluded = append(excluded, Exclusion{
			Provider: kp.provider,
			Scope:    ExclusionScopeEnv,
			Reason: fmt.Sprintf(
				"%s is set but provider %q (%s jurisdiction) is not EU/LOCAL",
				kp.env, kp.provider, llm.JurisdictionForProvider(kp.provider)),
		})
	}
	if op.LLM != nil {
		for id, p := range op.LLM.Providers {
			if !p.Enabled {
				continue
			}
			providerType := p.Type
			if providerType == "" {
				providerType = id
			}
			if AllowsProvider(mode, providerType) {
				hasCompliant = true
				continue
			}
			excluded = append(excluded, Exclusion{
				Provider: providerType,
				Scope:    ExclusionScopeLLMProviders,
				Reason: fmt.Sprintf(
					"llm.providers includes %q (type %q, %s jurisdiction) which is not EU/LOCAL",
					id, providerType, llm.JurisdictionForProvider(providerType)),
			})
		}
	}
	return excluded, hasCompliant
}

func evaluateGatewayProviders(gw *gateway.GatewayConfig, mode string) (excluded []Exclusion, compliant []string) {
	if gw == nil {
		return nil, nil
	}
	for name := range gw.Providers {
		p := gw.Providers[name]
		if !p.Enabled {
			continue
		}
		region := strings.ToUpper(strings.TrimSpace(p.Region))
		if region == "" {
			excluded = append(excluded, Exclusion{
				Provider: name,
				Scope:    ExclusionScopeGateway,
				Reason:   fmt.Sprintf("gateway provider %q region must be set (EU or LOCAL)", name),
			})
			continue
		}
		if region != "EU" && region != "LOCAL" {
			excluded = append(excluded, Exclusion{
				Provider: name,
				Scope:    ExclusionScopeGateway,
				Reason: fmt.Sprintf(
					"gateway provider %q region %q is not permitted under %s (use EU or LOCAL)",
					name, region, mode),
			})
			continue
		}
		compliant = append(compliant, name)
	}
	return excluded, compliant
}

// IsGatewayProviderExcluded reports whether a gateway provider name was
// excluded during sovereignty evaluation (eu_strict, non-EU/LOCAL region).
func IsGatewayProviderExcluded(eval Evaluation, provider string) bool {
	for _, ex := range eval.Excluded {
		if ex.Scope == ExclusionScopeGateway && ex.Provider == provider {
			return true
		}
	}
	return false
}

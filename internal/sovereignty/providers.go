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

	// GatewayEvaluated is true when a non-nil gateway config was evaluated
	// (the doctor/serve gateway path). When false, this is a native run/plan
	// path that routes to operator/native providers only.
	GatewayEvaluated bool
	// HasCompliantGatewayProvider is true when at least one enabled gateway
	// provider satisfies the sovereignty mode (EU/LOCAL region).
	HasCompliantGatewayProvider bool
	// HasCompliantOperatorProvider is true when at least one operator/native
	// provider (env keys, llm.providers, implicit local ollama) is routable.
	HasCompliantOperatorProvider bool
	// HasRoutableProvider is the union of gateway and operator routability.
	// Callers that need gateway-only routability (e.g. talon doctor with
	// --gateway-config) must use HasCompliantGatewayProvider instead.
	HasRoutableProvider bool
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
// data-sovereignty mode without a configured region. It is a convenience
// wrapper over AllowsProviderRegion with an empty region. For region-aware
// providers (Bedrock, Azure OpenAI, Vertex) callers SHOULD use
// AllowsProviderRegion with the configured region; with an empty region this
// only trusts EU-jurisdiction providers (fail closed for US-based providers
// that merely *offer* EU regions).
func AllowsProvider(mode, providerType string) bool {
	return AllowsProviderRegion(mode, providerType, "")
}

// AllowsProviderRegion reports whether a provider type with a specific
// configured region is permitted under the given data-sovereignty mode. Only
// eu_strict imposes a hard gate:
//
//   - LOCAL jurisdiction providers (e.g. ollama) are always allowed.
//   - Region-aware providers (Bedrock, Azure OpenAI, Vertex — those that
//     require/accept a region) are allowed only when the *configured* region is
//     an EU region. When no region is configured, only EU-jurisdiction
//     providers are trusted; US-based providers that merely offer EU regions
//     (e.g. Bedrock) are excluded (fail closed).
//   - All other providers are allowed only when their jurisdiction is EU.
//
// eu_preferred and global allow all providers (routing applies preference).
// Unknown provider types are rejected under eu_strict (fail closed).
func AllowsProviderRegion(mode, providerType, region string) bool {
	if mode != config.DataSovereigntyEUStrict {
		return true
	}
	meta, ok := llm.ProviderMetadataByType(providerType)
	if !ok {
		return false
	}
	j := strings.ToUpper(strings.TrimSpace(meta.Jurisdiction))
	if j == "LOCAL" {
		return true
	}
	if llm.RegionAwareProvider(providerType) {
		r := strings.TrimSpace(region)
		if r == "" {
			// Cannot affirm EU residency without a region; trust only
			// providers whose base jurisdiction is EU.
			return j == "EU"
		}
		return llm.IsEURegion(providerType, r)
	}
	return j == "EU"
}

// EvaluateSovereignty classifies declared providers as compliant or excluded
// under the effective sovereignty mode. Under eu_strict, non-EU/LOCAL declared
// providers are excluded (non-fatal); eu_preferred and global impose no gate.
func EvaluateSovereignty(op *config.Config, gw *gateway.GatewayConfig) Evaluation {
	if op == nil {
		return Evaluation{HasRoutableProvider: true, HasCompliantOperatorProvider: true}
	}
	mode := op.EffectiveSovereigntyMode()
	if mode != config.DataSovereigntyEUStrict {
		return Evaluation{
			GatewayEvaluated:             gw != nil,
			HasRoutableProvider:          true,
			HasCompliantOperatorProvider: true,
			HasCompliantGatewayProvider:  gw != nil,
		}
	}

	eval := Evaluation{GatewayEvaluated: gw != nil}
	evalExcluded, compliantOperator := evaluateOperatorProviders(op, mode)
	eval.Excluded = append(eval.Excluded, evalExcluded...)

	gwExcluded, compliantGW := evaluateGatewayProviders(gw, mode)
	eval.Excluded = append(eval.Excluded, gwExcluded...)
	eval.CompliantGatewayProviders = compliantGW
	eval.HasCompliantGatewayProvider = len(compliantGW) > 0

	eval.HasCompliantOperatorProvider = compliantOperator
	if gw == nil {
		// Native run/plan always registers ollama (LOCAL) via buildProviders.
		eval.HasCompliantOperatorProvider = true
	}

	eval.HasRoutableProvider = eval.HasCompliantGatewayProvider || eval.HasCompliantOperatorProvider
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
		if AllowsProviderRegion(mode, kp.provider, "") {
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

	// AWS_REGION implicitly registers Bedrock (see buildProviders). Bedrock is a
	// US-jurisdiction, region-aware provider, so its sovereignty status depends
	// on the *configured* AWS_REGION, not merely on metadata EU-region support.
	if region := strings.TrimSpace(os.Getenv("AWS_REGION")); region != "" {
		if AllowsProviderRegion(mode, "bedrock", region) {
			hasCompliant = true
		} else {
			excluded = append(excluded, Exclusion{
				Provider: "bedrock",
				Scope:    ExclusionScopeEnv,
				Reason: fmt.Sprintf(
					"AWS_REGION=%s selects a non-EU Bedrock region; not permitted under %s",
					region, mode),
			})
		}
	}

	if op.LLM != nil {
		for id := range op.LLM.Providers {
			p := op.LLM.Providers[id]
			if !p.Enabled {
				continue
			}
			providerType := p.Type
			if providerType == "" {
				providerType = id
			}
			region := providerRegionFromConfig(p)
			if AllowsProviderRegion(mode, providerType, region) {
				hasCompliant = true
				continue
			}
			excluded = append(excluded, Exclusion{
				Provider: providerType,
				Scope:    ExclusionScopeLLMProviders,
				Reason:   operatorExclusionReason(id, providerType, region, mode),
			})
		}
	}
	return excluded, hasCompliant
}

// providerRegionFromConfig extracts a configured region from an llm.providers
// entry, if present. Returns "" when no region is configured.
func providerRegionFromConfig(p config.LLMProviderConfig) string {
	if p.Config == nil {
		return ""
	}
	if v, ok := p.Config["region"]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// operatorExclusionReason builds a human-readable exclusion reason for an
// llm.providers entry, distinguishing region-aware providers from
// jurisdiction-only ones.
func operatorExclusionReason(id, providerType, region, mode string) string {
	if llm.RegionAwareProvider(providerType) {
		if region == "" {
			return fmt.Sprintf(
				"llm.providers includes %q (type %q) with no EU region configured; not permitted under %s",
				id, providerType, mode)
		}
		return fmt.Sprintf(
			"llm.providers includes %q (type %q, region %q) which is not an EU region; not permitted under %s",
			id, providerType, region, mode)
	}
	return fmt.Sprintf(
		"llm.providers includes %q (type %q, %s jurisdiction) which is not EU/LOCAL",
		id, providerType, llm.JurisdictionForProvider(providerType))
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

// DeclaredOperatorRegions returns configured regions for operator-declared
// providers (env keys and llm.providers). Used by compliance reporting so
// region-aware providers are evaluated against their actual configured region,
// not a metadata default EU region.
func DeclaredOperatorRegions(op *config.Config) map[string]string {
	regions := make(map[string]string)
	if region := strings.TrimSpace(os.Getenv("AWS_REGION")); region != "" {
		regions["bedrock"] = region
	}
	if op != nil && op.LLM != nil {
		for id, p := range op.LLM.Providers {
			if !p.Enabled {
				continue
			}
			providerType := p.Type
			if providerType == "" {
				providerType = id
			}
			if r := providerRegionFromConfig(p); r != "" {
				regions[providerType] = r
			}
		}
	}
	return regions
}

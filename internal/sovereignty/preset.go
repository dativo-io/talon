package sovereignty

import (
	"fmt"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
)

// DefaultAirGapEgress returns the gateway egress policy applied when
// sovereignty.deployment_mode is air_gap and no explicit egress block is set.
func DefaultAirGapEgress() *gateway.EgressPolicyConfig {
	tier0 := gateway.TierLevel(0)
	tier1 := gateway.TierLevel(1)
	tier2 := gateway.TierLevel(2)
	return &gateway.EgressPolicyConfig{
		DefaultAction: gateway.EgressActionDeny,
		Rules: []gateway.EgressRule{
			{Tier: &tier0, AllowedRegions: []string{"EU", "LOCAL"}},
			{Tier: &tier1, AllowedRegions: []string{"EU", "LOCAL"}},
			{Tier: &tier2, AllowedRegions: []string{"EU", "LOCAL"}},
		},
	}
}

// ApplyAirGapPreset mutates operator and gateway config for air-gap mode:
// forces eu_strict routing, applies default egress when absent, and returns
// an egress guard built from declared upstream endpoints.
func ApplyAirGapPreset(op *config.Config, gw *gateway.GatewayConfig) (*EgressGuard, error) {
	if op == nil || op.Sovereignty == nil || !op.Sovereignty.AirGapEnabled() {
		return nil, nil
	}
	if op.LLM == nil {
		op.LLM = &config.LLMConfig{}
	}
	if op.LLM.Routing == nil {
		op.LLM.Routing = &config.LLMRoutingConfig{}
	}
	if op.LLM.Routing.DataSovereigntyMode == "" {
		op.LLM.Routing.DataSovereigntyMode = "eu_strict"
	} else if op.LLM.Routing.DataSovereigntyMode != "eu_strict" {
		return nil, fmt.Errorf("sovereignty.deployment_mode air_gap requires llm.routing.data_sovereignty_mode eu_strict (got %q)", op.LLM.Routing.DataSovereigntyMode)
	}

	if gw != nil && isEgressUnconfigured(gw.ServerDefaults.Egress) {
		gw.ServerDefaults.Egress = DefaultAirGapEgress()
	}

	allow, err := BuildAllowlist(op, gw)
	if err != nil {
		return nil, err
	}
	return NewEgressGuard(allow), nil
}

// BuildAllowlist derives permitted upstream hosts from operator config and
// enabled gateway providers. Local loopback is always permitted.
func BuildAllowlist(op *config.Config, gw *gateway.GatewayConfig) ([]string, error) {
	hosts := map[string]struct{}{
		"localhost": {},
		"127.0.0.1": {},
		"[::1]":     {},
		"::1":       {},
	}
	addHost := func(raw string) error {
		host, err := hostFromAllowEntry(raw)
		if err != nil {
			return fmt.Errorf("parsing allowed egress host %q: %w", raw, err)
		}
		if host == "" {
			return nil
		}
		hosts[host] = struct{}{}
		return nil
	}

	if op != nil {
		if err := addHost(op.OllamaBaseURL); err != nil {
			return nil, err
		}
		if op.Sovereignty != nil {
			for _, h := range op.Sovereignty.AllowedEgressHosts {
				if err := addHost(h); err != nil {
					return nil, err
				}
			}
		}
	}
	if gw != nil {
		for name := range gw.Providers {
			p := gw.Providers[name]
			if !p.Enabled {
				continue
			}
			if err := addHost(p.BaseURL); err != nil {
				return nil, err
			}
		}
	}

	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	return out, nil
}

// isEgressUnconfigured returns true when the egress policy is nil or
// effectively empty (default allow with no rules), meaning the operator
// did not provide a meaningful custom egress configuration.
func isEgressUnconfigured(e *gateway.EgressPolicyConfig) bool {
	if e == nil {
		return true
	}
	return len(e.Rules) == 0 && (e.DefaultAction == "" || e.DefaultAction == gateway.EgressActionAllow)
}

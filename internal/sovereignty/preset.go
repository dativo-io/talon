package sovereignty

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"

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
//
// Consistent with the single-source-of-truth model, air_gap forces eu_strict
// and overrides any conflicting llm.routing.data_sovereignty_mode with a warning
// rather than erroring. The genuine conflict (deployment_mode air_gap combined
// with an explicit sovereignty.mode other than eu_strict, e.g. global) is
// rejected earlier by config.resolveSovereignty during load.
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
	if op.LLM.Routing.DataSovereigntyMode != config.DataSovereigntyEUStrict {
		if op.LLM.Routing.DataSovereigntyMode != "" {
			log.Warn().
				Str("data_sovereignty_mode", op.LLM.Routing.DataSovereigntyMode).
				Msg("air_gap forces eu_strict; overriding llm.routing.data_sovereignty_mode")
		}
		op.LLM.Routing.DataSovereigntyMode = config.DataSovereigntyEUStrict
	}

	if gw != nil && isEgressUnconfigured(gw.OrganizationPolicy.Egress) {
		gw.OrganizationPolicy.Egress = DefaultAirGapEgress()
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

// VerifyEgressGuard builds the air-gap egress guard from the same inputs serve
// uses and self-tests that it blocks a synthetic, non-allowlisted host. The
// guard consults its allowlist before calling the base transport, so the probe
// makes no network call. Returns the number of allowlisted hosts (loopback plus
// declared upstreams). It returns an error only when the guard fails to block
// surprise egress — proving to `talon doctor` that a transport-level
// enforcement path exists, not merely that the config parsed.
func VerifyEgressGuard(op *config.Config, gw *gateway.GatewayConfig) (int, error) {
	allow, err := BuildAllowlist(op, gw)
	if err != nil {
		return 0, err
	}
	guard := NewEgressGuard(allow)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://surprise-egress.invalid/probe", nil)
	if err != nil {
		return 0, err
	}
	resp, rtErr := guard.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(rtErr, ErrEgressBlocked) {
		return 0, fmt.Errorf("egress guard did not block surprise egress (got %v)", rtErr)
	}
	return guard.AllowlistSize(), nil
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

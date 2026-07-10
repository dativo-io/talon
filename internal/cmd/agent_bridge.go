package cmd

import (
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
)

// LoadedAgentFromPolicy maps one parsed agent.talon.yaml onto the gateway's
// LoadedAgent. This bridge lives in cmd — the composition root that already
// imports both packages — so the gateway stays free of the policy loader and
// the policy package stays free of gateway types (#266).
//
// The override is adapted from the file's EXISTING vocabulary (one semantic,
// one field): cost_limits/session_limits for caps, capabilities for tools,
// data_classification booleans for PII actions (via their ShouldRedact*
// semantics), models/egress/allowed_providers for the gateway-only semantics.
// Semantic validation of the produced override happens at registry build.
func LoadedAgentFromPolicy(pol *policy.Policy, path string) gateway.LoadedAgent {
	la := gateway.LoadedAgent{
		Path:                 path,
		Name:                 pol.Agent.Name,
		TenantID:             pol.Agent.TenantID,
		AcceptClientMetadata: pol.Agent.AcceptClientMetadata,
		Override:             overrideFromPolicy(pol),
	}
	if pol.Agent.Key != nil {
		la.KeySecretName = pol.Agent.Key.SecretName
	}
	if pol.Metadata != nil {
		la.Team = pol.Metadata.Team
		la.Tags = append([]string(nil), pol.Metadata.Tags...)
	}
	la.AllowedProviders = append([]string(nil), pol.Policies.AllowedProviders...)
	return la
}

// overrideFromPolicy adapts the agent-file policy fields into the canonical
// gateway override. Returns nil when the file expresses no gateway-relevant
// override (the agent then runs on the organization baseline alone).
func overrideFromPolicy(pol *policy.Policy) *gateway.PolicyOverride {
	o := &gateway.PolicyOverride{}
	set := false

	if cl := pol.Policies.CostLimits; cl != nil {
		if cl.Daily > 0 {
			o.MaxDailyCost = cl.Daily
			set = true
		}
		if cl.Monthly > 0 {
			o.MaxMonthlyCost = cl.Monthly
			set = true
		}
	}
	if sl := pol.Policies.SessionLimits; sl != nil && sl.MaxCost > 0 {
		o.MaxSessionCost = sl.MaxCost
		set = true
	}

	if in, out := piiActionsFromClassification(pol.Policies.DataClassification); in != "" || out != "" {
		o.PIIAction = in
		o.ResponsePIIAction = out
		set = true
	}
	if dc := pol.Policies.DataClassification; dc != nil && dc.MaxDataTier != nil {
		tier := gateway.TierLevel(int(*dc.MaxDataTier))
		o.MaxDataTier = &tier
		set = true
	}

	if m := pol.Policies.Models; m != nil {
		o.AllowedModels = append([]string(nil), m.Allowed...)
		o.BlockedModels = append([]string(nil), m.Blocked...)
		set = set || len(m.Allowed) > 0 || len(m.Blocked) > 0
	}

	if c := pol.Capabilities; c != nil {
		o.AllowedTools = append([]string(nil), c.AllowedTools...)
		o.ForbiddenTools = append([]string(nil), c.ForbiddenTools...)
		o.ToolPolicyAction = c.ToolPolicyAction
		set = set || len(c.AllowedTools) > 0 || len(c.ForbiddenTools) > 0 || c.ToolPolicyAction != ""
	}

	if e := egressFromPolicy(pol.Policies.Egress); e != nil {
		o.Egress = e
		set = true
	}

	if !set {
		return nil
	}
	return o
}

// piiActionsFromClassification derives the gateway (input, response) PII
// actions from the data_classification booleans, mirroring the native
// runner's semantics exactly (#266):
//
//	block_on_pii                          → input block
//	input_scan && ShouldRedactInput()     → input redact
//	input_scan alone                      → input warn (scan/evidence only)
//	output_scan && block_on_pii           → response block
//	output_scan && ShouldRedactOutput()   → response redact
//	output_scan alone                     → response warn
//	nothing set                           → inherit the organization baseline
//
// The warn→allow downgrade is deliberately not expressible per agent.
func piiActionsFromClassification(dc *policy.DataClassificationConfig) (input, response string) {
	if dc == nil {
		return "", ""
	}
	switch {
	case dc.BlockOnPII:
		input = "block"
	case dc.InputScan && dc.ShouldRedactInput():
		input = "redact"
	case dc.InputScan:
		input = "warn"
	}
	if dc.OutputScan {
		switch {
		case dc.BlockOnPII:
			response = "block"
		case dc.ShouldRedactOutput():
			response = "redact"
		default:
			response = "warn"
		}
	}
	return input, response
}

// egressFromPolicy converts the policy-side egress mirror into the gateway's
// egress policy type. Semantic validation (tier range, rule shape) happens at
// registry build via the gateway's own validator.
func egressFromPolicy(e *policy.EgressConfig) *gateway.EgressPolicyConfig {
	if e == nil {
		return nil
	}
	out := &gateway.EgressPolicyConfig{DefaultAction: e.DefaultAction}
	for i := range e.Rules {
		r := e.Rules[i]
		rule := gateway.EgressRule{
			AllowedProviders: append([]string(nil), r.AllowedProviders...),
			AllowedRegions:   append([]string(nil), r.AllowedRegions...),
		}
		if r.Tier != nil {
			tier := gateway.TierLevel(int(*r.Tier))
			rule.Tier = &tier
		}
		out.Rules = append(out.Rules, rule)
	}
	return out
}

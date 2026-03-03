// Package feature provides the compliance feature registry for the talon init wizard.
// Features map to sections in agent.talon.yaml (and optionally talon.config.yaml).
// The wizard calls DefaultsForWorkload(workloadType) to show workload-appropriate features:
// proxy gets 3 features (audit, cost, pii); agent and hybrid get all 6.
package feature

import "sort"

// FeatureDescriptor describes a compliance feature shown in the talon init wizard.
//
//nolint:revive // exported name is clear at call site (feature.FeatureDescriptor)
type FeatureDescriptor struct {
	ID                string   // used in --features flag and EnabledFeatures list
	DisplayName       string   // human-readable label in wizard
	Description       string   // short description (e.g. regulation reference)
	DefaultEnabled    bool     // pre-selected in wizard
	Order             int      // sort position; lower = earlier
	AgentYAMLSection  string   // which section of agent.talon.yaml this feature populates
	ConfigYAMLSection string   // section of talon.config.yaml if any (empty = agent only)
	WorkloadTypes     []string // workload types this feature applies to: "agent", "proxy", "hybrid"
}

var builtinFeatures = []FeatureDescriptor{
	{
		ID:               "pii",
		DisplayName:      "PII detection & redaction",
		Description:      "GDPR Article 25 — detects and redacts personal data in prompts/responses",
		DefaultEnabled:   true,
		Order:            10,
		AgentYAMLSection: "policies.data_classification",
		WorkloadTypes:    []string{"agent", "proxy", "hybrid"},
	},
	{
		ID:               "audit",
		DisplayName:      "Immutable audit trail",
		Description:      "EU AI Act Article 12 — HMAC-signed evidence records for every AI interaction",
		DefaultEnabled:   true,
		Order:            20,
		AgentYAMLSection: "audit",
		WorkloadTypes:    []string{"agent", "proxy", "hybrid"},
	},
	{
		ID:               "cost",
		DisplayName:      "Cost governance & budgets",
		Description:      "FinOps — per-agent daily/monthly budget limits with overage alerting",
		DefaultEnabled:   true,
		Order:            30,
		AgentYAMLSection: "policies.cost_limits",
		WorkloadTypes:    []string{"agent", "proxy", "hybrid"},
	},
	{
		ID:               "injection",
		DisplayName:      "Prompt injection prevention",
		Description:      "Security baseline — detects and blocks prompt injection attempts",
		DefaultEnabled:   true,
		Order:            40,
		AgentYAMLSection: "attachment_handling",
		WorkloadTypes:    []string{"agent", "hybrid"}, // proxy does not do attachment handling
	},
	{
		ID:               "eu-ai-act",
		DisplayName:      "EU AI Act risk classification",
		Description:      "Required for high-risk AI systems — risk tier classification per request",
		DefaultEnabled:   false,
		Order:            50,
		AgentYAMLSection: "compliance.ai_act_risk_level",
		WorkloadTypes:    []string{"agent", "hybrid"},
	},
	{
		ID:               "dora",
		DisplayName:      "DORA operational resilience logs",
		Description:      "Required for financial services — ICT incident logging per DORA Article 17",
		DefaultEnabled:   false,
		Order:            60,
		AgentYAMLSection: "compliance.frameworks",
		WorkloadTypes:    []string{"agent", "hybrid"},
	},
}

// AllFeatures returns all features in order (for full wizard display and validation).
func AllFeatures() []FeatureDescriptor {
	out := make([]FeatureDescriptor, len(builtinFeatures))
	copy(out, builtinFeatures)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// DefaultsForWorkload returns features applicable to the given workload type, sorted by Order.
// Proxy gets 3 features (pii, audit, cost); agent and hybrid get all 6.
func DefaultsForWorkload(workloadType string) []FeatureDescriptor {
	var out []FeatureDescriptor
	for _, f := range builtinFeatures {
		for _, w := range f.WorkloadTypes {
			if w == workloadType {
				out = append(out, f)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ValidFeatureIDs returns all feature IDs (for flag validation).
func ValidFeatureIDs() []string {
	all := AllFeatures()
	ids := make([]string, len(all))
	for i, f := range all {
		ids[i] = f.ID
	}
	return ids
}

// DefaultEnabledIDs returns IDs where DefaultEnabled is true.
func DefaultEnabledIDs() []string {
	var ids []string
	for _, f := range builtinFeatures {
		if f.DefaultEnabled {
			ids = append(ids, f.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// FindByID returns the feature with the given ID, or false if not found.
func FindByID(id string) (FeatureDescriptor, bool) {
	for _, f := range builtinFeatures {
		if f.ID == id {
			return f, true
		}
	}
	return FeatureDescriptor{}, false
}

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
)

func boolPtr(b bool) *bool { return &b }

// TestPIIActionsFromClassification (#266): scan flags alone produce NO
// override (they must not weaken an org baseline), redaction requires the
// ShouldRedact* flags, and block_on_pii escalates both directions.
func TestPIIActionsFromClassification(t *testing.T) {
	cases := []struct {
		name         string
		dc           *policy.DataClassificationConfig
		wantInput    string
		wantResponse string
	}{
		{"nil config inherits baseline", nil, "", ""},
		{"empty config inherits baseline", &policy.DataClassificationConfig{}, "", ""},
		{
			"input_scan alone is scan-only — no override, baseline inherited",
			&policy.DataClassificationConfig{InputScan: true}, "", "",
		},
		{
			"output_scan alone is scan-only — no override, baseline inherited",
			&policy.DataClassificationConfig{OutputScan: true}, "", "",
		},
		{
			"input redaction requires input_scan + redact",
			&policy.DataClassificationConfig{InputScan: true, RedactInput: boolPtr(true)}, "redact", "",
		},
		{
			"redact_input without input_scan inherits baseline",
			&policy.DataClassificationConfig{RedactInput: boolPtr(true)}, "", "",
		},
		{
			"output_scan + redact_output redacts response",
			&policy.DataClassificationConfig{OutputScan: true, RedactOutput: boolPtr(true)}, "", "redact",
		},
		{
			"redact_pii shorthand covers both directions",
			&policy.DataClassificationConfig{InputScan: true, OutputScan: true, RedactPII: true}, "redact", "redact",
		},
		{
			"explicit redact_output=false drops the response override",
			&policy.DataClassificationConfig{InputScan: true, OutputScan: true, RedactPII: true, RedactOutput: boolPtr(false)}, "redact", "",
		},
		{
			"block_on_pii blocks input",
			&policy.DataClassificationConfig{BlockOnPII: true}, "block", "",
		},
		{
			"block_on_pii + output_scan blocks response too",
			&policy.DataClassificationConfig{BlockOnPII: true, OutputScan: true}, "block", "block",
		},
		{
			"block wins over redact",
			&policy.DataClassificationConfig{BlockOnPII: true, InputScan: true, OutputScan: true, RedactPII: true}, "block", "block",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, out := piiActionsFromClassification(tc.dc)
			assert.Equal(t, tc.wantInput, in, "input action")
			assert.Equal(t, tc.wantResponse, out, "response action")
		})
	}
}

func TestLoadedAgentFromPolicyFullMapping(t *testing.T) {
	tier := policy.TierValue(2)
	egressTier := policy.TierValue(1)
	pol := &policy.Policy{
		Agent: policy.AgentConfig{
			Name:                 "customer-support",
			Version:              "1.0.0",
			TenantID:             "acme",
			Key:                  &policy.AgentKeyBinding{SecretName: "support-key"},
			AcceptClientMetadata: boolPtr(false),
		},
		Capabilities: &policy.CapabilitiesConfig{
			AllowedTools:     []string{"search"},
			ForbiddenTools:   []string{"send_email"},
			ToolPolicyAction: "block",
		},
		Policies: policy.PoliciesConfig{
			CostLimits:       &policy.CostLimitsConfig{Daily: 25, Monthly: 400},
			SessionLimits:    &policy.SessionLimitsConfig{MaxCost: 5},
			AllowedProviders: []string{"openai", "anthropic"},
			Models:           &policy.ModelsConfig{Allowed: []string{"gpt-4o"}, Blocked: []string{"gpt-3.5-turbo"}},
			DataClassification: &policy.DataClassificationConfig{
				InputScan:   true,
				RedactPII:   true,
				MaxDataTier: &tier,
			},
			Egress: &policy.EgressConfig{
				DefaultAction: "deny",
				Rules: []policy.EgressRuleConfig{
					{Tier: &egressTier, AllowedRegions: []string{"EU"}},
				},
			},
		},
		Metadata: &policy.MetadataConfig{Team: "support-eng", Tags: []string{"copaw"}},
	}

	la := LoadedAgentFromPolicy(pol, "support/agent.talon.yaml")
	assert.Equal(t, "support/agent.talon.yaml", la.Path)
	assert.Equal(t, "customer-support", la.Name)
	assert.Equal(t, "acme", la.TenantID)
	assert.Equal(t, "support-key", la.KeySecretName)
	assert.Equal(t, "support-eng", la.Team)
	assert.Equal(t, []string{"copaw"}, la.Tags)
	require.NotNil(t, la.AcceptClientMetadata)
	assert.False(t, *la.AcceptClientMetadata)

	o := la.Override
	require.NotNil(t, o)
	assert.Equal(t, float64(25), o.MaxDailyCost)
	assert.Equal(t, float64(400), o.MaxMonthlyCost)
	assert.Equal(t, float64(5), o.MaxSessionCost)
	assert.Equal(t, "redact", o.PIIAction)
	assert.Equal(t, "", o.ResponsePIIAction) // no output_scan → response inherits baseline
	assert.Equal(t, []string{"gpt-4o"}, o.AllowedModels)
	assert.Equal(t, []string{"gpt-3.5-turbo"}, o.BlockedModels)
	assert.Equal(t, []string{"openai", "anthropic"}, o.AllowedProviders,
		"allowed_providers rides the override so it flows through ResolveEffectivePolicy")
	require.NotNil(t, o.MaxDataTier)
	assert.Equal(t, gateway.TierConfidential, *o.MaxDataTier)
	assert.Equal(t, []string{"search"}, o.AllowedTools)
	assert.Equal(t, []string{"send_email"}, o.ForbiddenTools)
	assert.Equal(t, "block", o.ToolPolicyAction)
	require.NotNil(t, o.Egress)
	assert.Equal(t, "deny", o.Egress.DefaultAction)
	require.Len(t, o.Egress.Rules, 1)
	assert.Equal(t, gateway.TierInternal, *o.Egress.Rules[0].Tier)
	assert.Equal(t, []string{"EU"}, o.Egress.Rules[0].AllowedRegions)
}

// Cross-plane tenant authority (#266): the --tenant matrix.
func TestResolveRunTenant(t *testing.T) {
	withTenant := &policy.Policy{Agent: policy.AgentConfig{Name: "a", TenantID: "acme"}}
	noTenant := &policy.Policy{Agent: policy.AgentConfig{Name: "a"}}

	got, err := resolveRunTenant(withTenant, "default", false)
	require.NoError(t, err)
	assert.Equal(t, "acme", got, "file wins when flag not set")

	got, err = resolveRunTenant(withTenant, "acme", true)
	require.NoError(t, err)
	assert.Equal(t, "acme", got, "equal flag confirms")

	_, err = resolveRunTenant(withTenant, "globex", true)
	require.Error(t, err, "mismatch errors — the agent file is authoritative")
	assert.Contains(t, err.Error(), "agent.tenant_id")

	got, err = resolveRunTenant(noTenant, "globex", true)
	require.NoError(t, err)
	assert.Equal(t, "globex", got, "flag applies when file omits tenant_id")

	got, err = resolveRunTenant(noTenant, "default", false)
	require.NoError(t, err)
	assert.Equal(t, "default", got)
}

func TestLoadedAgentFromPolicyMinimal(t *testing.T) {
	pol := &policy.Policy{Agent: policy.AgentConfig{Name: "bare", Version: "0.0.1"}}
	la := LoadedAgentFromPolicy(pol, "agent.talon.yaml")
	assert.Equal(t, "bare", la.Name)
	assert.Equal(t, "", la.TenantID) // registry defaults to "default"
	assert.Equal(t, "", la.KeySecretName)
	assert.Nil(t, la.Override, "no gateway-relevant fields → baseline only")
}

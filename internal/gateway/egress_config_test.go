package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intPtr(v int) *TierLevel { t := TierLevel(v); return &t }

func TestResolveEgressPolicy(t *testing.T) {
	serverPolicy := &EgressPolicyConfig{
		DefaultAction: EgressActionDeny,
		Rules:         []EgressRule{{Tier: intPtr(2), AllowedRegions: []string{"EU"}}},
	}
	callerPolicy := &EgressPolicyConfig{
		Rules: []EgressRule{{Tier: intPtr(2), AllowedProviders: []string{"ollama"}}},
	}

	tests := []struct {
		name      string
		defaults  *ServerDefaults
		overrides *CallerPolicyOverrides
		want      *EgressPolicyConfig
	}{
		{
			name:      "unconfigured_returns_nil",
			defaults:  &ServerDefaults{},
			overrides: nil,
			want:      nil,
		},
		{
			name:      "server_default_used",
			defaults:  &ServerDefaults{Egress: serverPolicy},
			overrides: &CallerPolicyOverrides{},
			want:      serverPolicy,
		},
		{
			name:      "caller_override_replaces_default",
			defaults:  &ServerDefaults{Egress: serverPolicy},
			overrides: &CallerPolicyOverrides{Egress: callerPolicy},
			want: &EgressPolicyConfig{
				DefaultAction: EgressActionAllow, // normalized
				Rules:         callerPolicy.Rules,
			},
		},
		{
			name:      "caller_only",
			defaults:  &ServerDefaults{},
			overrides: &CallerPolicyOverrides{Egress: callerPolicy},
			want: &EgressPolicyConfig{
				DefaultAction: EgressActionAllow,
				Rules:         callerPolicy.Rules,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveEgressPolicy(tt.defaults, tt.overrides)
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want.Rules, got.Rules)
			if tt.want.DefaultAction != "" {
				assert.Equal(t, tt.want.DefaultAction, got.DefaultAction)
			}
		})
	}
}

func TestEvaluateEgress(t *testing.T) {
	euOnlyTier2 := &EgressPolicyConfig{
		DefaultAction: EgressActionAllow,
		Rules: []EgressRule{
			{Tier: intPtr(0), AllowedProviders: []string{"*"}},
			{Tier: intPtr(1), AllowedProviders: []string{"openai", "anthropic"}},
			{Tier: intPtr(2), AllowedRegions: []string{"EU", "LOCAL"}},
		},
	}

	tests := []struct {
		name        string
		policy      *EgressPolicyConfig
		tier        int
		provider    string
		region      string
		wantAllowed bool
		wantRule    string
		wantReason  string
		wantEval    bool
	}{
		{
			name: "nil_policy_not_evaluated", policy: nil,
			tier: 2, provider: "openai", region: "US",
			wantAllowed: true, wantEval: false,
		},
		{
			name: "tier2_disallowed_us_provider", policy: euOnlyTier2,
			tier: 2, provider: "openai", region: "US",
			wantAllowed: false, wantRule: "tier_2", wantReason: EgressReasonTierDestination, wantEval: true,
		},
		{
			name: "tier2_allowed_eu_region", policy: euOnlyTier2,
			tier: 2, provider: "mistral", region: "EU",
			wantAllowed: true, wantRule: "tier_2:allowed_regions", wantEval: true,
		},
		{
			name: "tier2_allowed_local_region", policy: euOnlyTier2,
			tier: 2, provider: "ollama", region: "LOCAL",
			wantAllowed: true, wantRule: "tier_2:allowed_regions", wantEval: true,
		},
		{
			name: "tier0_wildcard_provider", policy: euOnlyTier2,
			tier: 0, provider: "openai", region: "US",
			wantAllowed: true, wantRule: "tier_0:allowed_providers", wantEval: true,
		},
		{
			name: "tier1_approved_provider", policy: euOnlyTier2,
			tier: 1, provider: "anthropic", region: "US",
			wantAllowed: true, wantRule: "tier_1:allowed_providers", wantEval: true,
		},
		{
			name: "tier1_unapproved_provider", policy: euOnlyTier2,
			tier: 1, provider: "ollama", region: "LOCAL",
			wantAllowed: false, wantRule: "tier_1", wantReason: EgressReasonTierDestination, wantEval: true,
		},
		{
			name: "unknown_region_fails_closed", policy: euOnlyTier2,
			tier: 2, provider: "custom", region: "unknown",
			wantAllowed: false, wantRule: "tier_2", wantReason: EgressReasonTierDestination, wantEval: true,
		},
		{
			name: "unknown_region_never_matches_even_when_listed",
			policy: &EgressPolicyConfig{
				DefaultAction: EgressActionAllow,
				Rules:         []EgressRule{{Tier: intPtr(2), AllowedRegions: []string{"unknown"}}},
			},
			tier: 2, provider: "custom", region: "unknown",
			wantAllowed: false, wantRule: "tier_2", wantReason: EgressReasonTierDestination, wantEval: true,
		},
		{
			name: "no_rule_for_tier_default_allow", policy: euOnlyTier2,
			tier: 1, provider: "openai", region: "US",
			wantAllowed: true, wantRule: "tier_1:allowed_providers", wantEval: true,
		},
		{
			name: "no_rule_for_tier_default_deny",
			policy: &EgressPolicyConfig{
				DefaultAction: EgressActionDeny,
				Rules:         []EgressRule{{Tier: intPtr(2), AllowedRegions: []string{"EU"}}},
			},
			tier: 1, provider: "openai", region: "US",
			wantAllowed: false, wantRule: "default_action", wantReason: EgressReasonDestination, wantEval: true,
		},
		{
			name: "no_rules_default_allow",
			policy: &EgressPolicyConfig{
				DefaultAction: EgressActionAllow,
			},
			tier: 2, provider: "openai", region: "US",
			wantAllowed: true, wantRule: "default_action", wantEval: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateEgress(tt.policy, tt.tier, tt.provider, tt.region)
			assert.Equal(t, tt.wantEval, got.Evaluated, "Evaluated")
			assert.Equal(t, tt.wantAllowed, got.Allowed, "Allowed")
			assert.Equal(t, tt.wantRule, got.MatchedRule, "MatchedRule")
			assert.Equal(t, tt.wantReason, got.Reason, "Reason")
		})
	}
}

func TestValidateEgressPolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  *EgressPolicyConfig
		wantErr string
	}{
		{name: "nil_ok", policy: nil},
		{
			name:   "valid",
			policy: &EgressPolicyConfig{DefaultAction: "deny", Rules: []EgressRule{{Tier: intPtr(2), AllowedRegions: []string{"EU"}}}},
		},
		{
			name:    "bad_default_action",
			policy:  &EgressPolicyConfig{DefaultAction: "block"},
			wantErr: "default_action must be allow or deny",
		},
		{
			name:    "missing_tier",
			policy:  &EgressPolicyConfig{Rules: []EgressRule{{AllowedRegions: []string{"EU"}}}},
			wantErr: "tier is required",
		},
		{
			name:    "tier_out_of_range",
			policy:  &EgressPolicyConfig{Rules: []EgressRule{{Tier: intPtr(3), AllowedRegions: []string{"EU"}}}},
			wantErr: "tier must be 0, 1, or 2",
		},
		{
			name:    "empty_rule",
			policy:  &EgressPolicyConfig{Rules: []EgressRule{{Tier: intPtr(2)}}},
			wantErr: "at least one of allowed_providers or allowed_regions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEgressPolicy("default_policy", tt.policy)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoadGatewayConfig_Egress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	content := `
gateway:
  enabled: true
  mode: enforce
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
      region: "US"
  callers:
    - name: finance-bot
      tenant_key: "talon-gw-abc"
      tenant_id: "acme"
      policy_overrides:
        egress:
          default_action: deny
          rules:
            - tier: 2
              allowed_providers: ["ollama"]
  default_policy:
    default_pii_action: warn
    egress:
      rules:
        - tier: 0
          allowed_providers: ["*"]
        - tier: 2
          allowed_regions: ["EU", "LOCAL"]
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := LoadGatewayConfig(path)
	require.NoError(t, err)

	require.NotNil(t, cfg.ServerDefaults.Egress)
	assert.Equal(t, EgressActionAllow, cfg.ServerDefaults.Egress.DefaultAction, "default_action defaults to allow")
	require.Len(t, cfg.ServerDefaults.Egress.Rules, 2)
	assert.Equal(t, []string{"EU", "LOCAL"}, cfg.ServerDefaults.Egress.Rules[1].AllowedRegions)

	caller := cfg.CallerByName("finance-bot")
	require.NotNil(t, caller)
	require.NotNil(t, caller.PolicyOverrides.Egress)
	assert.Equal(t, EgressActionDeny, caller.PolicyOverrides.Egress.DefaultAction)

	prov, ok := cfg.Provider("openai")
	require.True(t, ok)
	assert.Equal(t, "US", prov.Region)
}

func TestLoadGatewayConfig_EgressNamedTiers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	content := `
gateway:
  enabled: true
  mode: enforce
  callers:
    - name: finance-bot
      tenant_key: "talon-gw-abc"
      tenant_id: "acme"
      policy_overrides:
        max_data_tier: internal
  default_policy:
    egress:
      rules:
        - tier: public
          allowed_providers: ["*"]
        - tier: 1
          allowed_providers: ["openai"]
        - tier: confidential
          allowed_regions: ["EU"]
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := LoadGatewayConfig(path)
	require.NoError(t, err)

	rules := cfg.ServerDefaults.Egress.Rules
	require.Len(t, rules, 3)
	assert.Equal(t, TierPublic, *rules[0].Tier, "named alias public")
	assert.Equal(t, TierInternal, *rules[1].Tier, "numeric tier still accepted")
	assert.Equal(t, TierConfidential, *rules[2].Tier, "named alias confidential")

	caller := cfg.CallerByName("finance-bot")
	require.NotNil(t, caller)
	require.NotNil(t, caller.PolicyOverrides.MaxDataTier)
	assert.Equal(t, TierInternal, *caller.PolicyOverrides.MaxDataTier, "max_data_tier accepts named alias")
}

func TestLoadGatewayConfig_EgressInvalidTierName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	content := `
gateway:
  enabled: true
  mode: enforce
  default_policy:
    egress:
      rules:
        - tier: restricted
          allowed_regions: ["EU"]
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	_, err := LoadGatewayConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public, internal, confidential")
}

func TestLoadGatewayConfig_EgressInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	content := `
gateway:
  enabled: true
  mode: enforce
  default_policy:
    egress:
      default_action: maybe
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	_, err := LoadGatewayConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default_action must be allow or deny")
}

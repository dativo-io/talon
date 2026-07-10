package sovereignty

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestEgressGuard_AllowsAndBlocks(t *testing.T) {
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(allowed.Close)

	guard := NewEgressGuard([]string{allowed.URL})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, allowed.URL, nil)
	require.NoError(t, err)
	resp, err := guard.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	req2, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://surprise-egress.example/v1", nil)
	require.NoError(t, err)
	resp2, err := guard.RoundTrip(req2)
	if resp2 != nil && resp2.Body != nil {
		_ = resp2.Body.Close()
	}
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEgressBlocked)
	assert.Equal(t, int64(1), guard.Violations())
}

func TestApplyAirGapPreset_ForcesEUStrictAndEgress(t *testing.T) {
	op := &config.Config{
		Sovereignty:   &config.SovereigntyConfig{DeploymentMode: ModeAirGap},
		OllamaBaseURL: "http://localhost:11434",
		SecretsKey:    testutil.TestEncryptionKey,
		SigningKey:    testutil.TestSigningKey,
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://127.0.0.1:11434", Region: "LOCAL"},
		},
	}
	guard, err := ApplyAirGapPreset(op, gw)
	require.NoError(t, err)
	require.NotNil(t, guard)
	require.NotNil(t, op.LLM)
	require.Equal(t, "eu_strict", op.LLM.Routing.DataSovereigntyMode)
	require.NotNil(t, gw.OrganizationPolicy.Egress)
	assert.Equal(t, gateway.EgressActionDeny, gw.OrganizationPolicy.Egress.DefaultAction)
}

// TestAirGapPreset_OverridesConflictingLLMRouting is the regression for the
// "single source of truth" bug: under air_gap the preset must force eu_strict
// and override a conflicting llm.routing.data_sovereignty_mode (with a warning),
// not error. The genuine conflict (sovereignty.mode global + air_gap) is caught
// earlier by config.resolveSovereignty during load.
func TestAirGapPreset_OverridesConflictingLLMRouting(t *testing.T) {
	op := &config.Config{
		Sovereignty:   &config.SovereigntyConfig{DeploymentMode: ModeAirGap},
		OllamaBaseURL: "http://localhost:11434",
		LLM: &config.LLMConfig{
			Routing: &config.LLMRoutingConfig{DataSovereigntyMode: config.DataSovereigntyGlobal},
		},
		SecretsKey: testutil.TestEncryptionKey,
		SigningKey: testutil.TestSigningKey,
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://127.0.0.1:11434", Region: "LOCAL"},
		},
	}
	guard, err := ApplyAirGapPreset(op, gw)
	require.NoError(t, err, "air_gap must override conflicting routing, not error")
	require.NotNil(t, guard)
	assert.Equal(t, config.DataSovereigntyEUStrict, op.LLM.Routing.DataSovereigntyMode)
}

func TestApplyAirGapPreset_EmptyEgressStillAppliesPreset(t *testing.T) {
	op := &config.Config{
		Sovereignty:   &config.SovereigntyConfig{DeploymentMode: ModeAirGap},
		OllamaBaseURL: "http://localhost:11434",
		SecretsKey:    testutil.TestEncryptionKey,
		SigningKey:    testutil.TestSigningKey,
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"ollama": {Enabled: true, BaseURL: "http://127.0.0.1:11434", Region: "LOCAL"},
		},
		OrganizationPolicy: gateway.OrganizationPolicy{
			Egress: &gateway.EgressPolicyConfig{DefaultAction: "allow"},
		},
	}
	guard, err := ApplyAirGapPreset(op, gw)
	require.NoError(t, err)
	require.NotNil(t, guard)
	require.NotNil(t, gw.OrganizationPolicy.Egress)
	assert.Equal(t, gateway.EgressActionDeny, gw.OrganizationPolicy.Egress.DefaultAction)
	assert.NotEmpty(t, gw.OrganizationPolicy.Egress.Rules)
}

func TestValidateAirGap_RejectsDefaultCryptoKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SECRETS_KEY", "")
	t.Setenv("TALON_SIGNING_KEY", "")

	viper.Set("sovereignty", map[string]interface{}{"deployment_mode": ModeAirGap})
	t.Cleanup(func() {
		viper.Reset()
		viper.SetEnvPrefix("TALON")
		viper.AutomaticEnv()
		viper.SetDefault(config.KeyDefaultPolicy, config.DefaultPolicy)
		viper.SetDefault(config.KeyMaxAttachmentMB, config.DefaultMaxAttachMB)
		viper.SetDefault(config.KeyOllamaBaseURL, config.DefaultOllamaURL)
	})

	op, err := config.Load()
	require.NoError(t, err)
	require.True(t, op.UsingDefaultKeys())

	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", Region: "US"},
		},
	}
	err = ValidateAirGap(op, gw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TALON_SECRETS_KEY")
}

func TestValidateAirGap_USProviderIsNonFatal(t *testing.T) {
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{DeploymentMode: ModeAirGap},
		SecretsKey:  testutil.TestEncryptionKey,
		SigningKey:  testutil.TestSigningKey,
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", Region: "US"},
		},
	}
	require.NoError(t, ValidateAirGap(op, gw))
	eval := EvaluateSovereignty(op, gw)
	require.Len(t, eval.Excluded, 1)
	assert.Equal(t, "openai", eval.Excluded[0].Provider)
}

func TestBuildAllowlist_IncludesOllamaAndProviders(t *testing.T) {
	op := &config.Config{
		OllamaBaseURL: "http://localhost:11434",
		Sovereignty:   &config.SovereigntyConfig{AllowedEgressHosts: []string{"llm.internal.example"}},
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"eu": {Enabled: true, BaseURL: "https://api.mistral.ai", Region: "EU"},
		},
	}
	hosts, err := BuildAllowlist(op, gw)
	require.NoError(t, err)
	assert.Contains(t, hosts, "localhost")
	assert.Contains(t, hosts, "api.mistral.ai")
	assert.Contains(t, hosts, "llm.internal.example")
}

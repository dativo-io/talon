package sovereignty

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
	require.NotNil(t, gw.ServerDefaults.Egress)
	assert.Equal(t, gateway.EgressActionDeny, gw.ServerDefaults.Egress.DefaultAction)
}

func TestValidateAirGap_RejectsUSProvider(t *testing.T) {
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
	err := ValidateAirGap(op, gw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "openai")
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

package gateway_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/stretchr/testify/require"
)

func TestLoadShortlistDemoGatewayConfig(t *testing.T) {
	t.Parallel()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	path := filepath.Join(repoRoot, "examples", "shortlist-demo", "talon.config.shortlist.yaml")

	cfg, err := gateway.LoadGatewayConfig(path)
	require.NoError(t, err)
	require.True(t, cfg.Enabled)
	require.Equal(t, gateway.ModeEnforce, cfg.Mode)
	require.Equal(t, "block", cfg.ServerDefaults.DefaultPIIAction)
	require.True(t, cfg.ServerDefaults.CallerIDRequired())

	prov, ok := cfg.Provider("openai")
	require.True(t, ok)
	require.Equal(t, "US", prov.Region)

	var allowCaller, denyCaller, euCaller *gateway.CallerConfig
	for i := range cfg.Callers {
		switch cfg.Callers[i].Name {
		case "shortlist-allow":
			allowCaller = &cfg.Callers[i]
		case "shortlist-policy-deny":
			denyCaller = &cfg.Callers[i]
		case "shortlist-eu-strict":
			euCaller = &cfg.Callers[i]
		}
	}
	require.NotNil(t, allowCaller)
	require.NotNil(t, denyCaller)
	require.NotNil(t, euCaller)
	require.NotEmpty(t, denyCaller.PolicyOverrides.AllowedModels)
	require.NotNil(t, euCaller.PolicyOverrides.Egress)
	require.NotEmpty(t, euCaller.PolicyOverrides.Egress.Rules)
}

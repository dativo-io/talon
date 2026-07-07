package gateway_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/stretchr/testify/require"
)

// The governed-session demo (#107 Act II) runs against REAL providers; this
// guards the example config so the demo cannot silently rot: both providers
// present, the session budget cap and admin_* tool governance configured,
// PII blocking on, and prompt logging off (real traffic).
func TestLoadGovernedSessionGatewayConfig(t *testing.T) {
	t.Parallel()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	path := filepath.Join(repoRoot, "examples", "governed-session", "talon.config.session.yaml")

	cfg, err := gateway.LoadGatewayConfig(path)
	require.NoError(t, err)
	require.True(t, cfg.Enabled)
	require.Equal(t, gateway.ModeEnforce, cfg.Mode)
	require.Equal(t, "block", cfg.ServerDefaults.DefaultPIIAction)
	require.True(t, cfg.ServerDefaults.CallerIDRequired())
	require.False(t, cfg.ServerDefaults.LogPrompts, "real-provider demo must not store prompt bodies")
	require.Positive(t, cfg.ServerDefaults.MaxDailyCost, "real-money safety net must be configured")

	anthropic, ok := cfg.Provider("anthropic")
	require.True(t, ok)
	require.Contains(t, anthropic.AllowedModels, "claude-sonnet-5")
	openai, ok := cfg.Provider("openai")
	require.True(t, ok)
	require.Contains(t, openai.AllowedModels, "gpt-4o")

	callers := map[string]*gateway.CallerConfig{}
	for i := range cfg.Callers {
		callers[cfg.Callers[i].Name] = &cfg.Callers[i]
	}

	sessionCaller := callers["session-demo"]
	require.NotNil(t, sessionCaller)
	require.NotNil(t, sessionCaller.PolicyOverrides)
	require.InDelta(t, 0.03, sessionCaller.PolicyOverrides.MaxSessionCost, 1e-9,
		"session budget gate: demo.sh budget-gate loop is tuned to this cap")
	require.Contains(t, sessionCaller.PolicyOverrides.ForbiddenTools, "admin_*")

	// Model-governance act: this caller may only use gpt-4o-mini, so a gpt-4o
	// request is denied POLICY_DENIED_ROUTING.
	euCaller := callers["session-demo-eu"]
	require.NotNil(t, euCaller, "model-governance act needs the session-demo-eu caller")
	require.NotNil(t, euCaller.PolicyOverrides)
	require.Equal(t, []string{"gpt-4o-mini"}, euCaller.PolicyOverrides.AllowedModels)

	// Redaction act: an email is scrubbed but the request still forwards.
	redactCaller := callers["session-demo-redact"]
	require.NotNil(t, redactCaller, "redaction act needs the session-demo-redact caller")
	require.NotNil(t, redactCaller.PolicyOverrides)
	require.Equal(t, "redact", redactCaller.PolicyOverrides.PIIAction)
}

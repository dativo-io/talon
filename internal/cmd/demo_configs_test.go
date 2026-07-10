package cmd

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
)

// Demo-config guards (#107): the example configs behind the recorded demos
// must not silently rot. Post-#266 each demo scenario is its own agent file;
// these tests load the real example YAMLs through the same loader + bridge +
// effective-policy path `talon serve --gateway` uses.

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func loadDemoAgent(t *testing.T, path string) gateway.LoadedAgent {
	t.Helper()
	pol, err := policy.LoadPolicy(context.Background(), path, false, filepath.Dir(path))
	require.NoError(t, err, "agent file %s must parse and validate", path)
	return LoadedAgentFromPolicy(pol, path)
}

// The governed-session demo (#107 Act II) runs against REAL providers; this
// guards the example config: both providers present, the session budget cap
// and admin_* tool governance configured, PII blocking on, and prompt logging
// off (real traffic).
func TestGovernedSessionDemoConfig(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	dir := filepath.Join(root, "examples", "governed-session")

	cfg, err := gateway.LoadGatewayConfig(filepath.Join(dir, "talon.config.session.yaml"))
	require.NoError(t, err)
	require.True(t, cfg.Enabled)
	require.Equal(t, gateway.ModeEnforce, cfg.Mode)
	require.Equal(t, "block", cfg.OrganizationPolicy.DefaultPIIAction)
	require.False(t, cfg.OrganizationPolicy.LogPrompts, "real-provider demo must not store prompt bodies")
	require.Positive(t, cfg.OrganizationPolicy.MaxDailyCost, "real-money safety net must be configured")

	anthropic, ok := cfg.Provider("anthropic")
	require.True(t, ok)
	require.Contains(t, anthropic.AllowedModels, "claude-sonnet-5")
	openai, ok := cfg.Provider("openai")
	require.True(t, ok)
	require.Contains(t, openai.AllowedModels, "gpt-4o")

	// Hero act: session budget gate + admin_* tool governance, vault-bound key.
	hero := loadDemoAgent(t, filepath.Join(dir, "agents", "session-demo.talon.yaml"))
	require.Equal(t, "session-demo", hero.Name)
	require.Equal(t, "governed-session", hero.TenantID)
	require.Equal(t, "session-demo-talon-key", hero.KeySecretName, "traffic key must be a vault reference")
	require.Equal(t, "governed-session-demo", hero.Team)
	heroEff := gateway.ResolveEffectivePolicy(cfg.OrganizationPolicy, openai, hero.Override)
	require.InDelta(t, 0.03, heroEff.MaxSessionCost, 1e-9,
		"session budget gate: demo.sh budget-gate loop is tuned to this cap")
	require.Contains(t, heroEff.ForbiddenTools, "admin_*")

	// Model-governance act: this agent may only use gpt-4o-mini, so a gpt-4o
	// request is denied POLICY_DENIED_ROUTING.
	eu := loadDemoAgent(t, filepath.Join(dir, "agents", "session-demo-eu.talon.yaml"))
	require.Equal(t, "session-demo-eu-talon-key", eu.KeySecretName)
	euEff := gateway.ResolveEffectivePolicy(cfg.OrganizationPolicy, openai, eu.Override)
	require.Equal(t, []string{"gpt-4o-mini"}, euEff.AllowedModels)

	// Redaction act: an email is scrubbed but the request still forwards.
	redact := loadDemoAgent(t, filepath.Join(dir, "agents", "session-demo-redact.talon.yaml"))
	redactEff := gateway.ResolveEffectivePolicy(cfg.OrganizationPolicy, openai, redact.Override)
	require.Equal(t, "redact", redactEff.PIIAction)
	require.Equal(t, "block", heroEff.PIIAction, "hero act inherits the baseline block action")
}

func TestShortlistDemoConfig(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	dir := filepath.Join(root, "examples", "shortlist-demo")

	cfg, err := gateway.LoadGatewayConfig(filepath.Join(dir, "talon.config.shortlist.yaml"))
	require.NoError(t, err)
	require.True(t, cfg.Enabled)
	require.Equal(t, gateway.ModeEnforce, cfg.Mode)
	require.Equal(t, "block", cfg.OrganizationPolicy.DefaultPIIAction)

	prov, ok := cfg.Provider("openai")
	require.True(t, ok)
	require.Equal(t, "US", prov.Region)

	allow := loadDemoAgent(t, filepath.Join(dir, "agents", "shortlist-allow.talon.yaml"))
	require.Equal(t, "shortlist", allow.TenantID)
	require.NotEmpty(t, allow.KeySecretName)

	deny := loadDemoAgent(t, filepath.Join(dir, "agents", "shortlist-policy-deny.talon.yaml"))
	denyEff := gateway.ResolveEffectivePolicy(cfg.OrganizationPolicy, prov, deny.Override)
	require.NotEmpty(t, denyEff.AllowedModels)

	eu := loadDemoAgent(t, filepath.Join(dir, "agents", "shortlist-eu-strict.talon.yaml"))
	euEff := gateway.ResolveEffectivePolicy(cfg.OrganizationPolicy, prov, eu.Override)
	require.NotNil(t, euEff.Egress)
	require.Equal(t, "deny", euEff.Egress.DefaultAction)
	require.NotEmpty(t, euEff.Egress.Rules)
}

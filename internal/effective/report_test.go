package effective

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

const signingKey = "effective-test-signing-key-0000000001"

type fixture struct {
	dir, agents, gw, proxy string
	store                  *evidence.Store
}

// peopleAnalytics writes the People Analytics shape: an organization
// baseline, the hr-analytics-assistant agent file, and an MCP proxy that
// forbids hr_employee_export.
func peopleAnalytics(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	f := fixture{dir: dir, agents: filepath.Join(dir, "agents"), gw: filepath.Join(dir, "talon.config.yaml"), proxy: filepath.Join(dir, "proxy.talon.yaml")}
	a := filepath.Join(f.agents, "hr-analytics-assistant")
	require.NoError(t, os.MkdirAll(a, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(a, "agent.talon.yaml"), []byte(`agent:
  name: hr-analytics-assistant
  version: "1.0.0"
capabilities:
  allowed_tools: ["hr_aggregate_sql"]
  forbidden_tools: ["hr_employee_export"]
policies:
  cost_limits:
    daily: 5
    monthly: 50
`), 0o600))
	require.NoError(t, os.WriteFile(f.gw, []byte(`gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: openai-api-key
  organization_policy:
    defaults:
      pii_action: redact
      daily_cost: 100
      monthly_cost: 2000
    constraints:
      forbidden_tools: ["admin_*"]
`), 0o600))
	require.NoError(t, os.WriteFile(f.proxy, []byte(`agent:
  name: hr-mcp-proxy
  type: mcp_proxy
proxy:
  upstream:
    vendor: hr-backend
    url: "http://hr-upstream:9000/mcp"
  allowed_tools:
    - name: hr_aggregate_sql
  forbidden_tools: ["hr_employee_export"]
`), 0o600))
	s, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), signingKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	f.store = s
	return f
}

func (f fixture) inputs() Inputs {
	return Inputs{AgentsDir: f.agents, GatewayConfig: f.gw, ProxyConfig: f.proxy, Name: "hr-analytics-assistant", Evidence: f.store}
}

func rule(r *Report, name string) gateway.RuleProvenance {
	for _, x := range r.Effective.Rules {
		if x.Rule == name {
			return x
		}
	}
	return gateway.RuleProvenance{}
}

func TestBuild_PeopleAnalyticsLayers(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	r, err := Build(ctx, f.inputs())
	require.NoError(t, err)

	assert.Equal(t, "default", r.TenantID)
	assert.NotEmpty(t, r.CurrentFiles.PolicyDigest)
	require.NotNil(t, r.CurrentFiles.GatewayConfig)
	assert.True(t, r.Effective.BaselinePresent)

	// Effective: use-case caps replace the org defaults; PII from the org floor.
	assert.InDelta(t, 5, r.Effective.DailyCap, 1e-9)
	assert.InDelta(t, 50, r.Effective.MonthlyCap, 1e-9)
	assert.Equal(t, "redact", r.Effective.PIIAction)
	assert.Equal(t, gateway.SourceUseCase, rule(r, "daily_cost").Winner)
	assert.Equal(t, gateway.SourceOrgDefaults, rule(r, "pii_action").Winner)
	assert.ElementsMatch(t, []string{"admin_*", "hr_employee_export"}, r.Effective.ForbiddenTools, "union of organization and use-case lists")
	require.Len(t, r.Effective.Providers, 1)
	assert.Equal(t, "openai", r.Effective.Providers[0].Name)

	// MCP boundary: the proxy's own checks.
	require.NotNil(t, r.MCPBoundary)
	assert.Equal(t, "hr-mcp-proxy", r.MCPBoundary.Proxy)
	decisions := map[string]string{}
	for _, d := range r.MCPBoundary.Tools {
		s := "deny:" + d.Stage
		if d.Allowed {
			s = "allow"
		}
		decisions[d.Tool] = s
	}
	assert.Equal(t, "deny:forbidden_tools", decisions["hr_employee_export"], "forbidden at the MCP boundary before dispatch")
	assert.Equal(t, "allow", decisions["hr_aggregate_sql"])

	// Without runtime records nothing is proven active.
	assert.Equal(t, runtimestatus.LoadedUnknown, r.Loaded.State)
	assert.False(t, r.Effective.ProvenActive)
	assert.Contains(t, r.Effective.Basis, "not proven")
	assert.Nil(t, r.LastDecision)
	assert.Contains(t, r.Notes, "no evidence recorded for this use case yet")
}

func TestBuild_LoadedProofAndHistoricalDecision(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	in := f.inputs()
	first, err := Build(ctx, in)
	require.NoError(t, err)
	digest := first.CurrentFiles.PolicyDigest

	// A running gateway reports the current agent file's digest and the
	// current gateway config's digest: proven active.
	now := time.Now().UTC()
	view := runtimestatus.View{Processes: []runtimestatus.Process{
		runningRecord("gw1", []string{runtimestatus.RoleGateway}, digest, first.CurrentFiles.GatewayConfig.Digest, ""),
	}}
	in.Runtime, in.RuntimeReadable = &view, true
	r, err := Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, runtimestatus.LoadedMatchesFile, r.Loaded.State)
	assert.True(t, r.Effective.ProvenActive)

	// A decision recorded by the gateway under the current file and the
	// current effective policy toward openai.
	scan, err := fleetview.Scan(ctx, f.agents, "")
	require.NoError(t, err)
	override := agentbridge.LoadedAgentFromPolicy(scan.Agents[0].Policy, scan.Agents[0].Path).Override
	gw, err := gateway.LoadGatewayConfig(f.gw)
	require.NoError(t, err)
	effDigest := gateway.EffectivePolicyDigest(gw.OrganizationPolicy, gw.Providers["openai"], override)
	require.NoError(t, f.store.Store(ctx, &evidence.Evidence{
		ID: "old", CorrelationID: "c-old", TenantID: "default", AgentID: "hr-analytics-assistant", Timestamp: now.Add(-time.Hour), InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyDigests: &evidence.PolicyDigests{Agent: "an-older-file", Effective: "an-older-effective"}},
	}))
	require.NoError(t, f.store.Store(ctx, &evidence.Evidence{
		ID: "new", CorrelationID: "c-new", TenantID: "default", AgentID: "hr-analytics-assistant", Timestamp: now, InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyDigests: &evidence.PolicyDigests{Agent: digest, Effective: effDigest}},
	}))
	r, err = Build(ctx, in)
	require.NoError(t, err)
	require.NotNil(t, r.LastDecision)
	assert.Equal(t, "new", r.LastDecision.EvidenceID, "the newest record")
	assert.Equal(t, "same", r.LastDecision.AgentFile)
	assert.Equal(t, "matches_current:openai", r.LastDecision.EffectivePolicy)

	// A proxy record carries no policy digests: not recorded, never assumed.
	require.NoError(t, f.store.Store(ctx, &evidence.Evidence{
		ID: "mcp", CorrelationID: "c-mcp", TenantID: "default", AgentID: "hr-analytics-assistant", Timestamp: now.Add(time.Second), InvocationType: "proxy_tool_blocked",
		PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny"}, Execution: evidence.Execution{ToolsCalled: []string{"hr_employee_export"}, Error: "forbidden_tools"},
	}))
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, "mcp", r.LastDecision.EvidenceID)
	assert.Equal(t, "not_recorded", r.LastDecision.AgentFile)
	assert.Equal(t, "not_recorded", r.LastDecision.EffectivePolicy)
	assert.Equal(t, evidence.DispatchNotDispatched, r.LastDecision.Outcome.Dispatch)

	// A comment-only edit keeps the canonical policy digest: still loaded.
	agentFile := filepath.Join(f.agents, "hr-analytics-assistant", "agent.talon.yaml")
	raw, _ := os.ReadFile(agentFile)
	require.NoError(t, os.WriteFile(agentFile, append(raw, []byte("# a comment\n")...), 0o600))
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, runtimestatus.LoadedMatchesFile, r.Loaded.State, "the digest is canonical: comments are not policy")

	// A policy change: the running process loaded a different version.
	require.NoError(t, os.WriteFile(agentFile, []byte(strings.Replace(string(raw), "daily: 5", "daily: 7", 1)), 0o600))
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, runtimestatus.LoadedDiffersFromFile, r.Loaded.State)
	assert.False(t, r.Effective.ProvenActive)
}

func TestBuild_FailClosed(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	in := f.inputs()
	in.Name = "nope"
	_, err := Build(ctx, in)
	require.ErrorIs(t, err, ErrUnknownUseCase)

	require.NoError(t, os.WriteFile(f.gw, []byte("gateway: [broken"), 0o600))
	r, err := Build(ctx, f.inputs())
	require.NoError(t, err)
	assert.False(t, r.Effective.BaselinePresent)
	require.NotNil(t, r.CurrentFiles.GatewayConfig)
	assert.NotEmpty(t, r.CurrentFiles.GatewayConfig.Error)
	assert.Contains(t, r.Notes[0], "no organization baseline")
	assert.InDelta(t, 5, r.Effective.DailyCap, 1e-9, "the use case's own cap still compiles")

	require.NoError(t, os.WriteFile(f.proxy, []byte("proxy: ["), 0o600))
	r, err = Build(ctx, f.inputs())
	require.NoError(t, err)
	require.NotNil(t, r.MCPBoundary)
	assert.NotEmpty(t, r.MCPBoundary.Error)
	assert.Empty(t, r.MCPBoundary.Tools, "no decision is shown from a config that cannot be loaded")
}

// runningRecord is a running process of this installation as Assess shows it.
func runningRecord(id string, roles []string, agentDigest, gwDigest, proxyDigest string) runtimestatus.Process {
	r := runtimestatus.Record{InstanceID: id, Roles: roles, Catalog: &runtimestatus.Catalog{Agents: []runtimestatus.Agent{{Name: "hr-analytics-assistant", PolicyDigest: agentDigest}}}}
	if gwDigest != "" {
		r.GatewayConfig = &runtimestatus.ConfigRef{Digest: gwDigest}
	}
	if proxyDigest != "" {
		r.ProxyConfig = &runtimestatus.ConfigRef{Digest: proxyDigest}
	}
	return runtimestatus.Process{Record: r, Assessed: runtimestatus.Running, Current: true}
}

// TestBuild_ProofIsPerEnforcementBoundary (#555 review): the gateway policy is
// proven active only when a running gateway loaded the current agent file AND
// the current gateway config; the MCP decisions only when a running proxy
// loaded the current proxy config. Neither proves the other.
func TestBuild_ProofIsPerEnforcementBoundary(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	in := f.inputs()
	first, err := Build(ctx, in)
	require.NoError(t, err)
	agent, gw, px := first.CurrentFiles.PolicyDigest, first.CurrentFiles.GatewayConfig.Digest, first.CurrentFiles.ProxyConfig.Digest

	// Only the MCP proxy runs: its tool decisions are proven, the gateway
	// policy is not (no gateway enforces it).
	view := runtimestatus.View{Processes: []runtimestatus.Process{runningRecord("px", []string{runtimestatus.RoleMCPProxy}, agent, "", px)}}
	in.Runtime, in.RuntimeReadable = &view, true
	r, err := Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, runtimestatus.LoadedMatchesFile, r.Loaded.State, "the agent file itself is loaded by the proxy")
	assert.False(t, r.Effective.ProvenActive, "a proxy does not enforce the gateway policy")
	assert.Equal(t, runtimestatus.BoundaryNotRunning, r.Effective.Proof.State)
	require.NotNil(t, r.MCPBoundary)
	assert.True(t, r.MCPBoundary.ProvenActive)
	assert.Equal(t, runtimestatus.BoundaryProven, r.MCPBoundary.Proof.State)

	// A gateway runs with the current files: proven.
	view.Processes = append(view.Processes, runningRecord("gw", []string{runtimestatus.RoleGateway}, agent, gw, ""))
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.True(t, r.Effective.ProvenActive)

	// talon.config.yaml edited without restarting the gateway: the report
	// computes the new policy but must not call it active.
	raw, err := os.ReadFile(f.gw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.gw, []byte(strings.Replace(string(raw), "daily_cost: 100", "daily_cost: 90", 1)), 0o600))
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, runtimestatus.LoadedMatchesFile, r.Loaded.State, "the agent file did not change")
	assert.False(t, r.Effective.ProvenActive, "the running gateway loaded an older gateway config")
	assert.Equal(t, runtimestatus.BoundaryDiffers, r.Effective.Proof.State)
	assert.Contains(t, r.Effective.Basis, "not proven")

	// The proxy config edited without a restart: MCP decisions not proven.
	praw, err := os.ReadFile(f.proxy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.proxy, append(praw, []byte("# edited\n")...), 0o600))
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.False(t, r.MCPBoundary.ProvenActive)
	assert.Equal(t, runtimestatus.BoundaryDiffers, r.MCPBoundary.Proof.State)
}

// TestBuild_LastDecisionIsVerified (#555 review): the last decision is shown
// as authenticated history only when its signature verifies; a record changed
// after signing is flagged and its digests are not compared.
func TestBuild_LastDecisionIsVerified(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	first, err := Build(ctx, f.inputs())
	require.NoError(t, err)
	require.NoError(t, f.store.Store(ctx, &evidence.Evidence{
		ID: "ld1", CorrelationID: "c-ld1", TenantID: "default", AgentID: "hr-analytics-assistant", Timestamp: time.Now().UTC(), InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny", PolicyDigests: &evidence.PolicyDigests{Agent: first.CurrentFiles.PolicyDigest}},
	}))

	r, err := Build(ctx, f.inputs())
	require.NoError(t, err)
	require.NotNil(t, r.LastDecision)
	assert.Equal(t, "valid", r.LastDecision.Verification)
	assert.Equal(t, "same", r.LastDecision.AgentFile)

	// Make the denial look allowed, without re-signing.
	db, err := sql.Open("sqlite3", filepath.Join(f.dir, "evidence.db"))
	require.NoError(t, err)
	defer db.Close()
	var js string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT evidence_json FROM evidence WHERE id = 'ld1'`).Scan(&js))
	changed := strings.Replace(js, `"allowed":false`, `"allowed":true`, 1)
	require.NotEqual(t, js, changed)
	_, err = db.ExecContext(ctx, `UPDATE evidence SET evidence_json = ? WHERE id = 'ld1'`, changed)
	require.NoError(t, err)

	r, err = Build(ctx, f.inputs())
	require.NoError(t, err)
	require.NotNil(t, r.LastDecision)
	assert.Equal(t, "ld1", r.LastDecision.EvidenceID, "the record is still pointed at, never hidden")
	assert.Equal(t, "invalid", r.LastDecision.Verification)
	assert.Equal(t, "unverified", r.LastDecision.AgentFile, "no digest comparison on a record that fails verification")
	assert.Equal(t, "unverified", r.LastDecision.EffectivePolicy)
	assert.Contains(t, r.LastDecision.Note, "signature")
}

// TestBuild_DuplicateNameAcrossTenantsIsNotGuessed (#555 review 2): two
// tenants define a use case with the same name. Agent names are unique per
// installation, so the catalog rejects both files (#267) and the report
// resolves neither, in any tenant: it never returns one tenant's policy for
// the other. The error names the duplicate and both files.
func TestBuild_DuplicateNameAcrossTenantsIsNotGuessed(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	acme := filepath.Join(f.agents, "acme-hr")
	require.NoError(t, os.MkdirAll(acme, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(acme, "agent.talon.yaml"), []byte(`agent:
  name: hr-analytics-assistant
  tenant_id: acme
  version: "1.0.0"
policies:
  cost_limits:
    daily: 9
    monthly: 90
`), 0o600))

	for _, tenant := range []string{"", "default", "acme"} {
		in := f.inputs()
		in.Tenant = tenant
		r, err := Build(ctx, in)
		require.ErrorIs(t, err, ErrUnknownUseCase, "tenant %q", tenant)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "more than one file")
		assert.Contains(t, err.Error(), filepath.Join("acme-hr", "agent.talon.yaml"))
		assert.Contains(t, err.Error(), filepath.Join("hr-analytics-assistant", "agent.talon.yaml"))
	}
}

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func writeFleetReviewAgent(t *testing.T, agentsDir, name, tenant, secret string, extraPolicy string) string {
	t.Helper()
	d := filepath.Join(agentsDir, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
	if tenant != "" {
		y += "  tenant_id: " + tenant + "\n"
	}
	if secret != "" {
		y += "  key:\n    secret_name: " + secret + "\n"
	}
	y += "policies:\n  cost_limits:\n    per_request: 100.0\n    daily: 1000.0\n    monthly: 10000.0\n"
	y += extraPolicy
	p := filepath.Join(d, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(p, []byte(y), 0o600))
	return p
}

// TestAuthToRun_OneGeneration (#267 review, P1): server agent-key
// authentication and native execution derive from the SAME runtime holder —
// there is no independently swappable registry. A request authenticated
// under generation A whose agent moved tenants in generation B is EXPLICITLY
// REJECTED at run resolution (tenant mismatch), never silently executed
// under the new generation's identity; and a fresh authentication after the
// swap sees the new tenant — both surfaces moved together.
func TestAuthToRun_OneGeneration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeFleetReviewAgent(t, agentsDir, "support", "acme", "support-key", "")

	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(ctx, "support-key", []byte("tk-support"), secrets.ACL{}))

	buildGen := func() *agentcatalog.RuntimeSnapshot {
		scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
		require.NoError(t, err)
		reg, err := gateway.BuildIdentityRegistry(ctx, scan.LoadedAgents(), vault, "")
		require.NoError(t, err)
		bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{})
		require.NoError(t, err)
		return agentcatalog.NewRuntimeSnapshot(scan, bundles, reg, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
	}

	holder := agentcatalog.NewRuntimeHolder(buildGen())
	resolver := holderKeyResolver{holder: holder}

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	runner := agent.NewRunner(agent.RunnerConfig{Catalog: holder, Evidence: evStore})

	// Generation A: the key authenticates as support/acme.
	auth := resolver.AuthenticateAgentKey("tk-support")
	require.True(t, auth.Found)
	assert.Equal(t, "acme", auth.Identity.TenantID)

	// Generation B activates BETWEEN authentication and execution: the same
	// agent now belongs to tenant globex. ONE swap moves registry AND catalog.
	writeFleetReviewAgent(t, agentsDir, "support", "globex", "support-key", "")
	holder.Swap(buildGen())

	// The stale authenticated request (gen-A tenant) is explicitly rejected —
	// it can never execute under gen B with gen-A attribution.
	_, err = runner.Run(ctx, &agent.RunRequest{
		AgentName: auth.Identity.AgentID, TenantID: auth.Identity.TenantID,
		Prompt: "hello", InvocationType: "api",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant mismatch")

	// A fresh authentication resolves generation B — the SAME generation
	// execution resolves: no split is possible.
	auth = resolver.AuthenticateAgentKey("tk-support")
	require.True(t, auth.Found)
	assert.Equal(t, "globex", auth.Identity.TenantID)
}

// TestPlanExecute_FleetModeIgnoresStoredPolicyPath (#267 review, P1): a plan
// approved under a permissive historic policy file must execute under the
// agent's CURRENT catalog policy — later policy tightening can never be
// bypassed by the path captured at plan creation.
func TestPlanExecute_FleetModeIgnoresStoredPolicyPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("TALON_SIGNING_KEY", testutil.TestSigningKey)
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prevWd) })

	// Historic PERMISSIVE policy the plan was created under.
	permissive := filepath.Join(dir, "old-support.talon.yaml")
	require.NoError(t, os.WriteFile(permissive, []byte(`
agent:
  name: support
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
`), 0o600))

	// CURRENT fleet policy: RESTRICTIVE (denies on cost).
	agentsDir := filepath.Join(dir, "agents")
	writeFleetReviewAgent(t, agentsDir, "support", "", "", "")
	strict := "agent:\n  name: support\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    per_request: 0.000001\n    daily: 0.000001\n    monthly: 0.000001\n"
	require.NoError(t, os.WriteFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"), []byte(strict), 0o600))
	t.Setenv("TALON_AGENTS_DIR", agentsDir)

	// An approved plan carrying the historic permissive path.
	cfg, err := config.Load()
	require.NoError(t, err)
	require.NoError(t, cfg.EnsureDataDir())
	store, evStore, dbPlan, _, err := openPlanReviewStore()
	require.NoError(t, err)
	defer evStore.Close()
	defer dbPlan.Close()
	ctx := context.Background()
	plan := &agent.ExecutionPlan{
		ID: "plan_fleet_review", CorrelationID: "corr_fleet_review",
		TenantID: "default", AgentID: "support", Status: agent.PlanPending,
		Prompt: "do the thing", PolicyPath: permissive,
		CreatedAt: time.Now().UTC(), TimeoutAt: time.Now().UTC().Add(time.Hour),
	}
	require.NoError(t, store.Save(ctx, plan))
	require.NoError(t, store.Approve(ctx, plan.ID, "default", "reviewer"))

	// Manual execute: must be governed by the CURRENT strict policy — the
	// stored permissive path is ignored in fleet mode, so the run is DENIED.
	planTenantID = "default"
	planExecuteCmd.SetContext(ctx)
	err = runPlanExecute(planExecuteCmd, []string{plan.ID})
	require.Error(t, err, "the CURRENT restrictive policy must govern, not the plan's historic file")
	assert.Contains(t, err.Error(), "denied")
}

// TestAuthToRun_GenerationTokenRejectsRotation (#267 review round 2, P1):
// the COMMON split-generation case — agent name and tenant unchanged, but
// the key was rotated and the policy replaced between authentication and
// execution. The generation token captured at authentication travels into
// the run and fails closed: a key revoked in generation B can never
// authorize work that starts under generation B.
func TestAuthToRun_GenerationTokenRejectsRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")

	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })

	buildGen := func() *agentcatalog.RuntimeSnapshot {
		scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
		require.NoError(t, err)
		reg, err := gateway.BuildIdentityRegistry(ctx, scan.LoadedAgents(), vault, "")
		require.NoError(t, err)
		bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{})
		require.NoError(t, err)
		return agentcatalog.NewRuntimeSnapshot(scan, bundles, reg, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
	}

	// Generation A: support/acme, old key, permissive policy.
	writeFleetReviewAgent(t, agentsDir, "support", "acme", "old-key", "")
	require.NoError(t, vault.Set(ctx, "old-key", []byte("tk-old"), secrets.ACL{}))
	holder := agentcatalog.NewRuntimeHolder(buildGen())
	resolver := holderKeyResolver{holder: holder}

	auth := resolver.AuthenticateAgentKey("tk-old")
	require.True(t, auth.Found)
	require.NotEmpty(t, auth.Identity.Generation, "authentication captures the generation token")
	genA := auth.Identity.Generation

	// Generation B: SAME agent, SAME tenant — key rotated, policy tightened.
	writeFleetReviewAgent(t, agentsDir, "support", "acme", "new-key",
		"  data_classification:\n    block_on_pii: true\n")
	require.NoError(t, vault.Set(ctx, "new-key", []byte("tk-new"), secrets.ACL{}))
	holder.Swap(buildGen())
	require.NotEqual(t, genA, holder.Current().Generation)

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	runner := agent.NewRunner(agent.RunnerConfig{Catalog: holder, Evidence: evStore})

	// Name and tenant still match — but the generation token does not: the
	// stale authenticated request is rejected before any lifecycle state.
	_, err = runner.Run(ctx, &agent.RunRequest{
		AgentName: auth.Identity.AgentID, TenantID: auth.Identity.TenantID,
		ExpectedGeneration: genA,
		Prompt:             "hello", InvocationType: "api",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generation changed")

	// The rejection leaves signed early-termination evidence.
	records, err := evStore.List(ctx, "acme", "support", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.Contains(t, records[0].PolicyDecision.Reasons[0], "generation_changed")

	// A request authenticated under the CURRENT generation proceeds.
	auth = resolver.AuthenticateAgentKey("tk-new")
	require.True(t, auth.Found)
	assert.Equal(t, holder.Current().Generation, auth.Identity.Generation)
}

// TestPricingRoot_CLIAndServeAgree (#267 review round 2, P1): with a NESTED
// default_policy, a separate agents_dir, and a relative custom pricing file,
// the CLI and serve resolve the SAME pricing file from the project root —
// identical estimates on both surfaces.
func TestPricingRoot_CLIAndServeAgree(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prevWd) })

	// Project layout from the review: nested bootstrap default_policy,
	// separate agents_dir, root-level custom pricing.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "bootstrap"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "pricing"), 0o755))
	agentsDir := filepath.Join(dir, "agents")
	agentPath := writeFleetReviewAgent(t, agentsDir, "coding", "", "", "")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pricing", "custom.yaml"), []byte(`
version: "1"
currency: EUR
providers:
  openai:
    models:
      gpt-4o:
        input_per_1m: 111.0
        output_per_1m: 222.0
`), 0o600))

	cfg := &config.Config{
		AgentsDir:     agentsDir,
		DefaultPolicy: "bootstrap/agent.talon.yaml",
		LLM:           &config.LLMConfig{PricingFile: "pricing/custom.yaml"},
	}

	// CLI path: fleet mode, agent selected from agents_dir.
	cliTable := loadPricingTable(cfg, cliPricingBaseDir(cfg, "", agentPath))
	// Serve path: the same helper over the resolved default_policy path.
	serveTable := loadPricingTable(cfg, cliPricingBaseDir(cfg, "", filepath.Join(dir, "bootstrap", "agent.talon.yaml")))

	require.Equal(t, "EUR", cliTable.CurrencyCode(), "the custom file loaded (not the embedded default)")
	require.Equal(t, "EUR", serveTable.CurrencyCode(), "serve must resolve the SAME project-root pricing, not bootstrap/pricing/")

	cliCost, cliKnown := cliTable.Estimate("openai", "gpt-4o", 1000, 1000)
	serveCost, serveKnown := serveTable.Estimate("openai", "gpt-4o", 1000, 1000)
	require.True(t, cliKnown)
	require.True(t, serveKnown)
	assert.Equal(t, cliCost, serveCost, "identical estimates on both surfaces")
	assert.InDelta(t, 0.333, cliCost, 0.0001)
}

// TestCLIPricingBaseDir (#267 review, P1): pricing is SHARED process
// infrastructure — fleet mode resolves it from the project root (the same
// base serve uses), never the selected agent's directory.
func TestCLIPricingBaseDir(t *testing.T) {
	fleetCfg := &config.Config{AgentsDir: "./agents"}
	assert.Equal(t, ".", cliPricingBaseDir(fleetCfg, "", "agents/coding/agent.talon.yaml"),
		"fleet mode: project root, not the agent directory")
	assert.Equal(t, "sub", cliPricingBaseDir(fleetCfg, "sub/agent.talon.yaml", "sub/agent.talon.yaml"),
		"explicit --policy keeps the pre-fleet contract")
	singleCfg := &config.Config{}
	assert.Equal(t, "proj", cliPricingBaseDir(singleCfg, "", "proj/agent.talon.yaml"),
		"single-file mode: next to the policy file")
}

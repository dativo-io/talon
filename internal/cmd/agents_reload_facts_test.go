package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/secrets"
)

// runningServe stands in for `talon serve --gateway` of cfg's installation:
// the boot generation of agentsDir, a real reloader over it, and the runtime
// record published by serve's own code (startRuntimeStatus) with the reload
// interval serve passes (zero: reload disabled, the holder read directly, as
// serve does).
func runningServe(t *testing.T, cfg *config.Config, agentsDir string, every time.Duration) *agentcatalog.Reloader {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, os.MkdirAll(cfg.DataDir, 0o700))
	vault, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	require.NoError(t, err)
	require.NoError(t, vault.Set(ctx, "support-talon-key", []byte("talon_uc_support"), secrets.ACL{}))
	scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err)
	registry, err := gateway.BuildIdentityRegistry(ctx, scan.LoadedAgents(), vault, "")
	require.NoError(t, err)
	bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{})
	require.NoError(t, err)
	holder := agentcatalog.NewRuntimeHolder(agentcatalog.NewRuntimeSnapshot(scan, bundles, registry, time.Now().UTC()))
	reloader := agentcatalog.NewReloader(agentcatalog.ReloadConfig{Source: agentcatalog.Source{Dir: agentsDir}, Holder: holder, Vault: vault, RequireNonEmpty: true})
	view := reloader.View
	if every == 0 {
		view = func() agentcatalog.FleetView { return agentcatalog.FleetView{Snapshot: holder.Current()} }
	}

	oldGateway := serveGateway
	serveGateway = true
	stop := startRuntimeStatus(ctx, cfg, view, every)
	serveGateway = oldGateway
	t.Cleanup(func() {
		stop()
		_ = vault.Close()
	})
	require.Eventually(t, func() bool {
		v, readable := installationRuntime(cfg, time.Now().UTC())
		return readable && anyRunning(&v)
	}, 5*time.Second, 20*time.Millisecond, "the running process is on record")
	return reloader
}

// #575. While `talon serve` runs, `talon agents add`, `talon agents show`,
// `talon agents enable/disable` and the registration's fallback line state
// what the running process reports in its own runtime record: the interval
// it re-scans agents_dir at (never an assumed default), that it needs a
// restart when it does not reload, and, when its last re-scan was rejected,
// the blocking file and the cause. Only operator commands say this; nothing
// reaches an application's request.
func TestAgentsAdd_StatesTheRunningProcessReloadFacts(t *testing.T) {
	ctx := context.Background()
	add := func(t *testing.T, cfg *config.Config, name string) string {
		t.Helper()
		var out bytes.Buffer
		require.NoError(t, runAgentsAdd(ctx, &out, cfg, name))
		return out.String()
	}
	show := func(t *testing.T, cfg *config.Config, name string) string {
		t.Helper()
		cmd := newAgentsTestCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, showUseCase(ctx, cmd, cfg, name))
		return out.String()
	}
	noDefault := func(t *testing.T, text string) {
		t.Helper()
		require.NotRegexp(t, `default \d`, text, "the interval the running process reports, not a default")
	}

	t.Run("the process re-scans every 2s, then rejects a re-scan", func(t *testing.T) {
		cfg, agentsDir := setupAddFleetWith(t, addGateway)
		resetAgentsAddFlags(t)
		agentsAddNoCompanyPolicy, agentsAddOwner = false, "support-engineering"
		reloader := runningServe(t, cfg, agentsDir, 2*time.Second)
		v, _ := installationRuntime(cfg, time.Now().UTC())
		require.Equal(t, int64(2000), v.Processes[0].Catalog.ReloadIntervalMs, "the record states the interval")

		out := add(t, cfg, "customer-support")
		require.Contains(t, out, "Not active yet: the running Talon process loads it at its next re-scan of agents_dir (every 2s, agents_reload_interval). No restart is needed.")
		noDefault(t, out)
		next := show(t, cfg, "customer-support")
		require.Contains(t, next, "\nNext\n  A Talon process is running and has not loaded the current version of this use case yet. It re-scans agents_dir periodically (every 2s, agents_reload_interval) and loads it then, without a restart")
		noDefault(t, next)
		require.Equal(t, "the running `talon serve` applies this at its next re-scan (every 2s, agents_reload_interval), or on restart.", toggleActivationNote(cfg))
		require.Contains(t, fleetActivation(cfg), "loads the use case at its next re-scan of agents_dir (every 2s, agents_reload_interval)")

		// A use case written by hand whose key was never stored: the running
		// process rejects its next re-scan and keeps serving the previous
		// generation, so no new use case activates until that is fixed.
		legacy := filepath.Join(agentsDir, "legacy", "agent.talon.yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(legacy), 0o755))
		require.NoError(t, os.WriteFile(legacy, []byte("agent:\n  name: legacy\n  version: \"1.0.0\"\n  key:\n    secret_name: legacy-talon-key\npolicies:\n  cost_limits: {}\n"), 0o600))
		require.Equal(t, agentcatalog.ReloadRejected, reloader.ReloadOnce(ctx))
		require.Eventually(t, func() bool {
			v, readable := installationRuntime(cfg, time.Now().UTC())
			return readable && len(runtimestatus.ReloadFactsOf(v, "").RejectedCauses) > 0
		}, 5*time.Second, 20*time.Millisecond, "the record states the rejection")
		blocking := `Blocking: agent "legacy" (` + legacy + `): resolving key secret "legacy-talon-key"`

		out = add(t, cfg, "hr-copilot")
		require.Contains(t, out, "Not active. The running Talon process rejected the last change to the fleet and keeps serving the previous one. "+blocking)
		require.Contains(t, out, "Fix that; the next re-scan (every 2s, agents_reload_interval) loads the current files.")
		require.LessOrEqual(t, strings.Count(out, "\n"), 30, "the registration output stays short:\n%s", out)
		next = show(t, cfg, "hr-copilot")
		require.Contains(t, next, "Status      Not active")
		require.Contains(t, next, "\nNext\n  The running Talon process rejected the last change to the fleet and keeps serving the previous one. "+blocking)
		require.Contains(t, toggleActivationNote(cfg), "rejected the last change to the fleet and keeps serving the previous one: this applies only once a re-scan validates. "+blocking)
		require.Contains(t, fleetActivation(cfg), "so this use case is not active. "+blocking)
	})

	t.Run("the process does not reload", func(t *testing.T) {
		cfg, agentsDir := setupAddFleetWith(t, addGateway)
		resetAgentsAddFlags(t)
		agentsAddNoCompanyPolicy, agentsAddOwner = false, "support-engineering"
		runningServe(t, cfg, agentsDir, 0)
		v, _ := installationRuntime(cfg, time.Now().UTC())
		require.False(t, v.Processes[0].Catalog.ReloadEnabled)
		require.Zero(t, v.Processes[0].Catalog.ReloadIntervalMs)

		out := add(t, cfg, "customer-support")
		require.Contains(t, out, "Not active. A Talon process is running, but it does not re-scan agents_dir (agents_reload_interval is \"0\"): it loads this use case only when it starts. Restart `talon serve`, then look again.")
		require.NotContains(t, out, "No restart is needed")
		next := show(t, cfg, "customer-support")
		require.Contains(t, next, "\nNext\n  A Talon process is running, but it does not re-scan agents_dir (agents_reload_interval is \"0\")")
		require.Equal(t, "the running `talon serve` does not re-scan agent files (agents_reload_interval is \"0\"): it applies this when it restarts.", toggleActivationNote(cfg))
		require.Contains(t, fleetActivation(cfg), "it loads this use case only when it starts. Restart `talon serve`.")
	})

	t.Run("nothing runs", func(t *testing.T) {
		cfg, _ := setupAddFleetWith(t, addGateway)
		require.Equal(t, "a running `talon serve` applies this within its reload interval (agents_reload_interval, default "+config.DefaultAgentsReloadInterval+"), or on restart.", toggleActivationNote(cfg))
		require.Equal(t, "no Talon process of this installation is running. `talon serve` loads this use case when it starts.", fleetActivation(cfg))
	})
}

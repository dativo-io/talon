package fleetview

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/session"
)

func writeAgent(t *testing.T, agentsDir, name string, enabled bool, daily float64) {
	t.Helper()
	d := filepath.Join(agentsDir, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
	if !enabled {
		y += "  enabled: false\n"
	}
	// The agent schema requires a policies block; an agent without a daily
	// cap declares only a monthly one so "no daily cap" is a real absence.
	if daily > 0 {
		y += "policies:\n  cost_limits:\n    daily: 10\n"
	} else {
		y += "policies:\n  cost_limits:\n    monthly: 50\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
}

// TestProjectOffline_HandExpectations: two enabled agents and one disabled;
// a broken file is an issue, not a row; caps come from the agent override;
// a denial burst makes one agent need attention; the disabled one is
// stopped, never a failure.
func TestProjectOffline_HandExpectations(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeAgent(t, agentsDir, "alpha", true, 10)
	writeAgent(t, agentsDir, "beta", true, 0)
	writeAgent(t, agentsDir, "paused", false, 0)
	require.NoError(t, os.MkdirAll(filepath.Join(agentsDir, "broken"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(agentsDir, "broken", "agent.talon.yaml"), []byte("agent: [not a mapping"), 0o600))

	dbPath := filepath.Join(dir, "evidence.db")
	ev, err := evidence.NewStore(dbPath, "fleetview-test-signing-key-000001")
	require.NoError(t, err)
	defer ev.Close()
	ss, err := session.NewStore(dbPath)
	require.NoError(t, err)
	defer ss.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	put := func(id, agent string, allowed bool, minutesAgo int, cost float64) {
		require.NoError(t, ev.Store(ctx, &evidence.Evidence{
			ID: id, CorrelationID: "c_" + id, TenantID: "default", AgentID: agent, Timestamp: now.Add(-time.Duration(minutesAgo) * time.Minute),
			InvocationType: "gateway", PolicyDecision: evidence.PolicyDecision{Allowed: allowed, Action: map[bool]string{true: "allow", false: "deny"}[allowed]},
			Execution: evidence.Execution{Cost: cost, Currency: "EUR"},
		}))
	}
	// beta: 10 requests in the last hour, 3 denied (30% ≥ 20% over the floor of 10) → needs attention.
	for i := 0; i < 10; i++ {
		put("b"+string(rune('0'+i)), "beta", i >= 3, 5+i, 0.01)
	}
	// alpha: two quiet allowed requests today.
	put("a1", "alpha", true, 10, 0.50)
	put("a2", "alpha", true, 20, 0.25)

	scan, err := Scan(ctx, agentsDir, "")
	require.NoError(t, err)
	res, err := ProjectOffline(ctx, Inputs{
		Scan: scan, Org: gateway.OrganizationPolicy{}, Providers: nil, Tenant: "", Currency: "EUR",
		Evidence: ev, Sessions: ss, Now: now,
	})
	require.NoError(t, err)

	require.Len(t, res.Issues, 1, "the broken file is an issue, not an agent")
	assert.Contains(t, res.Issues[0].Path, "broken")

	byName := map[string]fleet.AgentRow{}
	for _, r := range res.Rows {
		byName[r.Name] = r
	}
	require.Len(t, byName, 3)
	assert.Equal(t, "beta", res.Rows[0].Name, "needs-attention sorts before healthy")
	assert.Equal(t, fleet.HealthNeedsAttention, byName["beta"].Health)
	assert.Equal(t, 10, byName["beta"].Requests)
	assert.Equal(t, 3, byName["beta"].Denied)
	assert.Equal(t, fleet.HealthHealthy, byName["alpha"].Health)
	assert.Equal(t, fleet.StateEnabled, byName["alpha"].State)
	assert.InDelta(t, 0.75, byName["alpha"].SpendDay, 1e-9)
	assert.InDelta(t, 10, byName["alpha"].DailyCap, 1e-9)
	assert.Equal(t, "EUR", byName["alpha"].Currency)
	assert.Equal(t, fleet.StateStopped, byName["paused"].State)
	assert.Equal(t, fleet.HealthStopped, byName["paused"].Health)

	assert.InDelta(t, 10, res.Caps["alpha"].Daily, 1e-9)
	assert.Zero(t, res.Caps["beta"].Daily, "no daily cap declared, none invented")
	assert.InDelta(t, 50, res.Caps["beta"].Monthly, 1e-9)
	assert.Zero(t, byName["beta"].DailyCap)
	assert.InDelta(t, 50, byName["beta"].MonthlyCap, 1e-9)

	// Tenant filter: an unknown tenant projects nothing but keeps the issues.
	res2, err := ProjectOffline(ctx, Inputs{Scan: scan, Tenant: "acme", Currency: "EUR", Evidence: ev, Sessions: ss, Now: now})
	require.NoError(t, err)
	assert.Empty(t, res2.Rows)
	assert.Len(t, res2.Issues, 1)
}

func TestProjectOffline_RequiresInputs(t *testing.T) {
	_, err := ProjectOffline(context.Background(), Inputs{})
	require.ErrorContains(t, err, "scan result is required")
	// An empty source scans to nothing; the CLI shows an empty queue, not an
	// error, and the console shows an empty section.
	scan, err := Scan(context.Background(), "", "")
	require.NoError(t, err)
	assert.Empty(t, scan.Agents)
}

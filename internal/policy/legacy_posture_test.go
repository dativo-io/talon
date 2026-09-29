package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #442: the removed live-posture keys must fail on EVERY load path with a
// tailored migration message — never be silently ignored (which would turn an
// old "observe only" file into an enforced one without telling the operator)
// and never be honoured.
func TestLoadPolicy_RejectsRemovedPostureKeys(t *testing.T) {
	base := `
agent:
  name: "legacy-agent"
  version: "1.0.0"
policies:
  cost_limits:
    daily: 1.0
`
	cases := []struct {
		name    string
		extra   string
		wantKey string
	}{
		{"audit.observation_only true", "audit:\n  observation_only: true\n", "audit.observation_only"},
		{"audit.observation_only false is still removed", "audit:\n  observation_only: false\n", "audit.observation_only"},
		{"schema_validation shadow", "tool_policies:\n  _default:\n    schema_validation: shadow\n", "tool_policies._default.schema_validation"},
		{"schema_validation disabled", "tool_policies:\n  sql_query:\n    schema_validation: disabled\n", "tool_policies.sql_query.schema_validation"},
		{"schema_validation enforce is redundant and removed", "tool_policies:\n  sql_query:\n    schema_validation: enforce\n", "tool_policies.sql_query.schema_validation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "agent.talon.yaml")
			require.NoError(t, os.WriteFile(path, []byte(base+tc.extra), 0o600))
			// Non-strict load is the lenient CLI path (`talon validate <file>`,
			// plain serve): unknown keys are only warned there, so the removed
			// keys need their own hard rejection.
			_, err := LoadPolicy(context.Background(), path, false, dir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantKey)
			assert.Contains(t, err.Error(), "#442")
			assert.Contains(t, err.Error(), "talon run --dry-run")
		})
	}
}

func TestLoadPolicy_AuditWithoutObservationOnlyStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
agent:
  name: "ok-agent"
  version: "1.0.0"
policies:
  cost_limits:
    daily: 1.0
audit:
  log_level: detailed
  retention_days: 30
tool_policies:
  sql_query:
    max_row_count: 100
`), 0o600))
	pol, err := LoadPolicy(context.Background(), path, false, dir)
	require.NoError(t, err)
	assert.Equal(t, "detailed", pol.Audit.LogLevel)
	assert.Equal(t, 100, pol.ToolPolicies["sql_query"].MaxRowCount)
}

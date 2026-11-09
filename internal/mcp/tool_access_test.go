package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

// TestEvaluateToolAccess_SameChecksAsTheHandler (#305): a forbidden tool is
// decided by the forbidden_tools stage before policy; an allowed tool passes
// the proxy policy engine; a tool outside allowed_tools is denied by policy.
func TestEvaluateToolAccess_SameChecksAsTheHandler(t *testing.T) {
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "hr-mcp-proxy", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:       policy.UpstreamConfig{Vendor: "hr-backend", URL: "http://hr:9000/mcp"},
			AllowedTools:   []policy.ToolMapping{{Name: "hr_aggregate_sql"}},
			ForbiddenTools: []string{"hr_employee_export", "admin_*"},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	got, err := EvaluateToolAccess(context.Background(), cfg, engine, "hr_employee_export")
	require.NoError(t, err)
	assert.False(t, got.Allowed)
	assert.Equal(t, "forbidden_tools", got.Stage)
	assert.Equal(t, "hr_employee_export", got.Matched)

	got, err = EvaluateToolAccess(context.Background(), cfg, engine, "admin_reset")
	require.NoError(t, err)
	assert.Equal(t, "admin_*", got.Matched, "wildcard entries match like the handler's check")

	got, err = EvaluateToolAccess(context.Background(), cfg, engine, "hr_aggregate_sql")
	require.NoError(t, err)
	assert.True(t, got.Allowed)
	assert.Equal(t, "policy", got.Stage)

	got, err = EvaluateToolAccess(context.Background(), cfg, engine, "hr_salary_dump")
	require.NoError(t, err)
	assert.False(t, got.Allowed, "a tool outside allowed_tools is denied by the proxy policy")
	assert.Equal(t, "policy", got.Stage)
	assert.NotEmpty(t, got.Reasons)
}

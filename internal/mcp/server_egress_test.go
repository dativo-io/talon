package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newServerHandlerForFlowWithScanner(
	t *testing.T,
	allowedTools []string,
	scanner *classifier.Scanner,
	extraTools ...tools.Tool,
) (*Handler, *evidence.Store) {
	t.Helper()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "test", Version: "1.0"},
		VersionTag:   "v1",
		Policies:     policy.PoliciesConfig{},
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: allowedTools},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	reg.Register(&stubToolForTest{name: "echo"})
	for _, tl := range extraTools {
		reg.Register(tl)
	}
	return NewHandler(reg, engine, store, scanner), store
}

func TestNoPIIEgressAfterRedaction_MCPServer(t *testing.T) {
	h, _ := newServerHandlerForFlow(t, []string{"pii_tool"}, &piiToolForTest{})
	resp := serverToolsCall(t, h, "pii_tool", `{}`)
	require.Nil(t, resp.Error)

	serialized, err := json.Marshal(resp.Result)
	require.NoError(t, err)
	assert.NotContains(t, string(serialized), "hans.mueller@example.de")
}

func TestMCPServerResidualPIIApprovalCannotBypass(t *testing.T) {
	h, store := newServerHandlerForFlowWithScanner(t, []string{"pii_tool"}, mcpResidualScanner(t), &piiToolForTest{})
	resp := serverToolsCall(t, h, "pii_tool", `{"approval":"approved"}`)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "recognized PII remains after redaction")
	assert.Contains(t, resp.Error.Message, "use approval workflow")

	ev := latestServerEvidence(t, store)
	assert.False(t, ev.PolicyDecision.Allowed, "residual output block must be persisted as denied evidence")
	assert.Contains(t, ev.PolicyDecision.Reasons, "output_pii_blocked_residual")
	require.NotNil(t, ev.DataFlow)
	require.Len(t, ev.DataFlow.Items, 2, "args flow plus blocked result flow")
	assert.Equal(t, evidence.FlowDispositionBlocked, ev.DataFlow.Items[1].Disposition,
		"residual output blocks must be recorded as blocked egress")
}

func TestMCPServerResidualPIIRequestBlockWritesEvidence(t *testing.T) {
	h, store := newServerHandlerForFlowWithScanner(t, []string{"echo"}, mcpResidualScanner(t))
	resp := serverToolsCall(t, h, "echo", `{"q":"contact anna.schmidt@example.com","approval":"approved"}`)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "recognized PII remains after redaction")
	assert.Contains(t, resp.Error.Message, "use approval workflow")

	ev := latestServerEvidence(t, store)
	assert.False(t, ev.PolicyDecision.Allowed, "residual request block must be persisted as denied evidence")
	assert.Contains(t, ev.PolicyDecision.Reasons, "request_residual_pii_after_redaction")
	require.NotNil(t, ev.DataFlow)
	require.Len(t, ev.DataFlow.Items, 1)
	assert.Equal(t, evidence.FlowDispositionBlocked, ev.DataFlow.Items[0].Disposition,
		"blocked request egress must be recorded with blocked disposition")
}

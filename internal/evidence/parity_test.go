package evidence

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGovernanceParity_EntryPathContract is the governance parity contract:
// it enumerates every evidence-producing entry path and asserts that the
// record shape each path produces (per its package tests) satisfies the
// shared invariants. When a new entry path is added, add a row here and wire
// the same controls — the runtime guardrail in Store.Store will flag any
// path that ships without doing so.
func TestGovernanceParity_EntryPathContract(t *testing.T) {
	tests := []struct {
		name string // entry path
		ev   Evidence
	}{
		{
			name: "agent_runner_cli_run",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "corr_1", AgentID: "agent",
				InvocationType: "manual",
				Execution:      Execution{ModelUsed: "gpt-4o-mini"},
				DataFlow: &DataFlow{Detector: "talon-regex", Items: []DataFlowItem{{
					Source: FlowSourcePrompt, Disposition: FlowDispositionForwarded,
					Destination: FlowDestination{Kind: FlowDestLLMProvider, Name: "openai", Region: "US"},
				}}},
			},
		},
		{
			name: "gateway_llm_proxy",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "corr_2", AgentID: "gateway-client",
				InvocationType: "gateway",
				Execution:      Execution{ModelUsed: "gpt-4o"},
				DataFlow: &DataFlow{Detector: "talon-regex", Items: []DataFlowItem{{
					Source: FlowSourcePrompt, Disposition: FlowDispositionForwarded,
					Destination: FlowDestination{Kind: FlowDestLLMProvider, Name: "openai", Region: "US"},
				}}},
			},
		},
		{
			name: "mcp_server_embedded_tool",
			ev: Evidence{
				TenantID: "default", CorrelationID: "mcp_1", AgentID: "mcp-client",
				InvocationType: "mcp",
				Execution:      Execution{ToolsCalled: []string{"echo"}},
				DataFlow: &DataFlow{Detector: "talon-regex", Items: []DataFlowItem{{
					Source: FlowSourceToolArgs, Disposition: FlowDispositionForwarded,
					Destination: FlowDestination{Kind: FlowDestMCPTool, Name: "echo", Region: "LOCAL"},
				}}},
			},
		},
		{
			name: "mcp_proxy_upstream_tool",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "mcp_proxy_1", AgentID: "mcp-proxy",
				InvocationType: "proxy_tool_call",
				Execution:      Execution{ToolsCalled: []string{"search_issues"}},
				DataFlow: &DataFlow{Detector: "talon-regex", Items: []DataFlowItem{{
					Source: FlowSourceToolArgs, Disposition: FlowDispositionForwarded,
					Destination: FlowDestination{Kind: FlowDestMCPTool, Name: "github", Region: "unknown"},
				}}},
			},
		},
		{
			name: "graph_adapter_run_end",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "gr_1", AgentID: "graph-agent",
				InvocationType: "graph_run",
				Execution:      Execution{ModelUsed: "gpt-4o"},
				DataFlow: &DataFlow{Items: []DataFlowItem{{
					Source: FlowSourcePrompt, SourceDetail: "orchestrator-reported",
					Disposition: FlowDispositionForwarded,
					Destination: FlowDestination{Kind: FlowDestLLMProvider, Name: "external:langgraph", Model: "gpt-4o", Region: FlowRegionUnknown},
				}}},
			},
		},
		{
			name: "graph_adapter_run_end_no_model_call",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "gr_2", AgentID: "graph-agent",
				InvocationType: "graph_run",
				// No model observed, zero cost: placeholder model, no flow — by design.
				Execution: Execution{ModelUsed: "unknown_graph_model"},
			},
		},
		{
			name: "agent_runner_cache_hit",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "corr_3", AgentID: "agent",
				InvocationType: "manual", CacheHit: true,
				Execution: Execution{ModelUsed: "gpt-4o-mini"},
				DataFlow: &DataFlow{Detector: "talon-regex", Items: []DataFlowItem{{
					Source: FlowSourcePrompt, Disposition: FlowDispositionForwarded,
					Destination: FlowDestination{Kind: FlowDestCache, Name: "cache_abc"},
				}}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Empty(t, ValidateGovernedRecord(&tt.ev),
				"entry path %q must satisfy the governance parity contract", tt.name)
		})
	}
}

func TestValidateGovernedRecord_Violations(t *testing.T) {
	tests := []struct {
		name string
		ev   Evidence
		want []string
	}{
		{
			name: "model call without data_flow",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "c1",
				Execution: Execution{ModelUsed: "gpt-4o"},
			},
			want: []string{"model call recorded without data_flow"},
		},
		{
			name: "missing tenant and correlation",
			ev:   Evidence{},
			want: []string{"missing tenant_id", "missing correlation_id"},
		},
		{
			name: "empty data_flow items",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "c2",
				DataFlow: &DataFlow{},
			},
			want: []string{"data_flow present but has no items"},
		},
		{
			name: "graph placeholder model without flow is exempt",
			ev: Evidence{
				TenantID: "acme", CorrelationID: "c3",
				Execution: Execution{ModelUsed: "unknown_graph_model"},
			},
			want: nil,
		},
		{
			name: "control-plane mode_change marker is exempt",
			ev: Evidence{
				TenantID: "system", CorrelationID: "mc_1",
				Execution: Execution{ModelUsed: "mode_change:shadow->enforce"},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ValidateGovernedRecord(&tt.ev))
		})
	}
}

package evidence

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ts(sec int) time.Time {
	return time.Date(2026, 7, 5, 10, 0, sec, 0, time.UTC)
}

func rec(sessionID, tenant, caller string, allowed bool, cost float64, in, out, cr, cw int, provider, model string, orch *OrchestrationContext) *Evidence {
	ev := &Evidence{
		SessionID:      sessionID,
		TenantID:       tenant,
		AgentID:        caller,
		Timestamp:      ts(0),
		PolicyDecision: PolicyDecision{Allowed: allowed},
		Execution: Execution{
			ModelUsed: model,
			Cost:      cost,
			Tokens:    TokenUsage{Input: in, Output: out, CacheRead: cr, CacheWrite: cw},
		},
		Orchestration: orch,
	}
	if provider != "" {
		ev.RoutingDecision = &RoutingDecision{SelectedProvider: provider}
	}
	return ev
}

func TestBuildSessionSummary_TotalsAndCounts(t *testing.T) {
	records := []*Evidence{
		rec("sess1", "acme", "coder", true, 0.10, 1000, 200, 500, 100, "anthropic", "claude-sonnet-5", nil),
		rec("sess1", "acme", "coder", false, 0.00, 0, 0, 0, 0, "openai", "gpt-5.3-codex", nil),
		rec("sess1", "acme", "coder", true, 0.05, 300, 50, 0, 0, "anthropic", "claude-sonnet-5", nil),
	}
	records[1].Execution.Error = "secret retrieval error"

	sum := BuildSessionSummary("sess1", records)

	assert.Equal(t, 3, sum.RecordCount)
	assert.Equal(t, 2, sum.Allowed)
	assert.Equal(t, 1, sum.Denied)
	assert.Equal(t, 1, sum.Errors)
	assert.Equal(t, "acme", sum.TenantID)
	assert.InDelta(t, 0.15, sum.TotalCost, 1e-9)
	assert.Equal(t, 1300, sum.InputTokens)
	assert.Equal(t, 250, sum.OutputTokens)
	assert.Equal(t, 500, sum.CacheReadTokens)
	assert.Equal(t, 100, sum.CacheWriteTokens)
	assert.Equal(t, []string{"anthropic", "openai"}, sum.Providers)
	assert.Len(t, sum.Models, 2)
}

func TestBuildSessionSummary_PerAgentRollupFromOrchestration(t *testing.T) {
	orchGen := &OrchestrationContext{AgentID: "generator", Client: "claude-code", SessionSource: "client_asserted"}
	orchJudge := &OrchestrationContext{AgentID: "judge", ParentAgentID: "generator", Client: "claude-code", SessionSource: "client_asserted"}
	records := []*Evidence{
		rec("s", "acme", "orchestrator", true, 0.20, 1000, 300, 0, 0, "anthropic", "claude-opus-4-8", orchGen),
		rec("s", "acme", "orchestrator", true, 0.02, 200, 40, 0, 0, "anthropic", "claude-haiku-4-5", orchJudge),
		rec("s", "acme", "orchestrator", true, 0.05, 400, 60, 0, 0, "anthropic", "claude-opus-4-8", orchGen),
	}

	sum := BuildSessionSummary("s", records)

	if sum.Client != "claude-code" || sum.SessionSource != "client_asserted" {
		t.Errorf("client/source = %q/%q, want claude-code/client_asserted", sum.Client, sum.SessionSource)
	}
	if len(sum.Agents) != 2 {
		t.Fatalf("Agents = %d, want 2 (generator, judge)", len(sum.Agents))
	}
	// Sorted by descending cost: generator (0.25) before judge (0.02).
	if sum.Agents[0].AgentID != "generator" {
		t.Errorf("Agents[0] = %q, want generator (highest cost first)", sum.Agents[0].AgentID)
	}
	if got, want := sum.Agents[0].TotalCost, 0.25; got < want-1e-9 || got > want+1e-9 {
		t.Errorf("generator cost = %v, want %v", got, want)
	}
	if sum.Agents[0].RecordCount != 2 {
		t.Errorf("generator records = %d, want 2", sum.Agents[0].RecordCount)
	}
	if sum.Agents[1].AgentID != "judge" || sum.Agents[1].ParentAgentID != "generator" {
		t.Errorf("Agents[1] = %q parent %q, want judge/generator", sum.Agents[1].AgentID, sum.Agents[1].ParentAgentID)
	}
}

func TestBuildSessionSummary_FallsBackToCallerWhenNoOrchestration(t *testing.T) {
	records := []*Evidence{
		rec("s", "acme", "cli-user", true, 0.10, 100, 20, 0, 0, "anthropic", "claude-sonnet-5", nil),
	}
	sum := BuildSessionSummary("s", records)
	if len(sum.Agents) != 1 || sum.Agents[0].AgentID != "cli-user" {
		t.Fatalf("Agents = %v, want single caller-keyed row cli-user", sum.Agents)
	}
	if len(sum.Callers) != 1 || sum.Callers[0] != "cli-user" {
		t.Errorf("Callers = %v, want [cli-user]", sum.Callers)
	}
}

func TestBuildSessionSummary_CrossCallerVisible(t *testing.T) {
	records := []*Evidence{
		rec("s", "acme", "callerA", true, 0.10, 100, 20, 0, 0, "anthropic", "claude-sonnet-5", nil),
		rec("s", "acme", "callerB", true, 0.10, 100, 20, 0, 0, "anthropic", "claude-sonnet-5", nil),
	}
	sum := BuildSessionSummary("s", records)
	if len(sum.Callers) != 2 {
		t.Errorf("Callers = %v, want two distinct callers surfaced", sum.Callers)
	}
}

func TestBuildSessionSummary_TimeWindowAndNilSkip(t *testing.T) {
	a := rec("s", "acme", "c", true, 0.01, 1, 1, 0, 0, "anthropic", "m", nil)
	a.Timestamp = ts(30)
	b := rec("s", "acme", "c", true, 0.01, 1, 1, 0, 0, "anthropic", "m", nil)
	b.Timestamp = ts(5)
	sum := BuildSessionSummary("s", []*Evidence{a, nil, b})
	if sum.RecordCount != 2 {
		t.Errorf("RecordCount = %d, want 2 (nil skipped)", sum.RecordCount)
	}
	if !sum.FirstSeen.Equal(ts(5)) || !sum.LastSeen.Equal(ts(30)) {
		t.Errorf("window = %s..%s, want %s..%s", sum.FirstSeen, sum.LastSeen, ts(5), ts(30))
	}
}

func TestBuildSessionSummary_Empty(t *testing.T) {
	sum := BuildSessionSummary("s", nil)
	if sum.RecordCount != 0 || sum.SessionID != "s" || sum.Agents != nil {
		t.Errorf("empty summary = %+v, want zeroed with SessionID set", sum)
	}
}

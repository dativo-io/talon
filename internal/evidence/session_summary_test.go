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
	// Deny record carries no currency (cost 0); the summary takes the unit
	// from the first record that has one (#216).
	records[0].Execution.Currency = "USD"
	records[2].Execution.Currency = "USD"

	sum := BuildSessionSummary("sess1", records)

	assert.Equal(t, 3, sum.RecordCount)
	assert.Equal(t, 2, sum.Allowed)
	assert.Equal(t, 1, sum.Denied)
	assert.Equal(t, 1, sum.Errors)
	assert.Equal(t, "acme", sum.TenantID)
	assert.Equal(t, "USD", sum.Currency)
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
	if len(sum.Subagents) != 2 {
		t.Fatalf("Agents = %d, want 2 (generator, judge)", len(sum.Subagents))
	}
	// Sorted by descending cost: generator (0.25) before judge (0.02).
	if sum.Subagents[0].AgentID != "generator" {
		t.Errorf("Agents[0] = %q, want generator (highest cost first)", sum.Subagents[0].AgentID)
	}
	if got, want := sum.Subagents[0].TotalCost, 0.25; got < want-1e-9 || got > want+1e-9 {
		t.Errorf("generator cost = %v, want %v", got, want)
	}
	if sum.Subagents[0].RecordCount != 2 {
		t.Errorf("generator records = %d, want 2", sum.Subagents[0].RecordCount)
	}
	if sum.Subagents[1].AgentID != "judge" || sum.Subagents[1].ParentAgentID != "generator" {
		t.Errorf("Agents[1] = %q parent %q, want judge/generator", sum.Subagents[1].AgentID, sum.Subagents[1].ParentAgentID)
	}
}

func TestBuildSessionSummary_FallsBackToCallerWhenNoOrchestration(t *testing.T) {
	records := []*Evidence{
		rec("s", "acme", "cli-user", true, 0.10, 100, 20, 0, 0, "anthropic", "claude-sonnet-5", nil),
	}
	sum := BuildSessionSummary("s", records)
	if len(sum.Subagents) != 1 || sum.Subagents[0].AgentID != "cli-user" {
		t.Fatalf("Agents = %v, want single caller-keyed row cli-user", sum.Subagents)
	}
	if len(sum.AgentIDs) != 1 || sum.AgentIDs[0] != "cli-user" {
		t.Errorf("AgentIDs = %v, want [cli-user]", sum.AgentIDs)
	}
}

func TestBuildSessionSummary_CrossCallerVisible(t *testing.T) {
	records := []*Evidence{
		rec("s", "acme", "callerA", true, 0.10, 100, 20, 0, 0, "anthropic", "claude-sonnet-5", nil),
		rec("s", "acme", "callerB", true, 0.10, 100, 20, 0, 0, "anthropic", "claude-sonnet-5", nil),
	}
	sum := BuildSessionSummary("s", records)
	if len(sum.AgentIDs) != 2 {
		t.Errorf("AgentIDs = %v, want two distinct agent identities surfaced", sum.AgentIDs)
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
	if sum.RecordCount != 0 || sum.SessionID != "s" || sum.Subagents != nil {
		t.Errorf("empty summary = %+v, want zeroed with SessionID set", sum)
	}
}

func TestListRecentOrchestrationSessionIDs(t *testing.T) {
	store, err := NewStore(t.TempDir()+"/e.db", "test-signing-key-1234567890123456")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := t.Context()
	now := time.Now().UTC()
	put := func(id, sessionID string, orch *OrchestrationContext, ts time.Time) {
		ev := &Evidence{
			ID: id, CorrelationID: "c_" + id, SessionID: sessionID, Timestamp: ts,
			TenantID: "default", AgentID: "coder", InvocationType: "gateway",
			PolicyDecision: PolicyDecision{Allowed: true}, Orchestration: orch,
		}
		if err := store.Store(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	orch := func(sid string) *OrchestrationContext {
		return &OrchestrationContext{SessionID: sid, Client: "generic", SessionSource: "client_asserted", Provenance: "client_asserted"}
	}
	put("e1", "sess-old", orch("sess-old"), now.Add(-3*time.Hour))
	put("e2", "sess-new", orch("sess-new"), now.Add(-1*time.Minute))
	put("e3", "sess-old", orch("sess-old"), now.Add(-2*time.Hour))
	put("e4", "sess_gw_synthetic", nil, now) // no orchestration block → excluded

	ids, err := store.ListRecentOrchestrationSessionIDs(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "sess-new" || ids[1] != "sess-old" {
		t.Fatalf("ids = %v, want [sess-new sess-old] (newest activity first, synthetic excluded)", ids)
	}

	one, err := store.ListRecentOrchestrationSessionIDs(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0] != "sess-new" {
		t.Fatalf("limit=1 → %v, want [sess-new]", one)
	}
}

// The #271 operational contract: one session that saw a fallback, a denial, a
// caller retry, intercepted MCP tool calls, tool filtering, and PII redaction
// must surface every fact with counts and the serving provider path.
func TestBuildSessionSummary_OperationalContract(t *testing.T) {
	served := rec("s", "acme", "coder", true, 0.10, 1000, 200, 0, 0, "anthropic", "claude-sonnet-5", nil)
	served.Timestamp = ts(1)
	served.InvocationType = "gateway"
	served.ToolGovernance = &ToolGovernance{
		ToolsRequested: []string{"search", "delete_record", "summarize"},
		ToolsFiltered:  []string{"delete_record"},
		ToolsForwarded: []string{"search", "summarize"},
	}
	served.Classification.PIIRedacted = true
	served.Classification.PIIDetected = []string{"EMAIL"}

	failedAttempt := rec("s", "acme", "coder", true, 0, 0, 0, 0, 0, "", "claude-sonnet-5", nil)
	failedAttempt.Timestamp = ts(10)
	failedAttempt.InvocationType = "gateway_failover_attempt"
	failedAttempt.Status = "failed"
	failedAttempt.FailureReason = FailureReasonProviderTransient
	failedAttempt.Execution.Error = "upstream status 529"
	failedAttempt.Failover = &FailoverContext{Role: FailoverRoleFailedAttempt, Provider: "anthropic", Model: "claude-sonnet-5"}

	fallbackServed := rec("s", "acme", "coder", true, 0.08, 800, 150, 0, 0, "", "gpt-5", nil)
	fallbackServed.Timestamp = ts(11)
	fallbackServed.InvocationType = "gateway"
	fallbackServed.RetryAttempt = "1"
	fallbackServed.Failover = &FailoverContext{Role: FailoverRoleFallbackDecision, Provider: "openai", Model: "gpt-5"}

	denied := rec("s", "acme", "coder", false, 0, 0, 0, 0, 0, "", "", nil)
	denied.Timestamp = ts(20)
	denied.PolicyDecision.Reasons = []string{"session_budget_exceeded: estimated cost 0.09 exceeds remaining session budget 0.01"}

	toolAllowed := rec("s", "acme", "coder", true, 0, 0, 0, 0, 0, "", "", nil)
	toolAllowed.Timestamp = ts(5)
	toolAllowed.InvocationType = "proxy_tool_call"
	toolAllowed.Execution.ToolsCalled = []string{"search_kb"}

	toolDenied := rec("s", "acme", "coder", false, 0, 0, 0, 0, 0, "", "", nil)
	toolDenied.Timestamp = ts(6)
	toolDenied.InvocationType = "proxy_tool_blocked"
	toolDenied.Execution.ToolsCalled = []string{"delete_record"}
	toolDenied.PolicyDecision.Reasons = []string{"mcp_tool_denied: delete_record"}
	toolDenied.Execution.Error = "mcp_tool_denied: delete_record"

	// Newest-first input, the ListBySessionID order.
	sum := BuildSessionSummary("s", []*Evidence{denied, fallbackServed, failedAttempt, toolDenied, toolAllowed, served})

	assert.Equal(t, 6, sum.RecordCount)
	assert.Equal(t, 3, sum.Requests, "LLM requests: served, fallback-served, denied — attempt and tool calls split out")
	assert.Equal(t, 2, sum.ToolCalls)
	assert.Equal(t, 1, sum.ToolCallsDenied)
	assert.Equal(t, 0, sum.ToolCallsFailed)
	assert.Equal(t, []string{"delete_record", "search_kb"}, sum.ToolNames)
	assert.Equal(t, 1, sum.Retries)
	assert.Equal(t, 1, sum.FailedAttempts)
	assert.Equal(t, 1, sum.Fallbacks)
	assert.Equal(t, 0, sum.FailClosed)
	assert.Equal(t, map[string]int{"session_budget_exceeded": 1, "mcp_tool_denied": 1}, sum.DeniedByReason)
	assert.Equal(t, []string{"anthropic/claude-sonnet-5", "openai/gpt-5"}, sum.ProviderPath,
		"path lists what served, in time order — the failed attempt is not a hop")
	assert.Equal(t, []string{"delete_record"}, sum.ToolsFiltered)
	assert.Equal(t, 1, sum.ToolFilterEvents)
	assert.Equal(t, 1, sum.PIIRedactions)
	assert.Equal(t, []string{"EMAIL"}, sum.PIITypes)
	assert.Equal(t, ts(20).Sub(ts(1)).Milliseconds(), sum.DurationMS)
	if assert.NotNil(t, sum.LastFailure, "denied session must explain its failure") {
		assert.Equal(t, "session_budget_exceeded", sum.LastFailure.Code)
		assert.True(t, sum.LastFailure.At.Equal(ts(20)))
	}

	// Order independence: oldest-first input gives the identical summary.
	sum2 := BuildSessionSummary("s", []*Evidence{served, toolAllowed, toolDenied, failedAttempt, fallbackServed, denied})
	assert.Equal(t, sum, sum2, "summary must be input-order independent")
}

// The failure explanation is the NEWEST deny or execution failure; structured
// failure_reason wins over the generic "error" code.
func TestBuildSessionSummary_LastFailureNewestWins(t *testing.T) {
	older := rec("s", "acme", "c", false, 0, 0, 0, 0, 0, "", "", nil)
	older.Timestamp = ts(3)
	older.PolicyDecision.Reasons = []string{"pii_block: EMAIL in tier-2 payload"}
	newer := rec("s", "acme", "c", true, 0, 0, 0, 0, 0, "", "m", nil)
	newer.Timestamp = ts(9)
	newer.Execution.Error = "provider timeout after 30s"
	newer.FailureReason = "llm_error"

	sum := BuildSessionSummary("s", []*Evidence{older, newer})
	if assert.NotNil(t, sum.LastFailure) {
		assert.Equal(t, "llm_error", sum.LastFailure.Code)
		assert.Equal(t, "provider timeout after 30s", sum.LastFailure.Detail)
	}

	clean := rec("s", "acme", "c", true, 0.01, 1, 1, 0, 0, "anthropic", "m", nil)
	assert.Nil(t, BuildSessionSummary("s", []*Evidence{clean}).LastFailure)
}

// Moved with the classifier from internal/metrics (#271): one deny-reason
// vocabulary for the dashboard event projection and the session summary.
func TestDenyReasonCode(t *testing.T) {
	assert.Equal(t, "policy_deny", DenyReasonCode(nil))
	assert.Equal(t, "policy_deny", DenyReasonCode([]string{"Data tier 2 exceeds caller restriction (max 1)"}))
	assert.Equal(t, "session_budget_exceeded", DenyReasonCode([]string{"session_budget_exceeded: spend"}))
	assert.Equal(t, "egress_tier_destination_disallowed", DenyReasonCode([]string{"egress_tier_destination_disallowed"}))
	assert.Equal(t, "policy_deny", DenyReasonCode([]string{"<img onerror=alert(1)>: nope"}), "hostile prefix falls back")
}

// The session's client/source label comes from the EARLIEST orchestrated
// record (the client that opened the session), regardless of input order —
// ListBySessionID returns newest-first, which used to mislabel a
// mostly-claude-code session as "codex" (found in the #203 demo).
func TestBuildSessionSummary_ClientFromEarliestRecord(t *testing.T) {
	older := rec("s", "acme", "coder", true, 0.01, 1, 1, 0, 0, "anthropic", "claude-sonnet-5",
		&OrchestrationContext{AgentID: "generator", Client: "claude-code", SessionSource: "client_asserted"})
	older.Timestamp = ts(1)
	newer := rec("s", "acme", "coder", true, 0.01, 1, 1, 0, 0, "openai", "gpt-5.3-codex",
		&OrchestrationContext{AgentID: "executor", Client: "codex", SessionSource: "vendor_asserted"})
	newer.Timestamp = ts(30)

	// Newest-first input (the ListBySessionID order).
	sum := BuildSessionSummary("s", []*Evidence{newer, older})
	if sum.Client != "claude-code" || sum.SessionSource != "client_asserted" {
		t.Fatalf("client/source = %q/%q, want claude-code/client_asserted (earliest record)", sum.Client, sum.SessionSource)
	}
	// Order-independence: oldest-first gives the same answer.
	sum2 := BuildSessionSummary("s", []*Evidence{older, newer})
	if sum2.Client != sum.Client || sum2.SessionSource != sum.SessionSource {
		t.Fatalf("client selection must be input-order independent")
	}
}

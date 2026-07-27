package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	talonsession "github.com/dativo-io/talon/internal/session"
)

const sessTestSigningKey = "test-signing-key-1234567890123456"

// sessionTestEnv points config.Load at a temp data dir and resets the
// package-level session flags (cobra flag values persist across Execute calls
// within one test binary).
func sessionTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", sessTestSigningKey)
	sessTenant, sessStatus, sessListJSON = "default", "", false
	sessShowTenant, sessShowJSON = "", false
	return dir
}

func sessionTestStores(t *testing.T, dir string) (sessions *talonsession.Store, ev *evidence.Store) {
	t.Helper()
	dbPath := filepath.Join(dir, "evidence.db")
	sessions, err := talonsession.NewStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessions.Close() })
	ev, err = evidence.NewStore(dbPath, sessTestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ev.Close() })
	return sessions, ev
}

func runSessionCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return buf.String(), err
}

// seedOperationalSession stores the #271 acceptance fixture under external
// session id ext-sess-1: a served request, a failed failover attempt, a
// fallback-served request, a budget denial, and a blocked MCP tool call.
func seedOperationalSession(t *testing.T, evStore *evidence.Store) {
	t.Helper()
	ctx := context.Background()
	base := time.Now().UTC().Add(-10 * time.Minute)
	put := func(id string, ev *evidence.Evidence) {
		ev.ID = id
		ev.CorrelationID = "corr_" + id
		ev.SessionID = "ext-sess-1"
		ev.TenantID = "default"
		ev.AgentID = "support-bot"
		require.NoError(t, evStore.Store(ctx, ev))
	}
	put("e_served", &evidence.Evidence{
		Timestamp:       base,
		InvocationType:  "gateway",
		PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
		RoutingDecision: &evidence.RoutingDecision{SelectedProvider: "anthropic"},
		ToolGovernance: &evidence.ToolGovernance{
			ToolsRequested: []string{"delete_record", "search"},
			ToolsFiltered:  []string{"delete_record"},
			ToolsForwarded: []string{"search"},
		},
		Classification: evidence.Classification{PIIRedacted: true, PIIDetected: []string{"EMAIL"}},
		Execution: evidence.Execution{
			ModelUsed: "claude-sonnet-5", Cost: 0.10, Currency: "EUR",
			Tokens: evidence.TokenUsage{Input: 1000, Output: 200},
		},
	})
	put("e_attempt", &evidence.Evidence{
		Timestamp:      base.Add(1 * time.Minute),
		InvocationType: "gateway_failover_attempt",
		Status:         "failed",
		FailureReason:  evidence.FailureReasonProviderTransient,
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution:      evidence.Execution{ModelUsed: "claude-sonnet-5", Error: "upstream status 529"},
		Failover:       &evidence.FailoverContext{Role: evidence.FailoverRoleFailedAttempt, Provider: "anthropic", Model: "claude-sonnet-5"},
	})
	put("e_fallback", &evidence.Evidence{
		Timestamp:      base.Add(2 * time.Minute),
		InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution: evidence.Execution{
			ModelUsed: "gpt-5", Cost: 0.08, Currency: "EUR",
			Tokens: evidence.TokenUsage{Input: 800, Output: 150},
		},
		Failover: &evidence.FailoverContext{Role: evidence.FailoverRoleFallbackDecision, Provider: "openai", Model: "gpt-5"},
	})
	put("e_denied", &evidence.Evidence{
		Timestamp:      base.Add(3 * time.Minute),
		InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: false, Action: "deny",
			Reasons: []string{"session_budget_exceeded: estimated cost exceeds remaining session budget"},
		},
	})
	put("e_toolblocked", &evidence.Evidence{
		Timestamp:      base.Add(90 * time.Second),
		InvocationType: "proxy_tool_blocked",
		PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"mcp_tool_denied: delete_record"}},
		Execution:      evidence.Execution{ToolsCalled: []string{"delete_record"}, Error: "mcp_tool_denied: delete_record"},
	})
}

// The mandatory #271 screen: a session with a fallback and a denial shows
// both, with counts and the provider path, plus interventions, tool calls,
// and a failure explanation — via the external id or the internal id.
func TestSessionShow_OperationalSummary(t *testing.T) {
	dir := sessionTestEnv(t)
	sessStore, evStore := sessionTestStores(t, dir)
	sess, err := sessStore.GetOrCreateExternal(context.Background(), "default", "support-bot", "ext-sess-1", talonsession.SourceClientAsserted)
	require.NoError(t, err)
	seedOperationalSession(t, evStore)

	for _, id := range []string{"ext-sess-1", sess.ID} {
		out, err := runSessionCmd(t, "session", "show", id)
		require.NoError(t, err, "show %s", id)
		assert.Contains(t, out, "Status:    active", "store row status must render")
		assert.Contains(t, out, "Asserted:  client_asserted")
		assert.Contains(t, out, "Requests:  3 LLM · 1 tool calls · 5 records")
		assert.Contains(t, out, "failed attempts 1")
		assert.Contains(t, out, "fallbacks 1")
		assert.Contains(t, out, "Path:      anthropic/claude-sonnet-5 → openai/gpt-5")
		assert.Contains(t, out, "mcp_tool_denied ×1")
		assert.Contains(t, out, "session_budget_exceeded ×1")
		assert.Contains(t, out, "PII redacted ×1 (EMAIL)")
		assert.Contains(t, out, "tools filtered ×1 (delete_record)")
		assert.Contains(t, out, "Tool calls: 1 intercepted (0 allowed, 1 denied) — delete_record")
		assert.Contains(t, out, "Failure:   ", "failed session must carry a one-line explanation")
		assert.Contains(t, out, "session_budget_exceeded: estimated cost exceeds remaining session budget")
	}
}

// --json must be the same structure the dashboard drill-down serves: the
// summary equals evidence.BuildSessionSummary over the session's records
// (shared code path — the parity contract of #271).
func TestSessionShow_JSONMatchesSharedProjection(t *testing.T) {
	dir := sessionTestEnv(t)
	sessStore, evStore := sessionTestStores(t, dir)
	_, err := sessStore.GetOrCreateExternal(context.Background(), "default", "support-bot", "ext-sess-1", talonsession.SourceClientAsserted)
	require.NoError(t, err)
	seedOperationalSession(t, evStore)

	out, err := runSessionCmd(t, "session", "show", "ext-sess-1", "--json")
	require.NoError(t, err)
	var got struct {
		Session *talonsession.Session   `json:"session"`
		Summary evidence.SessionSummary `json:"summary"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.NotNil(t, got.Session)
	assert.Equal(t, "ext-sess-1", got.Session.ExternalSessionID)

	records, err := evStore.ListBySessionID(context.Background(), "ext-sess-1")
	require.NoError(t, err)
	want := evidence.BuildSessionSummary("ext-sess-1", records)
	assert.Equal(t, want.Requests, got.Summary.Requests)
	assert.Equal(t, want.Fallbacks, got.Summary.Fallbacks)
	assert.Equal(t, want.FailedAttempts, got.Summary.FailedAttempts)
	assert.Equal(t, want.DeniedByReason, got.Summary.DeniedByReason)
	assert.Equal(t, want.ProviderPath, got.Summary.ProviderPath)
	assert.Equal(t, want.ToolCalls, got.Summary.ToolCalls)
	assert.Equal(t, want.PIITypes, got.Summary.PIITypes)
	assert.InDelta(t, want.TotalCost, got.Summary.TotalCost, 1e-9)
	require.NotNil(t, got.Summary.LastFailure)
	assert.Equal(t, want.LastFailure.Code, got.Summary.LastFailure.Code)
}

// A session asserted only on a path that creates no session row (e.g. MCP
// proxy) still gets a summary, stated as evidence-only — never a fake row.
func TestSessionShow_EvidenceOnlySession(t *testing.T) {
	dir := sessionTestEnv(t)
	_, evStore := sessionTestStores(t, dir)
	require.NoError(t, evStore.Store(context.Background(), &evidence.Evidence{
		ID: "e_only", CorrelationID: "corr_e_only", SessionID: "proxy-sess-9",
		Timestamp: time.Now().UTC(), TenantID: "default", AgentID: "support-bot",
		InvocationType: "proxy_tool_call",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution:      evidence.Execution{ToolsCalled: []string{"search_kb"}},
	}))

	out, err := runSessionCmd(t, "session", "show", "proxy-sess-9")
	require.NoError(t, err)
	assert.Contains(t, out, "(no session row — observed in evidence only)")
	assert.Contains(t, out, "Tool calls: 1 intercepted (1 allowed) — search_kb")
}

func TestSessionShow_UnknownIDFails(t *testing.T) {
	dir := sessionTestEnv(t)
	sessionTestStores(t, dir)
	_, err := runSessionCmd(t, "session", "show", "no-such-session")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// Two agents asserting the same external id are separate sessions (#198
// tuple); showing that external id must surface the ambiguity, not silently
// pick one.
func TestSessionShow_AmbiguousExternalID(t *testing.T) {
	dir := sessionTestEnv(t)
	sessStore, _ := sessionTestStores(t, dir)
	ctx := context.Background()
	_, err := sessStore.GetOrCreateExternal(ctx, "default", "agent-a", "shared-ext", talonsession.SourceClientAsserted)
	require.NoError(t, err)
	_, err = sessStore.GetOrCreateExternal(ctx, "default", "agent-b", "shared-ext", talonsession.SourceClientAsserted)
	require.NoError(t, err)

	out, err := runSessionCmd(t, "session", "show", "shared-ext")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matches 2 sessions")
	assert.Contains(t, out, "agent-a")
	assert.Contains(t, out, "agent-b")
}

// `session list` shows the asserted external id and source, and synthetic
// request-level ids never appear: they have no session rows by design (#271
// boundary) — only evidence correlation.
func TestSessionList_SourcesShownSyntheticExcluded(t *testing.T) {
	dir := sessionTestEnv(t)
	sessStore, evStore := sessionTestStores(t, dir)
	ctx := context.Background()
	_, err := sessStore.GetOrCreateExternal(ctx, "default", "support-bot", "ext-sess-1", talonsession.SourceClientAsserted)
	require.NoError(t, err)
	// Synthetic request-level id: evidence only, no session row.
	require.NoError(t, evStore.Store(ctx, &evidence.Evidence{
		ID: "e_syn", CorrelationID: "corr_e_syn", SessionID: "sess_gw_synthetic99",
		Timestamp: time.Now().UTC(), TenantID: "default", AgentID: "support-bot",
		InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
	}))

	out, err := runSessionCmd(t, "session", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "SOURCE")
	assert.Contains(t, out, "ext-sess-1")
	assert.Contains(t, out, "client_asserted")
	assert.NotContains(t, out, "sess_gw_synthetic99", "synthetic ids must not be presented as sessions")

	jsonOut, err := runSessionCmd(t, "session", "list", "--json")
	require.NoError(t, err)
	var rows []*talonsession.Session
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &rows))
	require.Len(t, rows, 1)
	assert.Equal(t, "ext-sess-1", rows[0].ExternalSessionID)
}

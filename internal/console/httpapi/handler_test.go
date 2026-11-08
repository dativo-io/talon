package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/session"
)

const key = "httpapi-test-signing-key-000000001"

// newServer seeds one agent on disk and three records (two in session
// hr-demo-s1, one denied), then serves the router over read-only stores.
func newServer(t *testing.T) (*httptest.Server, *evidence.Store, time.Time) {
	t.Helper()
	dir := t.TempDir()
	d := filepath.Join(dir, "agents", "hr-analytics-assistant")
	require.NoError(t, os.MkdirAll(d, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte("agent:\n  name: hr-analytics-assistant\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 10\n"), 0o600))
	dbPath := filepath.Join(dir, "evidence.db")
	writer, err := evidence.NewStore(dbPath, key)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })
	sw, err := session.NewStore(dbPath)
	require.NoError(t, err)
	require.NoError(t, sw.Close())

	now := time.Now().UTC()
	if now.Sub(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)) < 30*time.Minute {
		t.Skip("fixture places records up to 20 minutes ago inside today's UTC day")
	}
	ctx := context.Background()
	put := func(id, typ, sess string, allowed bool, cost float64, minutesAgo int) {
		require.NoError(t, writer.Store(ctx, &evidence.Evidence{
			ID: id, CorrelationID: "corr_" + id, TenantID: "default", AgentID: "hr-analytics-assistant", SessionID: sess, InvocationType: typ,
			Timestamp:      now.Add(-time.Duration(minutesAgo) * time.Minute),
			PolicyDecision: evidence.PolicyDecision{Allowed: allowed, Action: map[bool]string{true: "allow", false: "deny"}[allowed]},
			Execution:      evidence.Execution{Cost: cost, Currency: "USD"},
		}))
	}
	put("e_agg", "proxy_tool_call", "hr-demo-s1", true, 0, 20)
	put("e_export", "proxy_tool_blocked", "hr-demo-s1", false, 0, 15)
	put("e_llm", "gateway", "", true, 0.30, 10)

	ro, err := evidence.OpenReadOnly(dbPath, key)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ro.Close() })
	ss, err := session.OpenReadOnly(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	fleetSrc := console.OfflineFleetSource(filepath.Join(dir, "agents"), "", "", "USD", ro, ss, nil)
	svc, err := console.New(console.Config{Evidence: ro, Sessions: ss, StorePath: dbPath, Currency: "USD", Fleet: fleetSrc, Budgets: console.FleetCapsBudgets{Fleet: fleetSrc}, Version: "test"})
	require.NoError(t, err)
	srv := httptest.NewServer(Handler(svc))
	t.Cleanup(srv.Close)
	return srv, writer, now
}

func get(t *testing.T, srv *httptest.Server, path string, out interface{}) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	if out != nil {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
	}
	return resp.StatusCode
}

func TestRoutes_ServeTheDTOs(t *testing.T) {
	srv, writer, now := newServer(t)
	ctx := context.Background()

	var ov console.Overview
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/overview", &ov))
	assert.Equal(t, console.ContractVersion, ov.Meta.ContractVersion)
	require.Len(t, ov.UseCases.Rows, 1)
	assert.Equal(t, 3, ov.UseCases.Rows[0].Requests)
	assert.Equal(t, 1, ov.UseCases.Rows[0].Denied)
	assert.Equal(t, 3, ov.Today.Requests)
	assert.InDelta(t, 0.30, ov.Today.Cost, 1e-9)
	assert.Len(t, ov.RecentEvents.Events, 3)
	assert.Equal(t, console.StateUnknown, ov.UseCases.Runtime.Availability.State)

	var uc console.UseCaseDetail
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/use-cases/hr-analytics-assistant", &uc))
	require.NotNil(t, uc.Row)
	require.NotNil(t, uc.Costs.Report)
	assert.InDelta(t, 0.30, uc.Costs.Report.TodayEUR, 1e-9)
	require.NotNil(t, uc.Costs.Report.DailyBudget)
	assert.InDelta(t, 3, uc.Costs.Report.DailyBudget.Percent, 1e-9)
	assert.Equal(t, console.StateUnknown, uc.EffectivePolicy.State)

	var sd console.SessionDetail
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/sessions/hr-demo-s1", &sd))
	require.NotNil(t, sd.Timeline)
	assert.Len(t, sd.Timeline.Records, 2)
	assert.Equal(t, 1, sd.Detail.Summary.ToolCallsDenied)

	var ed console.EvidenceDetail
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/evidence/e_export?tenant=default", &ed))
	assert.Equal(t, "valid", ed.Detail.Verification.State)
	assert.False(t, ed.Detail.Record.PolicyDecision.Allowed)

	var c console.Costs
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/costs?tenant=default&breakdown=model", &c))
	require.NotNil(t, c.Report)
	assert.Equal(t, costs.Breakdown("model"), costs.BreakdownModel)
	assert.InDelta(t, 0.30, c.Report.TodayEUR, 1e-9)
	want, err := costs.Build(ctx, writer, costs.Scope{TenantID: "default", Breakdown: costs.BreakdownModel}, costs.WindowAt(now), "USD", nil)
	require.NoError(t, err)
	assert.Equal(t, len(want.ByModelEUR), len(c.Report.ByModelEUR), "same shared builder")

	var a console.Activity
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/activity?tenant=default&bucket=5m&from="+now.Add(-30*time.Minute).Format(time.RFC3339)+"&to="+now.Format(time.RFC3339), &a))
	require.NotNil(t, a.Series)
	assert.Equal(t, "5m", a.Series.Bucket)
	var reqs int
	for _, b := range a.Series.Buckets {
		reqs += b.Requests
	}
	assert.Equal(t, 3, reqs)

	var sys console.System
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/system", &sys))
	assert.True(t, sys.Store.ReadOnly)
	assert.Equal(t, 3, sys.Store.RecordCount)

	var sl console.SessionList
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/sessions?tenant=default&limit=5", &sl))
	assert.Equal(t, console.StateEmpty, sl.Availability.State, "no session-store rows")
	require.Len(t, sl.Observed, 1, "the evidence-only session is discoverable")
	assert.Equal(t, "hr-demo-s1", sl.Observed[0].SessionID)
	assert.Equal(t, "evidence", sl.Observed[0].Source)
	assert.Equal(t, 2, sl.Observed[0].RecordCount)

	// Timeline paging over HTTP: one record per page, cursor carried in two params.
	var p1 console.SessionDetail
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/sessions/hr-demo-s1?timeline_limit=1", &p1))
	require.Len(t, p1.Timeline.Records, 1)
	assert.Equal(t, 2, p1.Timeline.Total)
	require.NotNil(t, p1.Timeline.NextCursor)
	var p2 console.SessionDetail
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/sessions/hr-demo-s1?timeline_limit=1&timeline_after="+p1.Timeline.NextCursor.Timestamp.Format(time.RFC3339Nano)+"&timeline_after_id="+p1.Timeline.NextCursor.ID, &p2))
	require.Len(t, p2.Timeline.Records, 1)
	assert.NotEqual(t, p1.Timeline.Records[0].ID, p2.Timeline.Records[0].ID)
	assert.Equal(t, 2, p2.Detail.Summary.RecordCount, "the summary is complete on every page")
}

func TestRoutes_StoreFailureIs503NotNotFound(t *testing.T) {
	ro, err := evidence.OpenReadOnly(filepath.Join(t.TempDir(), "missing.db"), key)
	require.Error(t, err)
	_ = ro
	// A service whose evidence store is closed: reads fail, and the handler
	// must say unavailable (503), never not found (404).
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "evidence.db")
	writer, err := evidence.NewStore(dbPath, key)
	require.NoError(t, err)
	require.NoError(t, writer.Store(context.Background(), &evidence.Evidence{ID: "e1", CorrelationID: "c1", TenantID: "default", AgentID: "a", Timestamp: time.Now().UTC(), InvocationType: "gateway"}))
	closed, err := evidence.OpenReadOnly(dbPath, key)
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	svc, err := console.New(console.Config{Evidence: closed, Currency: "USD"})
	require.NoError(t, err)
	srv := httptest.NewServer(Handler(svc))
	defer srv.Close()
	var e map[string]string
	assert.Equal(t, http.StatusServiceUnavailable, get(t, srv, "/console/v1/evidence/e1", &e))
	assert.Equal(t, "unavailable", e["error"])
	require.NoError(t, writer.Close())
}

func TestRoutes_ErrorsAndValidation(t *testing.T) {
	srv, _, _ := newServer(t)
	var e map[string]string
	assert.Equal(t, http.StatusNotFound, get(t, srv, "/console/v1/use-cases/nope", &e))
	assert.Equal(t, "not_found", e["error"])
	assert.Equal(t, http.StatusNotFound, get(t, srv, "/console/v1/sessions/nope", &e))
	assert.Equal(t, http.StatusNotFound, get(t, srv, "/console/v1/evidence/e_export?tenant=acme", &e), "cross-tenant read is not found")
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/costs?breakdown=weekly", &e))
	assert.Equal(t, "invalid_request", e["error"])
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/activity?bucket=7m", &e))
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/activity?from=yesterday", &e))
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/sessions?limit=-1", &e))
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/sessions?before=noon&before_id=x", &e))
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/sessions?before=2026-01-01T00:00:00Z", &e), "a cursor needs both halves")
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/sessions?observed_before=2026-01-01T00:00:00Z&observed_before_id=x", &e), "the observed cursor needs all three parts")
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/sessions/hr-demo-s1?timeline_after_id=x", &e))
	assert.Equal(t, http.StatusBadRequest, get(t, srv, "/console/v1/sessions/hr-demo-s1?timeline_limit=0", &e))

	// Out-of-bound series is reported in the availability block, not as a transport error.
	var a console.Activity
	assert.Equal(t, http.StatusOK, get(t, srv, "/console/v1/activity?bucket=5m&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z", &a))
	assert.Equal(t, console.StateUnavailable, a.Availability.State)
	assert.Contains(t, a.Availability.Error, "exceed the bound")

	// Nothing but GET under the prefix; the data plane's routes do not exist here.
	for _, p := range []string{"/v1/secrets", "/v1/runs", "/api/v1/metrics", "/", "/dashboard"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+p, nil)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, p)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/console/v1/overview", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// TestRoutes_ObservedCursorLosslessAcrossAgents (#535 review round 3): two
// agents share one session id and one last_seen instant; paging the
// observed list one entry at a time over HTTP must visit both.
func TestRoutes_ObservedCursorLosslessAcrossAgents(t *testing.T) {
	srv, writer, now := newServer(t)
	ctx := context.Background()
	at := now.Add(-5 * time.Minute)
	for _, agent := range []string{"agent-a", "agent-b", "agent-c"} {
		require.NoError(t, writer.Store(ctx, &evidence.Evidence{
			ID: "tie-" + agent, CorrelationID: "c", SessionID: "tie-session", TenantID: "default", AgentID: agent, InvocationType: "proxy_tool_call",
			Timestamp: at, PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		}))
	}
	var walked []string
	query := "/console/v1/sessions?tenant=default&limit=1"
	for i := 0; i < 10; i++ {
		var page console.SessionList
		require.Equal(t, http.StatusOK, get(t, srv, query, &page))
		for _, o := range page.Observed {
			walked = append(walked, o.SessionID+"/"+o.AgentID)
		}
		if page.ObservedNextCursor == nil {
			break
		}
		c := page.ObservedNextCursor
		query = "/console/v1/sessions?tenant=default&limit=1&observed_before=" + c.LastSeen.Format(time.RFC3339Nano) + "&observed_before_id=" + c.SessionID + "&observed_before_agent=" + c.AgentID
	}
	assert.ElementsMatch(t, []string{"hr-demo-s1/hr-analytics-assistant", "tie-session/agent-a", "tie-session/agent-b", "tie-session/agent-c"}, walked)
	assert.Len(t, walked, 4, "no entry visited twice")

	// Opening an observed entry with its agent shows that agent's share only; the
	// summary-free timeline route follows the same scope.
	var d console.SessionDetail
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/sessions/tie-session?tenant=default&agent=agent-b", &d))
	assert.Equal(t, 1, d.Detail.Summary.RecordCount)
	assert.Equal(t, []string{"agent-b"}, d.Detail.Summary.AgentIDs)
	var tl console.SessionDetail
	require.Equal(t, http.StatusOK, get(t, srv, "/console/v1/sessions/tie-session/timeline?tenant=default&agent=agent-b&timeline_limit=5", &tl))
	assert.Nil(t, tl.Detail)
	assert.Equal(t, 1, tl.Timeline.Total)
	assert.Equal(t, "agent-b", tl.Timeline.Records[0].AgentID)
	var e map[string]string
	assert.Equal(t, http.StatusNotFound, get(t, srv, "/console/v1/sessions/tie-session/timeline?tenant=default&agent=nobody", &e))
}

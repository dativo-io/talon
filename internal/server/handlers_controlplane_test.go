package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/policy"
)

const testAdminKey = "test-admin-key-12345"

func controlPlaneServer(t *testing.T) (*Server, *agent.RunRegistry, *agent.OverrideStore, *agent.ToolApprovalStore) {
	t.Helper()
	pol := &policy.Policy{
		Agent:      policy.AgentConfig{Name: "test", Version: "1.0"},
		Policies:   policy.PoliciesConfig{},
		VersionTag: "test",
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)

	rr := agent.NewRunRegistry()
	os := agent.NewOverrideStore()
	tas := agent.NewToolApprovalStore(5 * time.Minute)

	srv := NewServer(
		nil, nil, nil, engine, pol, "", nil,
		testAdminKey,
		map[string]string{},
		WithRunRegistry(rr),
		WithOverrideStore(os),
		WithToolApprovalStore(tas),
	)
	return srv, rr, os, tas
}

func adminReq(method, path string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	r.Header.Set("X-Talon-Admin-Key", testAdminKey)
	return r
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	return out
}

// ---- Run management endpoints ----

func TestHandleRunsList_Empty(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/runs", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, float64(0), out["count"])
}

func TestHandleRunsList_WithRuns(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	_, c1 := context.WithCancel(context.Background())
	_, c2 := context.WithCancel(context.Background())
	defer c1()
	defer c2()

	rr.Register("run-1", "acme", "bot-a", "", c1)
	rr.Register("run-2", "acme", "bot-b", "", c2)
	rr.SetStatus("run-1", agent.RunStatusRunning, agent.FailureNone)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/runs", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, float64(2), out["count"])
}

func TestHandleRunsList_TenantFilter(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	_, c1 := context.WithCancel(context.Background())
	_, c2 := context.WithCancel(context.Background())
	defer c1()
	defer c2()

	rr.Register("run-1", "acme", "bot", "", c1)
	rr.Register("run-2", "globex", "bot", "", c2)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/runs?tenant_id=acme", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, float64(1), out["count"])
}

func TestHandleRunGet(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("run-abc", "acme", "bot", "", cancel)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/runs/run-abc", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, "run-abc", out["correlation_id"])
	assert.Equal(t, "queued", out["status"])
}

func TestHandleRunGet_NotFound(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/runs/nonexistent", ""))

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRunKill(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx

	rr.Register("run-kill", "acme", "bot", "", cancel)
	rr.SetStatus("run-kill", agent.RunStatusRunning, agent.FailureNone)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/runs/run-kill/kill", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, "terminated", out["status"])

	rs := rr.Get("run-kill")
	assert.Equal(t, agent.RunStatusTerminated, rs.Status)
}

func TestHandleRunKill_NotFound(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/runs/ghost/kill", ""))

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRunKillAll(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	_, c1 := context.WithCancel(context.Background())
	_, c2 := context.WithCancel(context.Background())

	rr.Register("r1", "acme", "bot", "", c1)
	rr.Register("r2", "acme", "bot", "", c2)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/runs/kill-all?tenant_id=acme", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, float64(2), out["killed"])
}

func TestHandleRunKillAll_MissingTenant(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/runs/kill-all", ""))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleRunPause(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("run-pause", "acme", "bot", "", cancel)
	rr.SetStatus("run-pause", agent.RunStatusRunning, agent.FailureNone)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/runs/run-pause/pause", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, "paused", out["status"])
	assert.True(t, rr.IsPaused("run-pause"))
}

func TestHandleRunPause_NotRunning(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("run-q", "acme", "bot", "", cancel)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/runs/run-q/pause", ""))

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRunResume(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("run-r", "acme", "bot", "", cancel)
	rr.SetStatus("run-r", agent.RunStatusRunning, agent.FailureNone)
	rr.Pause("run-r")

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/runs/run-r/resume", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, "running", out["status"])
	assert.False(t, rr.IsPaused("run-r"))
}

func TestHandleRunResume_NotPaused(t *testing.T) {
	srv, rr, _, _ := controlPlaneServer(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	rr.Register("run-np", "acme", "bot", "", cancel)
	rr.SetStatus("run-np", agent.RunStatusRunning, agent.FailureNone)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/runs/run-np/resume", ""))

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---- Override endpoints ----

func TestHandleOverridesList_Empty(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/overrides", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleOverrideGet_NoOverrides(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/overrides/acme", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, "no overrides", out["status"])
}

func TestHandleTenantLockdown(t *testing.T) {
	srv, rr, os, _ := controlPlaneServer(t)
	_, c1 := context.WithCancel(context.Background())
	rr.Register("r1", "acme", "bot", "", c1)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/overrides/acme/lockdown", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, true, out["lockdown"])
	assert.True(t, os.IsLocked("acme"))

	rs := rr.Get("r1")
	assert.Equal(t, agent.RunStatusTerminated, rs.Status, "active runs should be killed on lockdown")
}

func TestHandleTenantUnlock(t *testing.T) {
	srv, _, os, _ := controlPlaneServer(t)
	os.SetLockdown("acme", true, "test")

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodDelete, "/v1/overrides/acme/lockdown", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.False(t, os.IsLocked("acme"))
}

func TestHandleToolsDisable(t *testing.T) {
	srv, _, os, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/overrides/acme/tools/disable",
		`{"tools":["send_email","delete_all"],"reason":"INC-042"}`))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.ElementsMatch(t, []string{"send_email", "delete_all"}, os.DisabledToolsFor("acme"))
}

func TestHandleToolsDisable_EmptyTools(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/overrides/acme/tools/disable",
		`{"tools":[]}`))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleToolsEnable(t *testing.T) {
	srv, _, os, _ := controlPlaneServer(t)
	os.DisableTools("acme", []string{"a", "b", "c"}, "test")

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/overrides/acme/tools/enable",
		`{"tools":["b"]}`))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.ElementsMatch(t, []string{"a", "c"}, os.DisabledToolsFor("acme"))
}

func TestHandlePolicyOverride(t *testing.T) {
	srv, _, os, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/overrides/acme/policy",
		`{"max_cost_per_run":0.10,"max_tool_calls":5}`))

	assert.Equal(t, http.StatusOK, rec.Code)
	ov := os.Get("acme")
	require.NotNil(t, ov)
	require.NotNil(t, ov.MaxCostPerRun)
	assert.InDelta(t, 0.10, *ov.MaxCostPerRun, 1e-9)
	require.NotNil(t, ov.MaxToolCalls)
	assert.Equal(t, 5, *ov.MaxToolCalls)
}

func TestHandleOverrideClear(t *testing.T) {
	srv, _, os, _ := controlPlaneServer(t)
	os.SetLockdown("acme", true, "test")
	os.DisableTools("acme", []string{"tool_a"}, "test")

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodDelete, "/v1/overrides/acme", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, os.Get("acme"))
}

// ---- Tool approval endpoints ----

func TestHandleToolApprovalsList_Empty(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/tool-approvals", ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, float64(0), out["count"])
}

func TestHandleToolApprovalDecide_Approve(t *testing.T) {
	srv, _, _, tas := controlPlaneServer(t)
	ctx := context.Background()

	go func() {
		tas.RequestApproval(ctx, "req_appv1234", "acme", "bot", "send_email", "call_x", nil)
	}()

	require.Eventually(t, func() bool {
		return len(tas.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	pending := tas.ListPending()
	reqID := pending[0].ID

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/tool-approvals/"+reqID+"/decide",
		`{"decision":"approve","reason":"verified"}`))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, "approved", out["status"])
}

func TestHandleToolApprovalDecide_Deny(t *testing.T) {
	srv, _, _, tas := controlPlaneServer(t)
	ctx := context.Background()

	go func() {
		tas.RequestApproval(ctx, "req_deny1234", "acme", "bot", "delete_all", "call_y", nil)
	}()

	require.Eventually(t, func() bool {
		return len(tas.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	pending := tas.ListPending()
	reqID := pending[0].ID

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/tool-approvals/"+reqID+"/decide",
		`{"decision":"deny","reason":"too dangerous"}`))

	assert.Equal(t, http.StatusOK, rec.Code)
	out := decodeJSON(t, rec)
	assert.Equal(t, "denied", out["status"])
}

func TestHandleToolApprovalDecide_InvalidDecision(t *testing.T) {
	srv, _, _, tas := controlPlaneServer(t)
	ctx := context.Background()

	go func() {
		tas.RequestApproval(ctx, "req_invl1234", "acme", "bot", "tool_z", "call_z", nil)
	}()

	require.Eventually(t, func() bool {
		return len(tas.ListPending()) > 0
	}, 2*time.Second, 10*time.Millisecond)

	reqID := tas.ListPending()[0].ID

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodPost, "/v1/tool-approvals/"+reqID+"/decide",
		`{"decision":"maybe"}`))

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Cleanup: approve to unblock
	tas.Approve(reqID, "test", "")
}

func TestHandleToolApprovalGet_NotFound(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, adminReq(http.MethodGet, "/v1/tool-approvals/nonexistent", ""))

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---- Auth enforcement ----

func TestControlPlaneEndpoints_RequireAdminKey(t *testing.T) {
	srv, _, _, _ := controlPlaneServer(t)
	r := srv.Routes()

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/runs"},
		{http.MethodGet, "/v1/runs/some-id"},
		{http.MethodPost, "/v1/runs/some-id/kill"},
		{http.MethodPost, "/v1/runs/kill-all?tenant_id=x"},
		{http.MethodPost, "/v1/runs/some-id/pause"},
		{http.MethodPost, "/v1/runs/some-id/resume"},
		{http.MethodGet, "/v1/overrides"},
		{http.MethodGet, "/v1/overrides/acme"},
		{http.MethodPost, "/v1/overrides/acme/lockdown"},
		{http.MethodPost, "/v1/overrides/acme/tools/disable"},
		{http.MethodPost, "/v1/overrides/acme/tools/enable"},
		{http.MethodPost, "/v1/overrides/acme/policy"},
		{http.MethodGet, "/v1/tool-approvals"},
		{http.MethodGet, "/v1/tool-approvals/some-id"},
		{http.MethodPost, "/v1/tool-approvals/some-id/decide"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), ep.method, ep.path, nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "endpoint %s %s should require admin key", ep.method, ep.path)
		})
	}
}

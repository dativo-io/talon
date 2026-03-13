package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/metrics"
)

func newTestServerWithDashboard(t *testing.T, token string) (*Server, *metrics.Collector) {
	t.Helper()
	collector := metrics.NewCollector("enforce", nil)
	t.Cleanup(collector.Close)

	s := &Server{
		metricsCollector:     collector,
		gatewayDashboardHTML: "<html>test dashboard</html>",
		adminKey:             token,
		tenantKeys:           map[string]string{},
	}
	return s, collector
}

func newTestRequest(method, target string) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), method, target, nil)
}

func TestHandleGatewayDashboard(t *testing.T) {
	s, _ := newTestServerWithDashboard(t, "")
	req := newTestRequest("GET", "/gateway/dashboard")
	rec := httptest.NewRecorder()

	s.handleGatewayDashboard(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "test dashboard")
}

func TestHandleMetricsJSON(t *testing.T) {
	s, collector := newTestServerWithDashboard(t, "")
	collector.Record(metrics.GatewayEvent{
		Timestamp: time.Now(),
		CallerID:  "app-1",
		CostEUR:   0.05,
		LatencyMS: 100,
	})
	time.Sleep(50 * time.Millisecond)

	req := newTestRequest("GET", "/api/v1/metrics")
	rec := httptest.NewRecorder()

	s.handleMetricsJSON(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

	var snap metrics.Snapshot
	err := json.Unmarshal(rec.Body.Bytes(), &snap)
	require.NoError(t, err)
	assert.Equal(t, 1, snap.Summary.TotalRequests)
	assert.Equal(t, "enforce", snap.EnforcementMode)
}

func TestHandleMetricsJSON_FullSnapshot(t *testing.T) {
	s, collector := newTestServerWithDashboard(t, "")

	now := time.Now()
	collector.Record(metrics.GatewayEvent{
		Timestamp:      now,
		CallerID:       "sales-app",
		Model:          "gpt-4o",
		CostEUR:        0.10,
		LatencyMS:      200,
		TokensInput:    500,
		TokensOutput:   200,
		PIIDetected:    []string{"email", "iban"},
		PIIAction:      "redact",
		ToolsRequested: []string{"read_file", "exec_cmd"},
		ToolsFiltered:  []string{"exec_cmd"},
	})
	collector.Record(metrics.GatewayEvent{
		Timestamp: now.Add(1 * time.Second),
		CallerID:  "hr-app",
		Model:     "claude-3",
		CostEUR:   0.05,
		LatencyMS: 100,
		Blocked:   true,
		HasError:  true,
	})
	time.Sleep(80 * time.Millisecond)

	req := newTestRequest("GET", "/api/v1/metrics")
	rec := httptest.NewRecorder()
	s.handleMetricsJSON(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var snap metrics.Snapshot
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &snap))

	// Summary KPIs
	assert.Equal(t, 2, snap.Summary.TotalRequests)
	assert.Equal(t, 1, snap.Summary.BlockedRequests)
	assert.Equal(t, 2, snap.Summary.PIIDetections)
	assert.Equal(t, 2, snap.Summary.PIIRedactions)
	assert.Equal(t, 1, snap.Summary.ToolsFiltered)
	assert.InDelta(t, 0.15, snap.Summary.TotalCostEUR, 0.001)
	assert.Equal(t, int64(150), snap.Summary.AvgLatencyMS)
	assert.InDelta(t, 0.5, snap.Summary.ErrorRate, 0.01)

	// Caller stats sorted by request count (1 each, deterministic order by sort)
	require.Len(t, snap.CallerStats, 2)
	callerMap := map[string]metrics.CallerStat{}
	for _, cs := range snap.CallerStats {
		callerMap[cs.Caller] = cs
	}
	assert.Equal(t, 1, callerMap["sales-app"].Requests)
	assert.InDelta(t, 0.10, callerMap["sales-app"].CostEUR, 0.001)
	assert.Equal(t, 2, callerMap["sales-app"].PIIDetected)
	assert.Equal(t, 1, callerMap["hr-app"].Blocked)

	// PII breakdown
	require.GreaterOrEqual(t, len(snap.PIIBreakdown), 2)
	piiMap := map[string]int{}
	for _, p := range snap.PIIBreakdown {
		piiMap[p.Type] = p.Count
	}
	assert.Equal(t, 1, piiMap["email"])
	assert.Equal(t, 1, piiMap["iban"])

	// Tool governance
	assert.Equal(t, 2, snap.ToolGovernance.TotalRequested)
	assert.Equal(t, 1, snap.ToolGovernance.TotalFiltered)
	require.Len(t, snap.ToolGovernance.TopFiltered, 1)
	assert.Equal(t, "exec_cmd", snap.ToolGovernance.TopFiltered[0].Tool)

	// Timelines (at least 1 bucket)
	require.NotEmpty(t, snap.RequestsTimeline)
	require.NotEmpty(t, snap.PIITimeline)
	require.NotEmpty(t, snap.CostTimeline)

	// Uptime and time
	assert.NotEmpty(t, snap.Uptime)
	assert.False(t, snap.GeneratedAt.IsZero())

	// Shadow summary nil in enforce mode
	assert.Nil(t, snap.ShadowSummary)
}

func TestHandleMetricsJSON_IncludesPlanStats(t *testing.T) {
	collector := metrics.NewCollector("enforce", nil, metrics.WithPlanStatsFn(func(_ context.Context, _ string) (metrics.PlanStats, error) {
		return metrics.PlanStats{
			Pending:          3,
			Approved:         7,
			Rejected:         1,
			Modified:         2,
			Dispatched:       5,
			DispatchFailures: 1,
		}, nil
	}))
	t.Cleanup(collector.Close)

	s := &Server{
		metricsCollector:     collector,
		gatewayDashboardHTML: "<html>test dashboard</html>",
		tenantKeys:           map[string]string{},
	}

	req := newTestRequest("GET", "/api/v1/metrics")
	rec := httptest.NewRecorder()
	s.handleMetricsJSON(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var snap metrics.Snapshot
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &snap))
	require.NotNil(t, snap.PlanStats)
	assert.Equal(t, 3, snap.PlanStats.Pending)
	assert.Equal(t, 7, snap.PlanStats.Approved)
	assert.Equal(t, 1, snap.PlanStats.Rejected)
	assert.Equal(t, 2, snap.PlanStats.Modified)
	assert.Equal(t, 5, snap.PlanStats.Dispatched)
	assert.Equal(t, 1, snap.PlanStats.DispatchFailures)
	assert.Equal(t, 3, snap.Summary.PendingPlans)
	assert.Equal(t, 5, snap.Summary.DispatchedPlans)
}

// TestHandleMetricsJSON_MetricsCrossChecks sends ~20 events through the collector,
// fetches /api/v1/metrics, and asserts cross-checks between summary and breakdowns
// (same invariants as unit TestSnapshotCrossChecks and smoke test section 23).
func TestHandleMetricsJSON_MetricsCrossChecks(t *testing.T) {
	s, collector := newTestServerWithDashboard(t, "")

	now := time.Now()
	// 20 events: 12 caller "app-a", 8 caller "app-b"; 2 blocked, 4 errors; mixed PII and cost
	for i := 0; i < 12; i++ {
		collector.Record(metrics.GatewayEvent{
			Timestamp:   now,
			CallerID:    "app-a",
			Model:       "gpt-4o-mini",
			CostEUR:     0.01 * float64(i+1),
			LatencyMS:   int64(50 + i*8),
			Blocked:     i == 0,
			HasError:    i >= 9,
			PIIDetected: []string{},
			PIIAction:   "",
		})
	}
	for i := 0; i < 8; i++ {
		pii := []string{"email"}
		if i >= 3 {
			pii = []string{"email", "iban"}
		}
		collector.Record(metrics.GatewayEvent{
			Timestamp:   now,
			CallerID:    "app-b",
			Model:       "claude-3",
			CostEUR:     0.05,
			LatencyMS:   100,
			Blocked:     i == 1,
			PIIDetected: pii,
			PIIAction:   "redact",
		})
	}
	time.Sleep(80 * time.Millisecond)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/metrics", nil)
	rec := httptest.NewRecorder()
	s.handleMetricsJSON(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var snap metrics.Snapshot
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &snap))

	// Cross-checks: total_requests == sum(caller_stats[].requests)
	var callerRequests, callerBlocked int
	var callerCost float64
	for _, cs := range snap.CallerStats {
		callerRequests += cs.Requests
		callerBlocked += cs.Blocked
		callerCost += cs.CostEUR
	}
	assert.Equal(t, snap.Summary.TotalRequests, callerRequests,
		"total_requests must equal sum of caller_stats[].requests")
	assert.Equal(t, snap.Summary.BlockedRequests, callerBlocked,
		"blocked_requests must equal sum of caller_stats[].blocked")
	assert.InDelta(t, snap.Summary.TotalCostEUR, callerCost, 0.0001,
		"total_cost_eur must equal sum of caller_stats[].cost_eur")

	// pii_detections == sum(pii_breakdown[].count)
	var piiSum int
	for _, p := range snap.PIIBreakdown {
		piiSum += p.Count
	}
	assert.Equal(t, snap.Summary.PIIDetections, piiSum,
		"pii_detections must equal sum of pii_breakdown[].count")
	assert.LessOrEqual(t, snap.Summary.PIIRedactions, snap.Summary.PIIDetections,
		"pii_redactions must be <= pii_detections")

	// Bounds
	assert.LessOrEqual(t, snap.Summary.BlockedRequests, snap.Summary.TotalRequests,
		"blocked_requests must be <= total_requests")
	assert.GreaterOrEqual(t, snap.Summary.ErrorRate, 0.0, "error_rate must be >= 0")
	assert.LessOrEqual(t, snap.Summary.ErrorRate, 1.0, "error_rate must be <= 1")

	// We sent 20 requests
	assert.Equal(t, 20, snap.Summary.TotalRequests)
	assert.Equal(t, 2, snap.Summary.BlockedRequests)
}

func TestHandleMetricsStreamSSE(t *testing.T) {
	s, _ := newTestServerWithDashboard(t, "")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, "GET", "/api/v1/metrics/stream", nil)
	rec := httptest.NewRecorder()

	s.handleMetricsStream(rec, req)

	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
	assert.Contains(t, rec.Body.String(), "data: ")
}

func TestAdminKeyMiddleware_NoKeyRequired(t *testing.T) {
	mw := AdminKeyMiddleware("")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAdminKeyMiddleware_ValidAdminHeader(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/")
	req.Header.Set("X-Talon-Admin-Key", "s3cr3t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAdminKeyMiddleware_ValidSessionCookie(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/gateway/dashboard")
	req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "s3cr3t"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAdminKeyMiddleware_SetsSessionCookieOnHeaderAuth(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/")
	req.Header.Set("X-Talon-Admin-Key", "s3cr3t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == adminSessionCookieName {
			found = true
			assert.Equal(t, "s3cr3t", c.Value)
			assert.True(t, c.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
			assert.Equal(t, "/", c.Path)
		}
	}
	assert.True(t, found, "expected admin session cookie to be set")
}

func TestAdminKeyMiddleware_BearerFallback(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/")
	req.Header.Set("Authorization", "Bearer s3cr3t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAdminKeyMiddleware_InvalidKey(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/")
	req.Header.Set("X-Talon-Admin-Key", "wrong")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAdminKeyMiddleware_ValidTalonAdminKeyQueryParam(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/gateway/dashboard?talon_admin_key=s3cr3t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAdminKeyMiddleware_InvalidTalonAdminKeyQueryParam(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/gateway/dashboard?talon_admin_key=wrong")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAdminKeyMiddleware_ValidLegacyTokenQueryParam(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/gateway/dashboard?token=s3cr3t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAdminKeyMiddleware_TalonAdminKeyQueryParamIgnoredForPost(t *testing.T) {
	mw := AdminKeyMiddleware("s3cr3t")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("POST", "/api/v1/something?talon_admin_key=s3cr3t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// POST must not use query param for auth (avoid leaking key in logs)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestTenantOrAdminMiddleware_AllowsTenantBearer(t *testing.T) {
	mw := TenantOrAdminMiddleware(map[string]string{"tenant-key-1": "tenant-default"}, "admin-secret")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/api/v1/metrics")
	req.Header.Set("Authorization", "Bearer tenant-key-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTenantOrAdminMiddleware_AllowsAdminKey(t *testing.T) {
	mw := TenantOrAdminMiddleware(map[string]string{"tenant-key-1": "tenant-default"}, "admin-secret")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/api/v1/metrics")
	req.Header.Set("X-Talon-Admin-Key", "admin-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTenantOrAdminMiddleware_SetsSessionCookieForAdmin(t *testing.T) {
	mw := TenantOrAdminMiddleware(map[string]string{"tenant-key-1": "tenant-default"}, "admin-secret")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/api/v1/metrics")
	req.Header.Set("X-Talon-Admin-Key", "admin-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == adminSessionCookieName {
			found = true
			break
		}
	}
	assert.True(t, found, "expected admin session cookie to be set")
}

func TestTenantOrAdminMiddleware_RejectsMissingAuth(t *testing.T) {
	mw := TenantOrAdminMiddleware(map[string]string{"tenant-key-1": "tenant-default"}, "admin-secret")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := newTestRequest("GET", "/api/v1/metrics")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

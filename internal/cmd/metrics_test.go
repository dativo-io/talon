package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	metricsapi "github.com/dativo-io/talon/internal/metrics"
)

func newMetricsTestServer(t *testing.T, snap metricsapi.Snapshot) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	}))
}

func TestMetricsCommand_DefaultOutput(t *testing.T) {
	srv := newMetricsTestServer(t, metricsapi.Snapshot{
		GeneratedAt: time.Now(),
		AgentStats: []metricsapi.AgentStat{
			{Agent: "agent-a", Requests: 3, Successful: 2, Failed: 1, TimedOut: 0, Denied: 0, SuccessRate: 0.66},
		},
	})
	defer srv.Close()

	metricsURL = srv.URL
	metricsAgent = ""
	metricsJSON = false
	var out bytes.Buffer
	metricsCmd.SetOut(&out)
	metricsCmd.SetContext(context.Background())
	err := metricsCmd.RunE(metricsCmd, nil)
	require.NoError(t, err)

	text := out.String()
	assert.Contains(t, text, "AGENT")
	assert.Contains(t, text, "REQUESTS")
	assert.Contains(t, text, "SUCCESS")
	assert.Contains(t, text, "FAILED")
	assert.Contains(t, text, "TIMEOUT")
	assert.Contains(t, text, "DENIED")
}

func TestMetricsCommand_JSONOutput(t *testing.T) {
	srv := newMetricsTestServer(t, metricsapi.Snapshot{
		GeneratedAt: time.Now(),
		AgentStats: []metricsapi.AgentStat{
			{Agent: "agent-a", Requests: 2, SuccessRate: 1.0},
		},
	})
	defer srv.Close()

	metricsURL = srv.URL
	metricsAgent = ""
	metricsJSON = true
	var out bytes.Buffer
	metricsCmd.SetOut(&out)
	metricsCmd.SetContext(context.Background())
	err := metricsCmd.RunE(metricsCmd, nil)
	require.NoError(t, err)

	var callers []metricsapi.AgentStat
	require.NoError(t, json.Unmarshal(out.Bytes(), &callers))
	require.Len(t, callers, 1)
	assert.Equal(t, "agent-a", callers[0].Agent)
}

func TestMetricsCommand_AgentFilter(t *testing.T) {
	srv := newMetricsTestServer(t, metricsapi.Snapshot{
		GeneratedAt: time.Now(),
		Summary:     metricsapi.Summary{P99LatencyMS: 123},
		AgentStats: []metricsapi.AgentStat{
			{Agent: "agent-a", Requests: 2, Successful: 2, SuccessRate: 1.0},
			{Agent: "agent-b", Requests: 1, Successful: 0, Failed: 1},
		},
	})
	defer srv.Close()

	metricsURL = srv.URL
	metricsAgent = "agent-b"
	metricsJSON = false
	var out bytes.Buffer
	metricsCmd.SetOut(&out)
	metricsCmd.SetContext(context.Background())
	err := metricsCmd.RunE(metricsCmd, nil)
	require.NoError(t, err)

	text := out.String()
	assert.Contains(t, text, "Agent Metrics: agent-b")
	assert.NotContains(t, text, "Agent Metrics: agent-a")
}

func TestSparkline_AllZeros(t *testing.T) {
	assert.Equal(t, "▁▁▁▁▁▁▁", sparkline([]int{0, 0, 0, 0, 0, 0, 0}))
}

func TestSparkline_Ascending(t *testing.T) {
	out := sparkline([]int{1, 2, 3, 4, 5, 6, 7})
	assert.Equal(t, 7, len([]rune(out)))
	assert.NotEqual(t, strings.Repeat("▁", 7), out)
}

func TestSparkline_SingleSpike(t *testing.T) {
	out := sparkline([]int{0, 0, 0, 5, 0, 0, 0})
	assert.Equal(t, "▁▁▁█▁▁▁", out)
}

func TestFetchMetricsSnapshot(t *testing.T) {
	srv := newMetricsTestServer(t, metricsapi.Snapshot{
		GeneratedAt: time.Now(),
		AgentStats:  []metricsapi.AgentStat{{Agent: "agent-a"}},
	})
	defer srv.Close()

	snap, offline, err := fetchMetricsSnapshot(context.Background(), srv.URL, true, io.Discard)
	require.NoError(t, err)
	assert.False(t, offline)
	require.Len(t, snap.AgentStats, 1)
	assert.Equal(t, "agent-a", snap.AgentStats[0].Agent)
}

// TestFetchMetricsSnapshot_NoSilentFallback (#535): a reachable server that
// rejects or fails the request is an error; only an unreachable DEFAULT url
// (or an explicit --url "") yields the offline projection, and says so.
func TestFetchMetricsSnapshot_NoSilentFallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", sessTestSigningKey)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		status int
		want   string
	}{
		{"401 names the admin key", http.StatusUnauthorized, "TALON_ADMIN_KEY"},
		{"403 names the admin key", http.StatusForbidden, "TALON_ADMIN_KEY"},
		{"500 is an error", http.StatusInternalServerError, "HTTP 500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status) }))
			defer srv.Close()
			for _, explicit := range []bool{true, false} {
				var warn bytes.Buffer
				_, offline, err := fetchMetricsSnapshot(ctx, srv.URL, explicit, &warn)
				require.Error(t, err, "explicit=%v", explicit)
				assert.Contains(t, err.Error(), tc.want)
				assert.False(t, offline)
				assert.Empty(t, warn.String(), "an error is not also a warning")
			}
		})
	}

	t.Run("garbled body is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
		defer srv.Close()
		_, _, err := fetchMetricsSnapshot(ctx, srv.URL, false, io.Discard)
		require.ErrorContains(t, err, "unexpected /api/v1/metrics response")
	})

	closed := httptest.NewServer(http.NotFoundHandler())
	unreachable := closed.URL
	closed.Close()

	t.Run("unreachable explicit url is an error", func(t *testing.T) {
		_, offline, err := fetchMetricsSnapshot(ctx, unreachable, true, io.Discard)
		require.ErrorContains(t, err, "refusing the offline fallback")
		assert.False(t, offline)
	})
	t.Run("unreachable default url falls back with a warning", func(t *testing.T) {
		var warn bytes.Buffer
		snap, offline, err := fetchMetricsSnapshot(ctx, unreachable, false, &warn)
		require.NoError(t, err)
		assert.True(t, offline)
		assert.Equal(t, "standalone", snap.Uptime)
		assert.Contains(t, warn.String(), "OFFLINE projection")
		assert.Contains(t, warn.String(), unreachable)
	})
	t.Run("empty url is the explicit offline mode", func(t *testing.T) {
		var warn bytes.Buffer
		snap, offline, err := fetchMetricsSnapshot(ctx, "", true, &warn)
		require.NoError(t, err)
		assert.True(t, offline)
		assert.Equal(t, "standalone", snap.Uptime)
		assert.Contains(t, warn.String(), `note: --url ""`)
	})
}

func TestAggregateStandaloneSnapshot_UsesSharedProjection(t *testing.T) {
	now := time.Now().UTC()
	records := []evidence.Evidence{
		{
			ID:              "ev-1",
			CorrelationID:   "corr-1",
			Timestamp:       now,
			TenantID:        "default",
			AgentID:         "agent-a",
			RequestSourceID: "caller-a",
			InvocationType:  "gateway",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o-mini",
				Cost:       0.05,
				DurationMS: 100,
			},
		},
	}
	snap := aggregateStandaloneSnapshot(records, now)
	require.Len(t, snap.AgentStats, 1)
	assert.Equal(t, "caller-a", snap.AgentStats[0].Agent)
	assert.Equal(t, 1, snap.Summary.TotalRequests)
}

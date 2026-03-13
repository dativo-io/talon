package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		CallerStats: []metricsapi.CallerStat{
			{Caller: "agent-a", Requests: 3, Successful: 2, Failed: 1, TimedOut: 0, Denied: 0, SuccessRate: 0.66},
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
		CallerStats: []metricsapi.CallerStat{
			{Caller: "agent-a", Requests: 2, SuccessRate: 1.0},
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

	var callers []metricsapi.CallerStat
	require.NoError(t, json.Unmarshal(out.Bytes(), &callers))
	require.Len(t, callers, 1)
	assert.Equal(t, "agent-a", callers[0].Caller)
}

func TestMetricsCommand_AgentFilter(t *testing.T) {
	srv := newMetricsTestServer(t, metricsapi.Snapshot{
		GeneratedAt: time.Now(),
		Summary:     metricsapi.Summary{P99LatencyMS: 123},
		CallerStats: []metricsapi.CallerStat{
			{Caller: "agent-a", Requests: 2, Successful: 2, SuccessRate: 1.0},
			{Caller: "agent-b", Requests: 1, Successful: 0, Failed: 1},
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
		CallerStats: []metricsapi.CallerStat{{Caller: "agent-a"}},
	})
	defer srv.Close()

	snap, err := fetchMetricsSnapshot(context.Background(), srv.URL)
	require.NoError(t, err)
	require.Len(t, snap.CallerStats, 1)
	assert.Equal(t, "agent-a", snap.CallerStats[0].Caller)
}

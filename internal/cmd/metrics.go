package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	metricsapi "github.com/dativo-io/talon/internal/metrics"
)

var (
	metricsAgent string
	metricsJSON  bool
	metricsURL   string
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show enhanced gateway metrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, span := tracer.Start(cmd.Context(), "metrics")
		defer span.End()

		snap, err := fetchMetricsSnapshot(ctx, metricsURL)
		if err != nil {
			return err
		}
		if !metricsJSON {
			warnIfDegraded(ctx, cmd.OutOrStdout(), metricsURL)
		}

		callers := snap.CallerStats
		sort.Slice(callers, func(i, j int) bool { return callers[i].Requests > callers[j].Requests })
		if metricsAgent != "" {
			callers = filterCallers(callers, metricsAgent)
		}

		out := cmd.OutOrStdout()
		if metricsJSON {
			return json.NewEncoder(out).Encode(callers)
		}

		if metricsAgent != "" {
			return renderMetricsAgentDetail(out, metricsAgent, callers, snap)
		}
		renderMetricsSummary(out, callers, snap)
		return nil
	},
}

func fetchMetricsSnapshot(ctx context.Context, baseURL string) (metricsapi.Snapshot, error) {
	trimmed := trimRightSlash(baseURL)
	if trimmed == "" {
		trimmed = "http://localhost:8080"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimmed+"/api/v1/metrics", nil)
	if err != nil {
		return metricsapi.Snapshot{}, fmt.Errorf("building metrics request: %w", err)
	}
	if adminKey := os.Getenv("TALON_ADMIN_KEY"); adminKey != "" {
		req.Header.Set("X-Talon-Admin-Key", adminKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return buildSnapshotFromEvidence(ctx)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return buildSnapshotFromEvidence(ctx)
	}

	var snap metricsapi.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return buildSnapshotFromEvidence(ctx)
	}
	return snap, nil
}

func buildSnapshotFromEvidence(ctx context.Context) (metricsapi.Snapshot, error) {
	cfg, err := config.Load()
	if err != nil {
		return metricsapi.Snapshot{}, fmt.Errorf("loading config for standalone metrics mode: %w", err)
	}
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return metricsapi.Snapshot{}, fmt.Errorf("opening evidence store for standalone metrics mode: %w", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	records, err := store.List(ctx, "", "", from, now, 100000)
	if err != nil {
		return metricsapi.Snapshot{}, fmt.Errorf("querying evidence for standalone metrics mode: %w", err)
	}
	return metricsapi.SnapshotFromEvidenceRecords(records, now), nil
}

func aggregateStandaloneSnapshot(records []evidence.Evidence, now time.Time) metricsapi.Snapshot {
	return metricsapi.SnapshotFromEvidenceRecords(records, now)
}

func filterCallers(in []metricsapi.CallerStat, caller string) []metricsapi.CallerStat {
	filtered := make([]metricsapi.CallerStat, 0, len(in))
	for i := range in {
		c := in[i]
		if c.Caller == caller {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func renderMetricsSummary(w io.Writer, callers []metricsapi.CallerStat, snap metricsapi.Snapshot) {
	fmt.Fprintln(w, "Agent Metrics (last 24h)")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-20s %8s %8s %8s %8s %8s %8s %10s %11s %13s\n",
		"AGENT", "REQUESTS", "SUCCESS", "FAILED", "TIMEOUT", "DENIED", "RATE", "COST(EUR)", "EUR/SUCCESS", "VIOLATIONS(7d)")

	var totalReq, totalSuccess, totalFailed, totalTimeout, totalDenied int
	var totalCost float64
	for i := range callers {
		c := callers[i]
		totalReq += c.Requests
		totalSuccess += c.Successful
		totalFailed += c.Failed
		totalTimeout += c.TimedOut
		totalDenied += c.Denied
		totalCost += c.CostEUR

		values := make([]int, 0, len(c.ViolationTrend))
		for _, d := range c.ViolationTrend {
			values = append(values, d.Count)
		}
		fmt.Fprintf(w, "%-20s %8d %8d %8d %8d %8d %7.1f%% %10.4f %11.4f %13s\n",
			c.Caller, c.Requests, c.Successful, c.Failed, c.TimedOut, c.Denied, c.SuccessRate*100,
			c.CostEUR, c.CostPerSuccess, sparkline(values))
	}
	if len(callers) == 0 {
		fmt.Fprintln(w, "(no caller data)")
	}

	fmt.Fprintln(w)
	if totalReq == 0 {
		fmt.Fprintln(w, "Totals: 0 requests | 0 successful | 0 failed | 0 timeouts | 0 denied | EUR0.0000")
		return
	}
	successRate := (float64(totalSuccess) / float64(totalReq)) * 100
	fmt.Fprintf(w, "Totals: %d requests | %d successful | %d failed | %d timeouts | %d denied | EUR%.4f | success rate %.1f%%\n",
		totalReq, totalSuccess, totalFailed, totalTimeout, totalDenied, totalCost, successRate)
	_ = snap
}

func renderMetricsAgentDetail(w io.Writer, requested string, callers []metricsapi.CallerStat, snap metricsapi.Snapshot) error {
	if len(callers) == 0 {
		return fmt.Errorf("agent %q not found in metrics snapshot", requested)
	}
	c := callers[0]
	fmt.Fprintf(w, "Agent Metrics: %s\n\n", c.Caller)
	fmt.Fprintf(w, "Requests: %d\n", c.Requests)
	fmt.Fprintf(w, "Successful: %d\n", c.Successful)
	fmt.Fprintf(w, "Failed: %d\n", c.Failed)
	fmt.Fprintf(w, "Timed out: %d\n", c.TimedOut)
	fmt.Fprintf(w, "Denied: %d\n", c.Denied)
	fmt.Fprintf(w, "Success rate: %.1f%%\n", c.SuccessRate*100)
	fmt.Fprintf(w, "Cost (EUR): %.4f\n", c.CostEUR)
	fmt.Fprintf(w, "Cost per success (EUR): %.4f\n", c.CostPerSuccess)
	fmt.Fprintf(w, "Avg latency: %dms\n", c.AvgLatencyMS)
	fmt.Fprintf(w, "Global P99 latency: %dms\n", snap.Summary.P99LatencyMS)
	if snap.BudgetStatus != nil {
		fmt.Fprintf(w, "Budget daily: %.1f%% (%.4f/%.4f)\n", snap.BudgetStatus.DailyPercent, snap.BudgetStatus.DailyUsed, snap.BudgetStatus.DailyLimit)
		fmt.Fprintf(w, "Budget monthly: %.1f%% (%.4f/%.4f)\n", snap.BudgetStatus.MonthlyPercent, snap.BudgetStatus.MonthlyUsed, snap.BudgetStatus.MonthlyLimit)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Violation trend (7d):")
	for _, d := range c.ViolationTrend {
		fmt.Fprintf(w, "  %s  %d\n", d.Date, d.Count)
	}
	return nil
}

func sparkline(values []int) string {
	blocks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	if len(values) == 0 {
		return ""
	}
	max := 0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	result := make([]rune, len(values))
	for i, v := range values {
		if max == 0 {
			result[i] = blocks[0]
			continue
		}
		idx := (v * (len(blocks) - 1)) / max
		result[i] = blocks[idx]
	}
	return string(result)
}

func trimRightSlash(url string) string {
	for url != "" && url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	return url
}

func init() {
	rootCmd.AddCommand(metricsCmd)
	metricsCmd.Flags().StringVar(&metricsAgent, "agent", "", "show detailed metrics for a single agent")
	metricsCmd.Flags().BoolVar(&metricsJSON, "json", false, "emit caller metrics as JSON")
	metricsCmd.Flags().StringVar(&metricsURL, "url", "http://localhost:8080", "base URL for talon server")
}

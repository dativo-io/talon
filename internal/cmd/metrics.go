package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
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
	trimmed := strings.TrimRight(baseURL, "/")
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

type standaloneCallerAccum struct {
	requests       int
	successful     int
	failed         int
	timedOut       int
	denied         int
	piiDetected    int
	blocked        int
	costEUR        float64
	totalLatencyMS int64
	successCostEUR float64
	violations     map[string]int
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
	return aggregateStandaloneSnapshot(records, now), nil
}

func aggregateStandaloneSnapshot(records []evidence.Evidence, now time.Time) metricsapi.Snapshot {
	callers := map[string]*standaloneCallerAccum{}
	for i := range records {
		aggregateStandaloneRecord(callers, records[i])
	}
	outCallers, summary := buildStandaloneCallerStats(callers, now)
	return metricsapi.Snapshot{
		GeneratedAt: now,
		Uptime:      "standalone",
		Summary:     summary,
		CallerStats: outCallers,
	}
}

func aggregateStandaloneRecord(callers map[string]*standaloneCallerAccum, rec evidence.Evidence) {
	caller := standaloneCallerName(rec)
	acc := callers[caller]
	if acc == nil {
		acc = &standaloneCallerAccum{violations: map[string]int{}}
		callers[caller] = acc
	}

	acc.requests++
	acc.costEUR += rec.Execution.Cost
	acc.totalLatencyMS += rec.Execution.DurationMS
	acc.piiDetected += len(rec.Classification.PIIDetected)

	isDenied := !rec.PolicyDecision.Allowed
	if isDenied {
		acc.denied++
		acc.blocked++
	}

	switch {
	case standaloneTimedOut(rec.Execution.Error):
		acc.timedOut++
		acc.failed++
	case isDenied:
	case rec.Execution.Error != "":
		acc.failed++
	default:
		acc.successful++
		acc.successCostEUR += rec.Execution.Cost
	}
	if standaloneHasViolation(rec, isDenied) {
		acc.violations[rec.Timestamp.UTC().Format("2006-01-02")]++
	}
}

func buildStandaloneCallerStats(callers map[string]*standaloneCallerAccum, now time.Time) ([]metricsapi.CallerStat, metricsapi.Summary) {
	outCallers := make([]metricsapi.CallerStat, 0, len(callers))
	totalRequests := 0
	totalSuccessful := 0
	totalFailed := 0
	totalTimedOut := 0
	totalDenied := 0
	totalBlocked := 0
	totalPII := 0
	totalCost := 0.0
	totalLat := int64(0)

	for caller, acc := range callers {
		cs := metricsapi.CallerStat{
			Caller:      caller,
			Requests:    acc.requests,
			PIIDetected: acc.piiDetected,
			Blocked:     acc.blocked,
			CostEUR:     acc.costEUR,
			Successful:  acc.successful,
			Failed:      acc.failed,
			TimedOut:    acc.timedOut,
			Denied:      acc.denied,
		}
		if acc.requests > 0 {
			cs.AvgLatencyMS = acc.totalLatencyMS / int64(acc.requests)
			cs.SuccessRate = float64(acc.successful) / float64(acc.requests)
		}
		if acc.successful > 0 {
			cs.CostPerSuccess = acc.successCostEUR / float64(acc.successful)
		}
		cs.ViolationTrend = buildViolationTrend(acc.violations, now)
		outCallers = append(outCallers, cs)

		totalRequests += acc.requests
		totalSuccessful += acc.successful
		totalFailed += acc.failed
		totalTimedOut += acc.timedOut
		totalDenied += acc.denied
		totalBlocked += acc.blocked
		totalPII += acc.piiDetected
		totalCost += acc.costEUR
		totalLat += acc.totalLatencyMS
	}
	sort.Slice(outCallers, func(i, j int) bool { return outCallers[i].Requests > outCallers[j].Requests })

	summary := metricsapi.Summary{
		TotalRequests:   totalRequests,
		BlockedRequests: totalBlocked,
		PIIDetections:   totalPII,
		TotalCostEUR:    totalCost,
		TotalSuccessful: totalSuccessful,
		TotalFailed:     totalFailed,
		TotalTimedOut:   totalTimedOut,
		TotalDenied:     totalDenied,
	}
	if totalRequests > 0 {
		summary.AvgLatencyMS = totalLat / int64(totalRequests)
		summary.SuccessRate = float64(totalSuccessful) / float64(totalRequests)
		summary.ErrorRate = float64(totalFailed) / float64(totalRequests)
	}
	return outCallers, summary
}

func standaloneCallerName(rec evidence.Evidence) string {
	switch {
	case rec.AgentID != "":
		return rec.AgentID
	case rec.RequestSourceID != "":
		return rec.RequestSourceID
	default:
		return "unknown"
	}
}

func standaloneTimedOut(execErr string) bool {
	errLower := strings.ToLower(execErr)
	return strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline exceeded")
}

func standaloneHasViolation(rec evidence.Evidence, isDenied bool) bool {
	if isDenied || len(rec.Classification.PIIDetected) > 0 {
		return true
	}
	return rec.ToolGovernance != nil && len(rec.ToolGovernance.ToolsFiltered) > 0
}

func buildViolationTrend(byDay map[string]int, now time.Time) []metricsapi.DayCount {
	today := now.UTC().Truncate(24 * time.Hour)
	trend := make([]metricsapi.DayCount, 7)
	for i := 6; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		key := day.Format("2006-01-02")
		trend[6-i] = metricsapi.DayCount{Date: key, Count: byDay[key]}
	}
	return trend
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

func init() {
	rootCmd.AddCommand(metricsCmd)
	metricsCmd.Flags().StringVar(&metricsAgent, "agent", "", "show detailed metrics for a single agent")
	metricsCmd.Flags().BoolVar(&metricsJSON, "json", false, "emit caller metrics as JSON")
	metricsCmd.Flags().StringVar(&metricsURL, "url", "http://localhost:8080", "base URL for talon server")
}

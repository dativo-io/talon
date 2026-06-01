package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type statusSnapshot struct {
	Status               string `json:"status"`
	EvidenceOK           bool   `json:"evidence_ok"`
	EvidenceError        string `json:"evidence_error"`
	EventsStreamGaps     int64  `json:"events_stream_gaps"`
	EventsReplayMisses   int64  `json:"events_replay_misses"`
	EventsBacklogDrops   int64  `json:"events_backlog_drops"`
	MetricsEventsDropped int64  `json:"metrics_events_dropped"`
	ReconcileError       string `json:"metrics_reconcile_error"`
}

func warnIfDegraded(ctx context.Context, out io.Writer, baseURL string) {
	snap, ok := fetchStatusSnapshot(ctx, baseURL)
	if !ok {
		return
	}
	issues := degradedIssues(snap)
	if len(issues) == 0 {
		return
	}
	_, _ = fmt.Fprintf(out, "warning: runtime degraded (%s)\n", strings.Join(issues, "; "))
}

func fetchStatusSnapshot(ctx context.Context, baseURL string) (statusSnapshot, bool) {
	base := trimRightSlash(baseURL)
	if base == "" {
		base = "http://localhost:8080"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/status", nil)
	if err != nil {
		return statusSnapshot{}, false
	}
	if adminKey := os.Getenv("TALON_ADMIN_KEY"); adminKey != "" {
		req.Header.Set("X-Talon-Admin-Key", adminKey)
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return statusSnapshot{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusSnapshot{}, false
	}
	var snap statusSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return statusSnapshot{}, false
	}
	return snap, true
}

func degradedIssues(snap statusSnapshot) []string {
	issues := make([]string, 0, 5)
	if !snap.EvidenceOK || strings.EqualFold(snap.Status, "degraded") {
		if snap.EvidenceError != "" {
			issues = append(issues, "evidence write failures")
		} else {
			issues = append(issues, "degraded server status")
		}
	}
	if snap.EventsBacklogDrops > 0 || snap.MetricsEventsDropped > 0 {
		issues = append(issues, "collector/backlog drops")
	}
	if snap.EventsStreamGaps > 0 || snap.EventsReplayMisses > 0 {
		issues = append(issues, "event stream gaps")
	}
	if snap.ReconcileError != "" {
		issues = append(issues, "metrics reconciliation errors")
	}
	return issues
}

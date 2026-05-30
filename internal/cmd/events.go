package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/events"
	"github.com/dativo-io/talon/internal/evidence"
)

var (
	eventsURL    string
	eventsTenant string
	eventsSince  string
	eventsJSON   bool
)

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Stream operational events",
}

var eventsTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Tail operational events from API or local evidence",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		if err := tailEventsHTTP(ctx, cmd.OutOrStdout()); err == nil {
			return nil
		}
		return tailEventsLocal(ctx, cmd.OutOrStdout())
	},
}

func tailEventsHTTP(ctx context.Context, outWriter interface{ Write([]byte) (int, error) }) error {
	if !eventsJSON {
		warnIfDegraded(ctx, outWriter, eventsURL)
	}
	req, err := buildEventsStreamRequest(ctx)
	if err != nil {
		return err
	}
	resp, err := openEventsStream(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return consumeEventsStream(resp.Body, outWriter)
}

func buildEventsStreamRequest(ctx context.Context) (*http.Request, error) {
	base := trimRightSlash(eventsURL)
	if base == "" {
		base = "http://localhost:8080"
	}
	endpoint := base + "/api/v1/events/stream"
	values := url.Values{}
	if tenant := strings.TrimSpace(eventsTenant); tenant != "" {
		values.Set("tenant_id", tenant)
	}
	if since := strings.TrimSpace(eventsSince); since != "" {
		values.Set("since_id", since)
	}
	if encoded := values.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build events stream request: %w", err)
	}
	if adminKey := os.Getenv("TALON_ADMIN_KEY"); adminKey != "" {
		req.Header.Set("X-Talon-Admin-Key", adminKey)
	}
	if since := strings.TrimSpace(eventsSince); since != "" {
		req.Header.Set("Last-Event-ID", since)
	}
	return req, nil
}

func openEventsStream(req *http.Request) (*http.Response, error) {
	//nolint:gosec // G704: CLI intentionally connects to operator-provided Talon URL (--url).
	resp, err := (&http.Client{Timeout: 0}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect events stream: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("events stream status: %d", resp.StatusCode)
	}
	return resp, nil
}

func consumeEventsStream(body io.Reader, outWriter interface{ Write([]byte) (int, error) }) error {
	sc := bufio.NewScanner(body)
	var lastID string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "id: "):
			lastID = strings.TrimSpace(strings.TrimPrefix(line, "id: "))
		case strings.HasPrefix(line, "data: "):
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
			var ev events.OperationalEvent
			if err := json.Unmarshal([]byte(payload), &ev); err != nil {
				continue
			}
			if ev.EventID == "" {
				ev.EventID = lastID
			}
			printOperationalEvent(outWriter, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read events stream: %w", err)
	}
	return nil
}

func tailEventsLocal(ctx context.Context, outWriter interface{ Write([]byte) (int, error) }) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config for events fallback: %w", err)
	}
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("opening evidence store for events fallback: %w", err)
	}
	defer store.Close()

	cursor := strings.TrimSpace(eventsSince)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		list, err := store.List(ctx, strings.TrimSpace(eventsTenant), "", time.Time{}, time.Now().UTC(), 200)
		if err != nil {
			return fmt.Errorf("listing evidence events fallback: %w", err)
		}
		items := make([]events.OperationalEvent, 0, len(list))
		for i := range list {
			ev := events.FromEvidence(&list[i])
			if cursor != "" && ev.EventID <= cursor {
				continue
			}
			items = append(items, ev)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].EventID < items[j].EventID })
		for i := range items {
			printOperationalEvent(outWriter, items[i])
			cursor = items[i].EventID
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func printOperationalEvent(outWriter interface{ Write([]byte) (int, error) }, ev events.OperationalEvent) {
	if eventsJSON {
		b, _ := json.Marshal(ev)
		_, _ = outWriter.Write(append(b, '\n'))
		return
	}
	line := fmt.Sprintf(
		"%s | tenant=%s | caller=%s | decision=%s | reason_code=%s | reason_text=%s | cost=%.4f | model=%s | evidence=%s | correlation=%s\n",
		ev.Timestamp.Format(time.RFC3339), valueOrDash(ev.TenantID), valueOrDash(ev.Caller), valueOrDash(ev.Decision),
		valueOrDash(ev.ReasonCode), valueOrDash(ev.ReasonText), ev.CostEUR, valueOrDash(ev.Model), valueOrDash(ev.EvidenceID), valueOrDash(ev.CorrelationID),
	)
	_, _ = outWriter.Write([]byte(line))
}

func valueOrDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func init() {
	rootCmd.AddCommand(eventsCmd)
	eventsCmd.AddCommand(eventsTailCmd)
	eventsTailCmd.Flags().StringVar(&eventsURL, "url", "http://localhost:8080", "base URL for talon server")
	eventsTailCmd.Flags().StringVar(&eventsTenant, "tenant", "", "tenant id filter (admin may use * for all)")
	eventsTailCmd.Flags().StringVar(&eventsSince, "since", "", "resume cursor (event_id)")
	eventsTailCmd.Flags().BoolVar(&eventsJSON, "json", false, "emit JSON events")
}

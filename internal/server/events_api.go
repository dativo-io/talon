package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/events"
	"github.com/dativo-io/talon/internal/health"
)

const (
	defaultRecentEventsLimit = 50
)

type recentEventsResponse struct {
	Events []events.OperationalEvent `json:"events"`
	Cursor string                    `json:"cursor,omitempty"`
}

// handleEventsRecent returns the latest operational events for caller-visible tenants.
// It emits one event per persisted evidence row: terminal outcomes and lifecycle
// subset records that are evidence-backed (for example plan review and graph runtime rows).
func (s *Server) handleEventsRecent(w http.ResponseWriter, r *http.Request) {
	tenantID := s.resolveEventsTenant(r)
	limit := parsePositiveInt(r.URL.Query().Get("limit"), defaultRecentEventsLimit, s.eventsRecentMaxLimit)
	sinceID := strings.TrimSpace(r.URL.Query().Get("since_id"))

	list, err := s.listOperationalEvents(r, tenantID, limit, sinceID, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	resp := recentEventsResponse{Events: list}
	if len(list) > 0 {
		resp.Cursor = list[0].EventID
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleEventsStream streams operational events as SSE.
// Like handleEventsRecent, it emits only evidence-backed rows and therefore includes
// terminal outcomes plus the lifecycle subset represented in persisted evidence.
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	flusher, _ := w.(http.Flusher)
	if health.ActiveEventStreams() >= int64(s.eventsStreamMaxConn) {
		writeError(w, http.StatusServiceUnavailable, "stream_limit", "event stream connection limit reached")
		return
	}
	health.IncActiveEventStreams()
	defer health.DecActiveEventStreams()

	tenantID := s.resolveEventsTenant(r)
	cursor := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if cursor == "" {
		cursor = strings.TrimSpace(r.URL.Query().Get("since_id"))
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ctx := r.Context()
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}

	initial, gap, err := s.listEventsForStream(r, tenantID, cursor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if gap {
		health.IncEventStreamGap()
		fmt.Fprintf(w, "event: gap\ndata: {\"reason\":\"replay_window_miss\"}\n\n")
		flush()
	}
	for i := range initial {
		payload, _ := json.Marshal(initial[i])
		fmt.Fprintf(w, "id: %s\ndata: %s\n\n", initial[i].EventID, payload)
		cursor = initial[i].EventID
	}
	flush()

	ticker := time.NewTicker(s.eventsPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			health.IncEventStreamDisconnect()
			return
		case <-ticker.C:
			next, gapDetected, err := s.listEventsForStream(r, tenantID, cursor)
			if err != nil {
				continue
			}
			if gapDetected {
				health.IncEventStreamGap()
				if _, writeErr := fmt.Fprintf(w, "event: gap\ndata: {\"reason\":\"replay_window_miss\"}\n\n"); writeErr != nil {
					health.IncEventStreamDisconnect()
					return
				}
				flush()
			}
			for i := range next {
				payload, _ := json.Marshal(next[i])
				if _, writeErr := fmt.Fprintf(w, "id: %s\ndata: %s\n\n", next[i].EventID, payload); writeErr != nil {
					health.IncEventStreamDisconnect()
					return
				}
				cursor = next[i].EventID
			}
			flush()
		}
	}
}

func (s *Server) listOperationalEvents(r *http.Request, tenantID string, limit int, sinceID string, desc bool) ([]events.OperationalEvent, error) {
	now := time.Now().UTC()
	from := time.Time{}
	if sinceTS, ok := eventIDTimestamp(sinceID); ok {
		from = sinceTS
	}

	records, err := s.evidenceStore.List(r.Context(), tenantID, "", from, now, max(limit*4, s.eventsReplayBacklog))
	if err != nil {
		return nil, fmt.Errorf("listing evidence events: %w", err)
	}
	out := make([]events.OperationalEvent, 0, len(records))
	for i := range records {
		ev := events.FromEvidence(&records[i])
		if sinceID != "" && ev.EventID <= sinceID {
			continue
		}
		out = append(out, ev)
	}
	events.SortDesc(out)
	if !desc {
		reverse(out)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Server) listEventsForStream(r *http.Request, tenantID, sinceID string) ([]events.OperationalEvent, bool, error) {
	now := time.Now().UTC()
	records, err := s.evidenceStore.List(r.Context(), tenantID, "", time.Time{}, now, s.eventsReplayBacklog)
	if err != nil {
		return nil, false, fmt.Errorf("listing stream evidence events: %w", err)
	}
	desc := make([]events.OperationalEvent, 0, len(records))
	foundCursor := sinceID == ""
	for i := range records {
		ev := events.FromEvidence(&records[i])
		desc = append(desc, ev)
		if ev.EventID == sinceID {
			foundCursor = true
		}
	}
	events.SortDesc(desc)
	gap := sinceID != "" && !foundCursor && len(desc) == s.eventsReplayBacklog
	if gap {
		health.IncEventReplayMiss()
		health.IncEventBacklogDrop()
	}

	asc := make([]events.OperationalEvent, 0, len(desc))
	for i := len(desc) - 1; i >= 0; i-- {
		ev := desc[i]
		if sinceID != "" && ev.EventID <= sinceID {
			continue
		}
		asc = append(asc, ev)
	}
	return asc, gap, nil
}

func (s *Server) resolveEventsTenant(r *http.Request) string {
	tenantID := TenantIDFromContext(r.Context())
	queryTenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID != "" {
		return tenantID
	}
	if queryTenant != "" {
		if queryTenant == "*" && IsAdminFromContext(r.Context()) {
			return ""
		}
		return queryTenant
	}
	return "default"
}

func parsePositiveInt(raw string, fallback int, maxAllowed int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return fallback
	}
	if v > maxAllowed {
		return maxAllowed
	}
	return v
}

func reverse(items []events.OperationalEvent) {
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
}

func eventIDTimestamp(eventID string) (time.Time, bool) {
	parts := strings.SplitN(strings.TrimSpace(eventID), "-", 2)
	if len(parts) != 2 {
		return time.Time{}, false
	}
	ms, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(ms).UTC(), true
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

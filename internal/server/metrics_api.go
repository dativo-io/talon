package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// handleMetricsJSON returns the current metrics snapshot as JSON.
// The snapshot is all-activity and includes evidence-backed gateway and agent-run paths.
// The snapshot was built for the retired gateway dashboard; it remains the
// machine-readable metrics surface (`talon metrics`, #533 console).
func (s *Server) handleMetricsJSON(w http.ResponseWriter, r *http.Request) {
	snap := s.metricsCollector.Snapshot(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(snap)
}

// handleMetricsStream sends metrics snapshots as Server-Sent Events.
// The stream mirrors the same all-activity snapshot as handleMetricsJSON.
// The snapshot was built for the retired gateway dashboard; it remains the
// machine-readable metrics surface (`talon metrics`, #533 console).
// If the response writer does not implement http.Flusher (e.g. behind a buffering proxy),
// events are still sent but may be delayed until the buffer fills or the connection closes.
func (s *Server) handleMetricsStream(w http.ResponseWriter, r *http.Request) {
	flusher, _ := w.(http.Flusher)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}

	snap := s.metricsCollector.Snapshot(ctx)
	data, _ := json.Marshal(snap)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flush()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := s.metricsCollector.Snapshot(ctx)
			data, err := json.Marshal(snap)
			if err != nil {
				continue
			}
			_, writeErr := fmt.Fprintf(w, "data: %s\n\n", data)
			if writeErr != nil {
				return
			}
			flush()
		}
	}
}

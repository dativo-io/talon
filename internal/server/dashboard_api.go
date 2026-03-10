package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// handleGatewayDashboard serves the single-file HTML gateway dashboard.
func (s *Server) handleGatewayDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	//nolint:gosec // G203: embedded HTML served from Go binary (not user-supplied)
	fmt.Fprint(w, s.gatewayDashboardHTML)
}

// handleMetricsJSON returns the current metrics snapshot as JSON.
func (s *Server) handleMetricsJSON(w http.ResponseWriter, r *http.Request) {
	snap := s.metricsCollector.Snapshot(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(snap)
}

// handleMetricsStream sends metrics snapshots as Server-Sent Events.
func (s *Server) handleMetricsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	snap := s.metricsCollector.Snapshot(ctx)
	data, _ := json.Marshal(snap)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()

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
			flusher.Flush()
		}
	}
}

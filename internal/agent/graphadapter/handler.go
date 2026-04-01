package graphadapter

import (
	"encoding/json"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/requestctx"
)

// Handler serves the /v1/graph/events HTTP endpoint. External runtimes
// POST governance events and receive control decisions synchronously.
type Handler struct {
	adapter *Adapter
}

// NewHandler creates a graph events HTTP handler.
func NewHandler(adapter *Adapter) *Handler {
	return &Handler{adapter: adapter}
}

// ServeHTTP handles POST /v1/graph/events.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method must be POST"})
		return
	}

	ctx, span := tracer.Start(r.Context(), "graphadapter.http.serve",
		trace.WithAttributes(attribute.String("http.request.method", r.Method)),
	)
	defer span.End()

	var ev Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if ev.GraphRunID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "graph_run_id is required"})
		return
	}
	if ev.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type is required"})
		return
	}

	if ev.TenantID == "" {
		ev.TenantID = requestctx.TenantID(ctx)
	}
	if ev.TenantID == "" {
		ev.TenantID = "default"
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}

	span.SetAttributes(
		attribute.String("event.type", string(ev.Type)),
		attribute.String("graph_run_id", ev.GraphRunID),
		attribute.String("tenant_id", ev.TenantID),
	)

	dec, err := h.adapter.HandleEvent(ctx, &ev)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, dec)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

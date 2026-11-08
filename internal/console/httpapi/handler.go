// Package httpapi serves the console read model over HTTP (#535). It is a
// chi router the console process mounts behind the browser-session
// middleware (#537); nothing in the data-plane server mounts it, it has no
// authentication of its own and must not be exposed without that middleware.
// Every response is one DTO from internal/console; errors use the
// repository's {error, message} envelope.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/session"
)

// Prefix is the path prefix every console read route lives under.
const Prefix = "/console/v1"

// Handler returns the router for svc. Routes (all GET):
//
//	/console/v1/overview?tenant=
//	/console/v1/use-cases?tenant=
//	/console/v1/use-cases/{name}?tenant=
//	/console/v1/sessions?tenant=&agent=&status=&limit=&before=<RFC3339>&before_id=&observed_before=<RFC3339>&observed_before_id=&observed_before_agent=
//	/console/v1/sessions/{id}?tenant=&agent=&timeline_limit=&timeline_after=<RFC3339>&timeline_after_id=
//	/console/v1/sessions/{id}/timeline?tenant=&agent=&timeline_limit=&timeline_after=<RFC3339>&timeline_after_id=   (no summary)
//	/console/v1/evidence/{id}?tenant=
//	/console/v1/costs?tenant=&agent=&breakdown=agents|model|provider|team
//	/console/v1/activity?tenant=&agent=&from=&to=&bucket=5m|1h|24h
//	/console/v1/system
func Handler(svc *console.Service) http.Handler {
	r := chi.NewRouter()
	r.Route(Prefix, func(r chi.Router) {
		r.Get("/overview", func(w http.ResponseWriter, req *http.Request) {
			writeJSON(w, http.StatusOK, svc.Overview(req.Context(), q(req, "tenant")))
		})
		r.Get("/use-cases", func(w http.ResponseWriter, req *http.Request) {
			meta, uc := svc.UseCases(req.Context(), q(req, "tenant"))
			writeJSON(w, http.StatusOK, struct {
				Meta     console.Meta     `json:"meta"`
				UseCases console.UseCases `json:"use_cases"`
			}{meta, uc})
		})
		r.Get("/use-cases/{name}", func(w http.ResponseWriter, req *http.Request) {
			d, err := svc.UseCase(req.Context(), q(req, "tenant"), chi.URLParam(req, "name"))
			if err != nil {
				writeServiceError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, d)
		})
		r.Get("/sessions", sessionsHandler(svc))
		r.Get("/sessions/{id}", sessionDetailHandler(svc))
		r.Get("/sessions/{id}/timeline", sessionTimelineHandler(svc))
		r.Get("/evidence/{id}", func(w http.ResponseWriter, req *http.Request) {
			d, err := svc.Evidence(req.Context(), chi.URLParam(req, "id"), q(req, "tenant"))
			if err != nil {
				writeServiceError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, d)
		})
		r.Get("/costs", func(w http.ResponseWriter, req *http.Request) {
			breakdown := costs.Breakdown(q(req, "breakdown"))
			switch breakdown {
			case "", costs.BreakdownAgents, costs.BreakdownModel, costs.BreakdownProvider, costs.BreakdownTeam:
			default:
				writeError(w, http.StatusBadRequest, "invalid_request", "breakdown must be agents, model, provider or team")
				return
			}
			writeJSON(w, http.StatusOK, svc.Costs(req.Context(), q(req, "tenant"), q(req, "agent"), breakdown))
		})
		r.Get("/activity", func(w http.ResponseWriter, req *http.Request) {
			bucketName := q(req, "bucket")
			if bucketName == "" {
				bucketName = "1h"
			}
			bucket, ok := evidence.ActivityBucketSizes[bucketName]
			if !ok {
				writeError(w, http.StatusBadRequest, "invalid_request", "bucket must be 5m, 1h or 24h")
				return
			}
			to, err := optionalTime(q(req, "to"))
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_request", "to must be RFC 3339")
				return
			}
			if to.IsZero() {
				to = time.Now().UTC()
			}
			from, err := optionalTime(q(req, "from"))
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_request", "from must be RFC 3339")
				return
			}
			if from.IsZero() {
				from = to.Add(-console.DefaultActivitySpan)
			}
			writeJSON(w, http.StatusOK, svc.Activity(req.Context(), q(req, "tenant"), q(req, "agent"), from, to, bucket))
		})
		r.Get("/system", func(w http.ResponseWriter, req *http.Request) {
			writeJSON(w, http.StatusOK, svc.System(req.Context()))
		})
	})
	return r
}

// sessionsHandler serves GET /console/v1/sessions.
func sessionsHandler(svc *console.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Two keyset cursors, one per source: (before, before_id) for
		// session-store rows, (observed_before, observed_before_id) for
		// evidence-observed ids. Both halves of a cursor travel together.
		before, err := optionalTime(q(req, "before"))
		if err != nil || (before.IsZero() != (q(req, "before_id") == "")) {
			writeError(w, http.StatusBadRequest, "invalid_request", "before (RFC 3339) and before_id must be given together")
			return
		}
		observedBefore, err := optionalTime(q(req, "observed_before"))
		if err != nil || (observedBefore.IsZero() != (q(req, "observed_before_id") == "")) || (observedBefore.IsZero() != (q(req, "observed_before_agent") == "")) {
			writeError(w, http.StatusBadRequest, "invalid_request", "observed_before (RFC 3339), observed_before_id and observed_before_agent must be given together")
			return
		}
		limit, err := optionalInt(q(req, "limit"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
			return
		}
		writeJSON(w, http.StatusOK, svc.Sessions(req.Context(), q(req, "tenant"), q(req, "agent"), session.Status(q(req, "status")),
			session.Cursor{CreatedAt: before, ID: q(req, "before_id")},
			evidence.ObservedCursor{LastSeen: observedBefore, SessionID: q(req, "observed_before_id"), AgentID: q(req, "observed_before_agent")}, limit))
	}
}

// sessionDetailHandler serves GET /console/v1/sessions/{id}: the complete
// summary plus one timeline page (timeline_limit, timeline_after + timeline_after_id).
func sessionDetailHandler(svc *console.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		after, limit, ok := timelineParams(w, req)
		if !ok {
			return
		}
		d, err := svc.Session(req.Context(), chi.URLParam(req, "id"), q(req, "tenant"), q(req, "agent"), after, limit)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, d)
	}
}

// timelineParams parses timeline_limit and the (timeline_after,
// timeline_after_id) cursor; on a bad request it writes the error and
// returns ok=false.
func timelineParams(w http.ResponseWriter, req *http.Request) (after evidence.TimelineCursor, limit int, ok bool) {
	ts, err := optionalTime(q(req, "timeline_after"))
	if err != nil || (ts.IsZero() != (q(req, "timeline_after_id") == "")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "timeline_after (RFC 3339) and timeline_after_id must be given together")
		return after, 0, false
	}
	limit, err = optionalInt(q(req, "timeline_limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "timeline_limit must be a positive integer")
		return after, 0, false
	}
	return evidence.TimelineCursor{Timestamp: ts, ID: q(req, "timeline_after_id")}, limit, true
}

// sessionTimelineHandler serves GET /console/v1/sessions/{id}/timeline: one
// page without the summary (timeline_limit, timeline_after + timeline_after_id, agent).
func sessionTimelineHandler(svc *console.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		after, limit, ok := timelineParams(w, req)
		if !ok {
			return
		}
		d, err := svc.SessionTimeline(req.Context(), chi.URLParam(req, "id"), q(req, "tenant"), q(req, "agent"), after, limit)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, d)
	}
}

func q(r *http.Request, name string) string { return strings.TrimSpace(r.URL.Query().Get(name)) }

func optionalTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}

func optionalInt(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, errors.New("not a positive integer")
	}
	return n, nil
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, console.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, console.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, console.ErrUnavailable):
		// A store that cannot answer is not a missing record.
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

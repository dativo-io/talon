package otel

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/dativo-io/talon/internal/otel"

// MiddlewareWithStatus returns a chi middleware that starts a span per request,
// injects trace context so downstream handlers (e.g. webhook -> Run) appear as
// children of the HTTP span, and records span status from the response (Error
// for 5xx, Ok otherwise).
func MiddlewareWithStatus() func(next http.Handler) http.Handler {
	tr := Tracer(tracerName)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			route := routePattern(r)
			ctx, span := tr.Start(ctx, "http.request",
				trace.WithAttributes(
					attribute.String("http.request.method", r.Method),
					attribute.String("http.route", route),
					attribute.String("url.path", r.URL.Path),
				))
			r = r.WithContext(ctx)
			wrapped := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(wrapped, r)
			if wrapped.status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(wrapped.status))
			}
			span.End()
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush propagates streaming flushes. Embedding the http.ResponseWriter
// interface promotes only Header/Write/WriteHeader, so without this method
// every handler behind the middleware lost http.Flusher and each SSE
// response (gateway streams, dashboard event feeds) was silently held in
// the net/http buffer until it filled or the response ended (#476).
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// routePattern returns the chi route pattern (e.g. "/v1/triggers/{name}") when
// available, otherwise the request path.
func routePattern(r *http.Request) string {
	if ctx := chi.RouteContext(r.Context()); ctx != nil && ctx.RoutePattern() != "" {
		return ctx.RoutePattern()
	}
	return r.URL.Path
}

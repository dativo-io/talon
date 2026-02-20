package otel

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/dativo-io/talon/internal/otel"

// Middleware returns a chi middleware that starts a span per request and
// injects trace context so downstream handlers (e.g. webhook -> Run) appear
// as children of the HTTP span.
func Middleware() func(next http.Handler) http.Handler {
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
			defer span.End()

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
			// Optionally set span status from response; for simplicity we leave Ok.
			// If next handler writes 5xx, we could use a response wrapper to set status.
		})
	}
}

// MiddlewareWithStatus is like Middleware but records span status from the
// response status code (Error for 5xx, Ok otherwise).
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

// routePattern returns the chi route pattern (e.g. "/v1/triggers/{name}") when
// available, otherwise the request path.
func routePattern(r *http.Request) string {
	if ctx := chi.RouteContext(r.Context()); ctx != nil && ctx.RoutePattern() != "" {
		return ctx.RoutePattern()
	}
	return r.URL.Path
}

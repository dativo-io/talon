package otel

import (
	"context"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

// TraceContextFrom returns trace_id and span_id from the span in ctx, if any.
// Use with zerolog to correlate logs with traces, e.g.:
//
//	traceID, spanID := otel.TraceContextFrom(ctx)
//	log.Info().Str("correlation_id", id).Str("trace_id", traceID).Str("span_id", spanID).Msg("...")
//
// Only add Str("trace_id", ...) and Str("span_id", ...) when the values are non-empty
// so logs stay clean when OTel is disabled.
func TraceContextFrom(ctx context.Context) (traceID, spanID string) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return "", ""
	}
	return span.SpanContext().TraceID().String(), span.SpanContext().SpanID().String()
}

// LogTraceFields returns a zerolog Func hook that adds trace_id and span_id to the
// event when a valid span exists in ctx. Use with .Func():
//
//	log.Info().Str("correlation_id", id).Func(otel.LogTraceFields(ctx)).Msg("...")
func LogTraceFields(ctx context.Context) func(e *zerolog.Event) {
	return func(e *zerolog.Event) {
		traceID, spanID := TraceContextFrom(ctx)
		if traceID != "" {
			e.Str("trace_id", traceID)
		}
		if spanID != "" {
			e.Str("span_id", spanID)
		}
	}
}

package otel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// Setup initializes OpenTelemetry with stdout exporters for traces and metrics (MVP).
// If enabled is false, returns a no-op shutdown function and OTel remains disabled.
// Returns a shutdown function that must be called on exit.
// Phase 2: add OTLP exporter option via config for production backends.
func Setup(serviceName, version string, enabled bool) (shutdown func(context.Context) error, err error) {
	if !enabled {
		return func(ctx context.Context) error { return nil }, nil
	}

	ctx := context.Background()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTel resource: %w", err)
	}

	// Trace exporter and provider
	traceExporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("creating trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExporter),
	)
	otel.SetTracerProvider(tp)

	// Metric exporter and provider (so llm.RecordCostMetrics and memory metrics are exported)
	metricExporter, err := stdoutmetric.New(stdoutmetric.WithPrettyPrint())
	if err != nil {
		_ = tp.Shutdown(ctx)
		return nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	reader := metric.NewPeriodicReader(metricExporter)
	mp := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(reader),
	)
	otel.SetMeterProvider(mp)

	shutdown = func(ctx context.Context) error {
		var firstErr error
		if err := tp.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := mp.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	}
	return shutdown, nil
}

// Tracer returns a tracer for the given package
func Tracer(pkg string) trace.Tracer {
	return otel.Tracer(pkg)
}

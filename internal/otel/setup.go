package otel

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// Setup initializes OpenTelemetry with stdout exporter for MVP.
// If enabled is false, returns a no-op shutdown function and OTel remains disabled.
// Returns a shutdown function that must be called on exit.
func Setup(serviceName, version string, enabled bool) (shutdown func(context.Context) error, err error) {
	if !enabled {
		// Return no-op shutdown function
		return func(ctx context.Context) error { return nil }, nil
	}

	// Create resource
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTel resource: %w", err)
	}

	// Create exporter
	var exporter sdktrace.SpanExporter

	// Check if OTLP endpoint is configured (for Phase 2)
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); endpoint != "" {
		// Future: use OTLP exporter
		// For MVP: fall back to stdout
		_ = endpoint
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
	} else {
		// MVP: stdout exporter
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
	}

	if err != nil {
		return nil, fmt.Errorf("creating OTel exporter: %w", err)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	// Return shutdown function
	return tp.Shutdown, nil
}

// Tracer returns a tracer for the given package
func Tracer(pkg string) trace.Tracer {
	return otel.Tracer(pkg)
}

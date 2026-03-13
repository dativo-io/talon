package attachment

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var attachmentMeter = otel.Meter("github.com/dativo-io/talon/internal/attachment")

var injectionCounter metric.Int64Counter

func init() {
	var err error
	injectionCounter, err = attachmentMeter.Int64Counter("talon.injection.attempts.total",
		metric.WithDescription("Prompt injection attempts detected"),
		metric.WithUnit("{attempt}"))
	if err != nil {
		injectionCounter, _ = attachmentMeter.Int64Counter("talon.injection.attempts.total.fallback")
	}
}

// RecordInjectionAttempt increments the injection attempts counter.
func RecordInjectionAttempt(ctx context.Context, detectionType, action string) {
	injectionCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("detection_type", detectionType),
		attribute.String("action", action),
	))
}

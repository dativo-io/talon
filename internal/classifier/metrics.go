package classifier

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var classifierMeter = otel.Meter("github.com/dativo-io/talon/internal/classifier")

var (
	piiDetectionsCounter metric.Int64Counter
	piiRedactionsCounter metric.Int64Counter
)

func init() {
	var err error
	piiDetectionsCounter, err = classifierMeter.Int64Counter("talon.pii.detections.total",
		metric.WithDescription("PII entities detected"),
		metric.WithUnit("{detection}"))
	if err != nil {
		piiDetectionsCounter, _ = classifierMeter.Int64Counter("talon.pii.detections.total.fallback")
	}

	piiRedactionsCounter, err = classifierMeter.Int64Counter("talon.pii.redactions.total",
		metric.WithDescription("PII entities redacted"),
		metric.WithUnit("{redaction}"))
	if err != nil {
		piiRedactionsCounter, _ = classifierMeter.Int64Counter("talon.pii.redactions.total.fallback")
	}
}

// RecordPIIDetection increments the PII detection counter per entity type.
func RecordPIIDetection(ctx context.Context, piiType, direction, action string) {
	piiDetectionsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("pii_type", piiType),
		attribute.String("direction", direction),
		attribute.String("action", action),
	))
}

// RecordPIIRedaction increments the PII redaction counter per entity type.
func RecordPIIRedaction(ctx context.Context, piiType, direction string) {
	piiRedactionsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("pii_type", piiType),
		attribute.String("direction", direction),
	))
}

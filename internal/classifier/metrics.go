package classifier

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var classifierMeter = otel.Meter("github.com/dativo-io/talon/internal/classifier")

var (
	piiDetectionsCounter      metric.Int64Counter
	piiRedactionsCounter      metric.Int64Counter
	enrichmentAttempts        metric.Int64Counter
	enrichmentAttrEmitted     metric.Int64Counter
	enrichmentFallbackUnknown metric.Int64Counter
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
	enrichmentAttempts, _ = classifierMeter.Int64Counter("talon.pii.enrichment.attempts.total",
		metric.WithDescription("Semantic enrichment attempts by entity type"),
		metric.WithUnit("{attempt}"))
	enrichmentAttrEmitted, _ = classifierMeter.Int64Counter("talon.pii.enrichment.attributes.emitted.total",
		metric.WithDescription("Enrichment attributes emitted (e.g. gender, scope)"),
		metric.WithUnit("{attribute}"))
	enrichmentFallbackUnknown, _ = classifierMeter.Int64Counter("talon.pii.enrichment.fallback_unknown.total",
		metric.WithDescription("Enrichment fallback to unknown"),
		metric.WithUnit("{fallback}"))
}

// RecordEnrichmentAttempt records one enrichment attempt for an entity type.
func RecordEnrichmentAttempt(ctx context.Context, entityType string) {
	enrichmentAttempts.Add(ctx, 1, metric.WithAttributes(attribute.String("entity_type", entityType)))
}

// RecordEnrichmentAttribute records one attribute emitted (e.g. gender=female, scope=city).
func RecordEnrichmentAttribute(ctx context.Context, attrName, attrValue string) {
	enrichmentAttrEmitted.Add(ctx, 1, metric.WithAttributes(
		attribute.String("attr", attrName),
		attribute.String("value", attrValue),
	))
}

// RecordEnrichmentFallbackUnknown records fallback to unknown for an attribute.
func RecordEnrichmentFallbackUnknown(ctx context.Context, entityType string) {
	enrichmentFallbackUnknown.Add(ctx, 1, metric.WithAttributes(attribute.String("entity_type", entityType)))
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

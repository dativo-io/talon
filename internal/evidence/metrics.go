package evidence

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var evidenceMeter = otel.Meter("github.com/dativo-io/talon/internal/evidence")

var (
	recordsCounter      metric.Int64Counter
	verificationCounter metric.Int64Counter
)

func init() {
	var err error
	recordsCounter, err = evidenceMeter.Int64Counter("talon.evidence.records.total",
		metric.WithDescription("Total evidence records stored"),
		metric.WithUnit("{record}"))
	if err != nil {
		recordsCounter, _ = evidenceMeter.Int64Counter("talon.evidence.records.total.fallback")
	}

	verificationCounter, err = evidenceMeter.Int64Counter("talon.evidence.signature_verifications",
		metric.WithDescription("HMAC signature verification attempts"),
		metric.WithUnit("{verification}"))
	if err != nil {
		verificationCounter, _ = evidenceMeter.Int64Counter("talon.evidence.signature_verifications.fallback")
	}
}

// RecordEvidenceStored increments the evidence records counter.
func RecordEvidenceStored(ctx context.Context, evidenceType string) {
	recordsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", evidenceType),
	))
}

// RecordSignatureVerification increments the HMAC verification counter.
func RecordSignatureVerification(ctx context.Context, success bool) {
	result := "success"
	if !success {
		result = "failure"
	}
	verificationCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result),
	))
}

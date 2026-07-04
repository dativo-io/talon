package adapter

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var adapterMeter = otel.Meter("github.com/dativo-io/talon/internal/classifier/adapter")

var (
	scannerRequestsCounter metric.Int64Counter
	scannerFailuresCounter metric.Int64Counter
	scannerLatencyHist     metric.Float64Histogram
)

func init() {
	scannerRequestsCounter, _ = adapterMeter.Int64Counter("talon.scanner.requests.total",
		metric.WithDescription("External scanner adapter calls"),
		metric.WithUnit("{request}"))
	scannerFailuresCounter, _ = adapterMeter.Int64Counter("talon.scanner.failures.total",
		metric.WithDescription("External scanner adapter failures by kind"),
		metric.WithUnit("{failure}"))
	scannerLatencyHist, _ = adapterMeter.Float64Histogram("talon.scanner.latency",
		metric.WithDescription("External scanner adapter call latency"),
		metric.WithUnit("ms"))
}

// RecordScan records one adapter call with its outcome ("ok" or the failure
// kind). Shared by all external engine adapters (HTTP/UDS and llm).
func RecordScan(ctx context.Context, engine, outcome string, elapsed time.Duration) {
	attrs := metric.WithAttributes(
		attribute.String("engine", engine),
		attribute.String("outcome", outcome),
	)
	scannerRequestsCounter.Add(ctx, 1, attrs)
	scannerLatencyHist.Record(ctx, float64(elapsed.Milliseconds()),
		metric.WithAttributes(attribute.String("engine", engine)))
	if outcome != "ok" {
		scannerFailuresCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("engine", engine),
			attribute.String("kind", outcome),
		))
	}
}

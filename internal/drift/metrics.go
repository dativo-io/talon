package drift

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter = otel.Meter("github.com/dativo-io/talon/internal/drift")

	once       sync.Once
	registered bool
	costZHist  metric.Float64Histogram
	denyZHist  metric.Float64Histogram
	piiZHist   metric.Float64Histogram
)

func ensureMetrics() {
	once.Do(func() {
		var err error
		costZHist, err = meter.Float64Histogram("talon.drift.cost_zscore")
		if err != nil {
			return
		}
		denyZHist, err = meter.Float64Histogram("talon.drift.denial_rate_zscore")
		if err != nil {
			return
		}
		piiZHist, err = meter.Float64Histogram("talon.drift.pii_rate_zscore")
		if err != nil {
			return
		}
		registered = true
	})
}

func RecordSignal(ctx context.Context, agentID string, signal Signal) {
	ensureMetrics()
	if !registered {
		return
	}
	attrs := metric.WithAttributes(attribute.String("agent", agentID))
	switch signal.Name {
	case "cost_anomaly":
		costZHist.Record(ctx, signal.ZScore, attrs)
	case "denial_rate_spike":
		denyZHist.Record(ctx, signal.ZScore, attrs)
	case "pii_rate_change":
		piiZHist.Record(ctx, signal.ZScore, attrs)
	}
}

package llm

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const costMeterName = "github.com/dativo-io/talon/internal/llm"

var (
	costRequestHistogram  metric.Float64Histogram
	costMetricsOnce       sync.Once
	costMetricsRegistered bool
)

func initCostMetrics() {
	meter := otel.Meter(costMeterName)
	var err error
	costRequestHistogram, err = meter.Float64Histogram(
		"talon.cost.request",
		metric.WithDescription("Cost in EUR per LLM request"),
		metric.WithUnit("eur"),
	)
	if err != nil {
		return
	}
	costMetricsRegistered = true
}

// RecordCostMetrics records cost per request after an LLM call.
// Attributes agent, model, and degraded allow filtering in observability backends.
// Daily and budget-remaining metrics would require OTel observable gauges with
// callbacks; for MVP we emit the request histogram only.
func RecordCostMetrics(ctx context.Context, costEUR float64, agent, model string, degraded bool) {
	costMetricsOnce.Do(initCostMetrics)
	if !costMetricsRegistered {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("agent", agent),
		attribute.String("model", model),
		attribute.Bool("degraded", degraded),
	)
	costRequestHistogram.Record(ctx, costEUR, attrs)
}

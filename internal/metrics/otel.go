package metrics

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var collectorMeter = otel.Meter("github.com/dativo-io/talon/internal/metrics")

var (
	mTaskSuccessTotal  metric.Int64Counter
	mTaskFailedTotal   metric.Int64Counter
	mTaskTimedOutTotal metric.Int64Counter
	mTaskDeniedTotal   metric.Int64Counter
	mCostPerSuccess    metric.Float64Histogram
	mViolationsDaily   metric.Int64Counter

	collectorMetricsOnce       sync.Once
	collectorMetricsRegistered bool
)

func initCollectorMetrics() {
	var err error

	mTaskSuccessTotal, err = collectorMeter.Int64Counter("talon.task.success.total",
		metric.WithDescription("Total successful task runs"),
		metric.WithUnit("{task}"))
	if err != nil {
		return
	}

	mTaskFailedTotal, err = collectorMeter.Int64Counter("talon.task.failed.total",
		metric.WithDescription("Total failed task runs"),
		metric.WithUnit("{task}"))
	if err != nil {
		return
	}

	mTaskTimedOutTotal, err = collectorMeter.Int64Counter("talon.task.timed_out.total",
		metric.WithDescription("Total timed out task runs"),
		metric.WithUnit("{task}"))
	if err != nil {
		return
	}

	mTaskDeniedTotal, err = collectorMeter.Int64Counter("talon.task.denied.total",
		metric.WithDescription("Total policy denied task runs"),
		metric.WithUnit("{task}"))
	if err != nil {
		return
	}

	mCostPerSuccess, err = collectorMeter.Float64Histogram("talon.task.cost_per_success",
		metric.WithDescription("Cost per successful task run"),
		metric.WithUnit("eur"))
	if err != nil {
		return
	}

	mViolationsDaily, err = collectorMeter.Int64Counter("talon.violations.daily",
		metric.WithDescription("Daily policy or tool violations"),
		metric.WithUnit("{violation}"))
	if err != nil {
		return
	}

	collectorMetricsRegistered = true
}

func ensureCollectorMetrics() {
	collectorMetricsOnce.Do(initCollectorMetrics)
}

func recordTaskOutcome(callerID, modelUsed string, denied, hasError, timedOut bool) {
	ensureCollectorMetrics()
	if !collectorMetricsRegistered {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("caller_id", callerID),
		attribute.String("model_used", modelUsed),
	)
	switch {
	case timedOut:
		mTaskTimedOutTotal.Add(context.Background(), 1, attrs)
		mTaskFailedTotal.Add(context.Background(), 1, attrs)
	case denied:
		mTaskDeniedTotal.Add(context.Background(), 1, attrs)
	case hasError:
		mTaskFailedTotal.Add(context.Background(), 1, attrs)
	default:
		mTaskSuccessTotal.Add(context.Background(), 1, attrs)
	}
}

func recordCostPerSuccess(callerID, modelUsed string, costEUR float64) {
	ensureCollectorMetrics()
	if !collectorMetricsRegistered {
		return
	}
	mCostPerSuccess.Record(context.Background(), costEUR, metric.WithAttributes(
		attribute.String("caller_id", callerID),
		attribute.String("model_used", modelUsed),
	))
}

func recordViolationDaily(dayKey, callerID string) {
	ensureCollectorMetrics()
	if !collectorMetricsRegistered {
		return
	}
	mViolationsDaily.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("date", dayKey),
		attribute.String("caller_id", callerID),
	))
}

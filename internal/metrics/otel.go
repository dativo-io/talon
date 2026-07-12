package metrics

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var collectorMeter = otel.Meter("github.com/dativo-io/talon/internal/metrics")

var (
	mTaskSuccessTotal   metric.Int64Counter
	mTaskFailedTotal    metric.Int64Counter
	mTaskTimedOutTotal  metric.Int64Counter
	mTaskDeniedTotal    metric.Int64Counter
	mCostPerSuccess     metric.Float64Histogram
	mViolationsDaily    metric.Int64Counter
	mEventsDropped      metric.Int64Counter
	mReconcileRuns      metric.Int64Counter
	mReconcileRecovered metric.Int64Counter
	mReconcileErrors    metric.Int64Counter
	mReconcileLagMS     metric.Int64Histogram

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

	mEventsDropped, err = collectorMeter.Int64Counter("talon.metrics.events_dropped.total",
		metric.WithDescription("Dropped collector events due to backpressure"),
		metric.WithUnit("{event}"))
	if err != nil {
		return
	}

	mReconcileRuns, err = collectorMeter.Int64Counter("talon.metrics.reconcile_runs.total",
		metric.WithDescription("Periodic collector reconciliation runs"),
		metric.WithUnit("{run}"))
	if err != nil {
		return
	}

	mReconcileRecovered, err = collectorMeter.Int64Counter("talon.metrics.reconcile_recovered_events.total",
		metric.WithDescription("Events recovered by reconciliation"),
		metric.WithUnit("{event}"))
	if err != nil {
		return
	}

	mReconcileErrors, err = collectorMeter.Int64Counter("talon.metrics.reconcile_errors.total",
		metric.WithDescription("Reconciliation failures"),
		metric.WithUnit("{error}"))
	if err != nil {
		return
	}

	mReconcileLagMS, err = collectorMeter.Int64Histogram("talon.metrics.reconcile_lag_ms",
		metric.WithDescription("Replay lag from latest evidence to reconciliation time"),
		metric.WithUnit("ms"))
	if err != nil {
		return
	}

	collectorMetricsRegistered = true
}

func ensureCollectorMetrics() {
	collectorMetricsOnce.Do(initCollectorMetrics)
}

func recordTaskOutcome(agentName, modelUsed string, denied, hasError, timedOut bool) {
	ensureCollectorMetrics()
	if !collectorMetricsRegistered {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("agent_name", agentName),
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

func recordCostPerSuccess(agentName, modelUsed string, costEUR float64) {
	ensureCollectorMetrics()
	if !collectorMetricsRegistered {
		return
	}
	mCostPerSuccess.Record(context.Background(), costEUR, metric.WithAttributes(
		attribute.String("agent_name", agentName),
		attribute.String("model_used", modelUsed),
	))
}

func recordViolationDaily(dayKey, agentName string) {
	ensureCollectorMetrics()
	if !collectorMetricsRegistered {
		return
	}
	mViolationsDaily.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("date", dayKey),
		attribute.String("agent_name", agentName),
	))
}

func recordCollectorEventDrop() {
	ensureCollectorMetrics()
	if !collectorMetricsRegistered {
		return
	}
	mEventsDropped.Add(context.Background(), 1)
}

func recordCollectorReconcileRun(recovered int, lag time.Duration, hadError bool) {
	ensureCollectorMetrics()
	if !collectorMetricsRegistered {
		return
	}
	mReconcileRuns.Add(context.Background(), 1)
	if recovered > 0 {
		mReconcileRecovered.Add(context.Background(), int64(recovered))
	}
	if lag > 0 {
		mReconcileLagMS.Record(context.Background(), lag.Milliseconds())
	}
	if hadError {
		mReconcileErrors.Add(context.Background(), 1)
	}
}

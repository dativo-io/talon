package llm

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const llmMeterName = "github.com/dativo-io/talon/internal/llm"

var (
	costRequestHistogram        metric.Float64Histogram
	tokenUsageHistogram         metric.Int64Histogram
	operationDurationHistogram  metric.Float64Histogram
	timeToFirstTokenHistogram   metric.Float64Histogram
	timePerOutputTokenHistogram metric.Float64Histogram
	providerAvailabilityGauge   metric.Float64Gauge
	providerFailoverCounter     metric.Int64Counter

	metricsOnce       sync.Once
	metricsRegistered bool
)

func initMetrics() {
	meter := otel.Meter(llmMeterName)
	var err error

	costRequestHistogram, err = meter.Float64Histogram(
		"talon.cost.request",
		metric.WithDescription("Cost in EUR per LLM request"),
		metric.WithUnit("eur"))
	if err != nil {
		return
	}

	tokenUsageHistogram, err = meter.Int64Histogram(
		"gen_ai.client.token.usage",
		metric.WithDescription("Token usage per LLM request"),
		metric.WithUnit("{token}"))
	if err != nil {
		return
	}

	operationDurationHistogram, err = meter.Float64Histogram(
		"gen_ai.client.operation.duration",
		metric.WithDescription("End-to-end LLM operation duration"),
		metric.WithUnit("s"))
	if err != nil {
		return
	}

	timeToFirstTokenHistogram, err = meter.Float64Histogram(
		"gen_ai.server.time_to_first_token",
		metric.WithDescription("Time from request sent to first content token received (streaming)"),
		metric.WithUnit("s"))
	if err != nil {
		return
	}

	timePerOutputTokenHistogram, err = meter.Float64Histogram(
		"gen_ai.server.time_per_output_token",
		metric.WithDescription("Time per output token after first token (streaming decode phase)"),
		metric.WithUnit("s"))
	if err != nil {
		return
	}

	providerAvailabilityGauge, err = meter.Float64Gauge(
		"talon.provider.availability",
		metric.WithDescription("Provider availability (1=available, 0=unavailable)"),
		metric.WithUnit("1"))
	if err != nil {
		return
	}

	providerFailoverCounter, err = meter.Int64Counter(
		"talon.provider.failover.total",
		metric.WithDescription("Provider failover events"),
		metric.WithUnit("{failover}"))
	if err != nil {
		return
	}

	metricsRegistered = true
}

func ensureMetrics() {
	metricsOnce.Do(initMetrics)
}

// RecordCostMetrics records cost per request after an LLM call.
func RecordCostMetrics(ctx context.Context, cost float64, agent, model string, degraded bool) {
	ensureMetrics()
	if !metricsRegistered {
		return
	}
	costRequestHistogram.Record(ctx, cost, metric.WithAttributes(
		attribute.String("agent", agent),
		attribute.String("model", model),
		attribute.Bool("degraded", degraded),
	))
}

// RecordTokenUsage records input and output token counts per GenAI SemConv.
func RecordTokenUsage(ctx context.Context, inputTokens, outputTokens int, model, system string) {
	ensureMetrics()
	if !metricsRegistered {
		return
	}
	baseAttrs := []attribute.KeyValue{
		attribute.String("gen_ai.system", system),
		attribute.String("gen_ai.request.model", model),
	}
	tokenUsageHistogram.Record(ctx, int64(inputTokens), metric.WithAttributes(
		append(baseAttrs, attribute.String("gen_ai.token.type", "input"))...,
	))
	tokenUsageHistogram.Record(ctx, int64(outputTokens), metric.WithAttributes(
		append(baseAttrs, attribute.String("gen_ai.token.type", "output"))...,
	))
}

// RecordOperationDuration records end-to-end LLM call duration per GenAI SemConv.
func RecordOperationDuration(ctx context.Context, durationSeconds float64, model, system string) {
	ensureMetrics()
	if !metricsRegistered {
		return
	}
	operationDurationHistogram.Record(ctx, durationSeconds, metric.WithAttributes(
		attribute.String("gen_ai.system", system),
		attribute.String("gen_ai.request.model", model),
	))
}

// RecordTimeToFirstToken records time to first token for streaming requests (GenAI SemConv).
func RecordTimeToFirstToken(ctx context.Context, durationSeconds float64, model, system string) {
	ensureMetrics()
	if !metricsRegistered {
		return
	}
	timeToFirstTokenHistogram.Record(ctx, durationSeconds, metric.WithAttributes(
		attribute.String("gen_ai.system", system),
		attribute.String("gen_ai.request.model", model),
	))
}

// RecordTimePerOutputToken records time per output token for streaming requests (GenAI SemConv).
func RecordTimePerOutputToken(ctx context.Context, durationSeconds float64, model, system string) {
	ensureMetrics()
	if !metricsRegistered {
		return
	}
	timePerOutputTokenHistogram.Record(ctx, durationSeconds, metric.WithAttributes(
		attribute.String("gen_ai.system", system),
		attribute.String("gen_ai.request.model", model),
	))
}

// RecordProviderAvailability sets the reactive availability gauge for a provider.
func RecordProviderAvailability(ctx context.Context, system string, available bool) {
	ensureMetrics()
	if !metricsRegistered {
		return
	}
	val := 1.0
	if !available {
		val = 0.0
	}
	providerAvailabilityGauge.Record(ctx, val, metric.WithAttributes(
		attribute.String("provider", system),
	))
}

// RecordFailover increments the failover counter when cost degradation or
// provider unavailability triggers a model switch.
func RecordFailover(ctx context.Context, originalModel, fallbackModel, reason string) {
	ensureMetrics()
	if !metricsRegistered {
		return
	}
	providerFailoverCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("original_model", originalModel),
		attribute.String("fallback_model", fallbackModel),
		attribute.String("reason", reason),
	))
}

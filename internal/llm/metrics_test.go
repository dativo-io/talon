package llm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectLLMMetrics(t *testing.T, fn func(ctx context.Context)) []metricdata.Metrics {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	m := provider.Meter("test")

	// Consume the sync.Once so that ensureMetrics() inside Record*
	// functions becomes a no-op and won't overwrite our test instruments.
	ensureMetrics()

	var err error
	costRequestHistogram, err = m.Float64Histogram("talon.cost.request")
	require.NoError(t, err)
	tokenUsageHistogram, err = m.Int64Histogram("gen_ai.client.token.usage")
	require.NoError(t, err)
	operationDurationHistogram, err = m.Float64Histogram("gen_ai.client.operation.duration")
	require.NoError(t, err)
	providerAvailabilityGauge, err = m.Float64Gauge("talon.provider.availability")
	require.NoError(t, err)
	providerFailoverCounter, err = m.Int64Counter("talon.provider.failover.total")
	require.NoError(t, err)
	metricsRegistered = true

	fn(context.Background())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	if len(rm.ScopeMetrics) == 0 {
		return nil
	}
	return rm.ScopeMetrics[0].Metrics
}

func findLLMMetric(metrics []metricdata.Metrics, name string) *metricdata.Metrics {
	for _, m := range metrics {
		if m.Name == name {
			return &m
		}
	}
	return nil
}

func TestRecordCostMetrics(t *testing.T) {
	metrics := collectLLMMetrics(t, func(ctx context.Context) {
		RecordCostMetrics(ctx, 0.05, "sales-bot", "gpt-4o", false)
		RecordCostMetrics(ctx, 0.02, "hr-bot", "claude-3", true)
	})

	m := findLLMMetric(metrics, "talon.cost.request")
	require.NotNil(t, m, "talon.cost.request not found")
	hist := m.Data.(metricdata.Histogram[float64])
	var total float64
	for _, dp := range hist.DataPoints {
		total += dp.Sum
	}
	assert.InDelta(t, 0.07, total, 0.001)
}

func TestRecordTokenUsage(t *testing.T) {
	metrics := collectLLMMetrics(t, func(ctx context.Context) {
		RecordTokenUsage(ctx, 500, 200, "gpt-4o", "openai")
	})

	m := findLLMMetric(metrics, "gen_ai.client.token.usage")
	require.NotNil(t, m, "gen_ai.client.token.usage not found")
	hist := m.Data.(metricdata.Histogram[int64])
	require.Len(t, hist.DataPoints, 2, "should have input + output data points")
}

func TestRecordOperationDuration(t *testing.T) {
	metrics := collectLLMMetrics(t, func(ctx context.Context) {
		RecordOperationDuration(ctx, 1.5, "gpt-4o", "openai")
		RecordOperationDuration(ctx, 2.3, "claude-3", "anthropic")
	})

	m := findLLMMetric(metrics, "gen_ai.client.operation.duration")
	require.NotNil(t, m, "gen_ai.client.operation.duration not found")
	hist := m.Data.(metricdata.Histogram[float64])
	var total float64
	for _, dp := range hist.DataPoints {
		total += dp.Sum
	}
	assert.InDelta(t, 3.8, total, 0.01)
}

func TestRecordProviderAvailability(t *testing.T) {
	metrics := collectLLMMetrics(t, func(ctx context.Context) {
		RecordProviderAvailability(ctx, "openai", true)
		RecordProviderAvailability(ctx, "ollama", false)
	})

	m := findLLMMetric(metrics, "talon.provider.availability")
	require.NotNil(t, m, "talon.provider.availability not found")
	gauge := m.Data.(metricdata.Gauge[float64])
	require.Len(t, gauge.DataPoints, 2)
}

func TestRecordFailover(t *testing.T) {
	metrics := collectLLMMetrics(t, func(ctx context.Context) {
		RecordFailover(ctx, "gpt-4o", "gpt-4o-mini", "cost_degradation")
	})

	m := findLLMMetric(metrics, "talon.provider.failover.total")
	require.NotNil(t, m, "talon.provider.failover.total not found")
	sum := m.Data.(metricdata.Sum[int64])
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1), sum.DataPoints[0].Value)
}

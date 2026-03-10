package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectMemoryMetrics(t *testing.T, fn func(ctx context.Context)) []metricdata.Metrics {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	meter = provider.Meter("test")

	var err error
	poisoningBlocked, err = meter.Int64Counter("talon.memory.poisoning.blocked")
	require.NoError(t, err)
	writesTotal, err = meter.Int64Counter("memory.writes.total")
	require.NoError(t, err)
	writesDenied, err = meter.Int64Counter("memory.writes.denied")
	require.NoError(t, err)
	dedupSkips, err = meter.Int64Counter("memory.dedup.skips")
	require.NoError(t, err)

	fn(context.Background())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	if len(rm.ScopeMetrics) == 0 {
		return nil
	}
	return rm.ScopeMetrics[0].Metrics
}

func findMemoryMetric(metrics []metricdata.Metrics, name string) *metricdata.Metrics {
	for _, m := range metrics {
		if m.Name == name {
			return &m
		}
	}
	return nil
}

func TestRecordPoisoningBlocked(t *testing.T) {
	metrics := collectMemoryMetrics(t, func(ctx context.Context) {
		RecordPoisoningBlocked(ctx)
		RecordPoisoningBlocked(ctx)
	})

	m := findMemoryMetric(metrics, "talon.memory.poisoning.blocked")
	require.NotNil(t, m, "talon.memory.poisoning.blocked not found")
	sum := m.Data.(metricdata.Sum[int64])
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	assert.Equal(t, int64(2), total)
}

func TestDedupSkipsAdd(t *testing.T) {
	metrics := collectMemoryMetrics(t, func(ctx context.Context) {
		DedupSkipsAdd(ctx, 3)
		DedupSkipsAdd(ctx, 2)
	})

	m := findMemoryMetric(metrics, "memory.dedup.skips")
	require.NotNil(t, m, "memory.dedup.skips not found")
	sum := m.Data.(metricdata.Sum[int64])
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	assert.Equal(t, int64(5), total)
}

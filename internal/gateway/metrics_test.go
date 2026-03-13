package gateway

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectGatewayMetrics(t *testing.T, fn func(ctx context.Context)) []metricdata.Metrics {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	gatewayMeter = provider.Meter("test")

	var err error
	gatewayRequestsCounter, err = gatewayMeter.Int64Counter("talon.gateway.requests.total")
	require.NoError(t, err)
	gatewayErrorsCounter, err = gatewayMeter.Int64Counter("talon.gateway.errors.total")
	require.NoError(t, err)
	dataTierCounter, err = gatewayMeter.Int64Counter("talon.data_tier.requests")
	require.NoError(t, err)
	toolGovernanceCounter, err = gatewayMeter.Int64Counter("talon.tools.governance.total")
	require.NoError(t, err)
	cacheHitsCounter, err = gatewayMeter.Int64Counter("talon.cache.hits")
	require.NoError(t, err)
	cacheMissesCounter, err = gatewayMeter.Int64Counter("talon.cache.misses")
	require.NoError(t, err)
	shadowViolationsCounter, err = gatewayMeter.Int64Counter("talon.shadow.violations.total")
	require.NoError(t, err)
	budgetUtilizationGauge, err = gatewayMeter.Float64Gauge("talon.budget.utilization")
	require.NoError(t, err)
	budgetAlertsCounter, err = gatewayMeter.Int64Counter("talon.budget.alerts.total")
	require.NoError(t, err)
	gwMetricsRegistered = true

	fn(context.Background())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	if len(rm.ScopeMetrics) == 0 {
		return nil
	}
	return rm.ScopeMetrics[0].Metrics
}

func findMetric(metrics []metricdata.Metrics, name string) *metricdata.Metrics {
	for _, m := range metrics {
		if m.Name == name {
			return &m
		}
	}
	return nil
}

func TestRecordGatewayRequest(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordGatewayRequest(ctx, "app-1", "gpt-4o", "openai", "ok")
		RecordGatewayRequest(ctx, "app-2", "claude-3", "anthropic", "blocked")
	})

	m := findMetric(metrics, "talon.gateway.requests.total")
	require.NotNil(t, m, "talon.gateway.requests.total not found")
	sum := m.Data.(metricdata.Sum[int64])
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	assert.Equal(t, int64(2), total)
}

func TestRecordGatewayError(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordGatewayError(ctx, "upstream_timeout")
		RecordGatewayError(ctx, "rate_limit")
		RecordGatewayError(ctx, "upstream_timeout")
	})

	m := findMetric(metrics, "talon.gateway.errors.total")
	require.NotNil(t, m)
	sum := m.Data.(metricdata.Sum[int64])
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	assert.Equal(t, int64(3), total)
}

func TestRecordDataTier(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordDataTier(ctx, 0, "app-1")
		RecordDataTier(ctx, 2, "app-1")
	})

	m := findMetric(metrics, "talon.data_tier.requests")
	require.NotNil(t, m)
	sum := m.Data.(metricdata.Sum[int64])
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	assert.Equal(t, int64(2), total)
}

func TestRecordToolGovernance(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordToolGovernance(ctx, "read_file", "allowed")
		RecordToolGovernance(ctx, "exec_cmd", "filtered")
		RecordToolGovernance(ctx, "exec_cmd", "filtered")
	})

	m := findMetric(metrics, "talon.tools.governance.total")
	require.NotNil(t, m)
	sum := m.Data.(metricdata.Sum[int64])
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	assert.Equal(t, int64(3), total)
}

func TestRecordCacheResult_Hit(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordCacheResult(ctx, "tenant-1", true)
	})

	m := findMetric(metrics, "talon.cache.hits")
	require.NotNil(t, m)
	sum := m.Data.(metricdata.Sum[int64])
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1), sum.DataPoints[0].Value)
}

func TestRecordCacheResult_Miss(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordCacheResult(ctx, "tenant-1", false)
	})

	m := findMetric(metrics, "talon.cache.misses")
	require.NotNil(t, m)
	sum := m.Data.(metricdata.Sum[int64])
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1), sum.DataPoints[0].Value)
}

func TestRecordShadowViolation(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordShadowViolation(ctx, "pii_block")
		RecordShadowViolation(ctx, "rate_limit")
	})

	m := findMetric(metrics, "talon.shadow.violations.total")
	require.NotNil(t, m)
	sum := m.Data.(metricdata.Sum[int64])
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	assert.Equal(t, int64(2), total)
}

func TestRecordBudgetUtilization(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordBudgetUtilization(ctx, "acme", "daily", 75.5)
	})

	m := findMetric(metrics, "talon.budget.utilization")
	require.NotNil(t, m)
	gauge := m.Data.(metricdata.Gauge[float64])
	require.Len(t, gauge.DataPoints, 1)
	assert.InDelta(t, 75.5, gauge.DataPoints[0].Value, 0.1)
}

func TestRecordBudgetAlert(t *testing.T) {
	metrics := collectGatewayMetrics(t, func(ctx context.Context) {
		RecordBudgetAlert(ctx, "acme", 90.0)
	})

	m := findMetric(metrics, "talon.budget.alerts.total")
	require.NotNil(t, m)
	sum := m.Data.(metricdata.Sum[int64])
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1), sum.DataPoints[0].Value)
}

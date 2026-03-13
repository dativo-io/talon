package policy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectPolicyMetrics(t *testing.T, fn func(ctx context.Context)) []metricdata.Metrics {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	policyMeter = provider.Meter("test")

	var err error
	evaluationsCounter, err = policyMeter.Int64Counter("talon.policy.evaluations.total")
	require.NoError(t, err)
	evaluationDuration, err = policyMeter.Float64Histogram("talon.policy.evaluation.duration")
	require.NoError(t, err)

	fn(context.Background())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	if len(rm.ScopeMetrics) == 0 {
		return nil
	}
	return rm.ScopeMetrics[0].Metrics
}

func TestRecordPolicyEvaluation_Allow(t *testing.T) {
	metrics := collectPolicyMetrics(t, func(ctx context.Context) {
		RecordPolicyEvaluation(ctx, "allow", "tenant-1", "agent-1", 5*time.Millisecond)
	})

	require.NotEmpty(t, metrics)
	var counterFound, histFound bool
	for _, m := range metrics {
		if m.Name == "talon.policy.evaluations.total" {
			counterFound = true
			sum := m.Data.(metricdata.Sum[int64])
			require.Len(t, sum.DataPoints, 1)
			assert.Equal(t, int64(1), sum.DataPoints[0].Value)
		}
		if m.Name == "talon.policy.evaluation.duration" {
			histFound = true
			hist := m.Data.(metricdata.Histogram[float64])
			require.Len(t, hist.DataPoints, 1)
			assert.Greater(t, hist.DataPoints[0].Sum, 0.0)
		}
	}
	assert.True(t, counterFound, "evaluations counter not found")
	assert.True(t, histFound, "evaluation duration histogram not found")
}

func TestRecordPolicyEvaluation_Deny(t *testing.T) {
	metrics := collectPolicyMetrics(t, func(ctx context.Context) {
		RecordPolicyEvaluation(ctx, "deny", "acme", "sales-bot", 12*time.Millisecond)
		RecordPolicyEvaluation(ctx, "deny", "acme", "sales-bot", 8*time.Millisecond)
	})

	require.NotEmpty(t, metrics)
	for _, m := range metrics {
		if m.Name == "talon.policy.evaluations.total" {
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.Equal(t, int64(2), total)
		}
	}
}

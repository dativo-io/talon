package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectSecretsMetrics(t *testing.T, fn func(ctx context.Context)) []metricdata.Metrics {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	secretsMeter = provider.Meter("test")

	var err error
	accessCounter, err = secretsMeter.Int64Counter("talon.secrets.access.total")
	require.NoError(t, err)

	fn(context.Background())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	if len(rm.ScopeMetrics) == 0 {
		return nil
	}
	return rm.ScopeMetrics[0].Metrics
}

func TestRecordSecretAccess_Allowed(t *testing.T) {
	metrics := collectSecretsMetrics(t, func(ctx context.Context) {
		RecordSecretAccess(ctx, "openai-key", "sales-agent", "allowed")
	})

	require.NotEmpty(t, metrics)
	found := false
	for _, m := range metrics {
		if m.Name == "talon.secrets.access.total" {
			found = true
			sum := m.Data.(metricdata.Sum[int64])
			require.Len(t, sum.DataPoints, 1)
			assert.Equal(t, int64(1), sum.DataPoints[0].Value)
		}
	}
	assert.True(t, found, "talon.secrets.access.total not found")
}

func TestRecordSecretAccess_Denied(t *testing.T) {
	metrics := collectSecretsMetrics(t, func(ctx context.Context) {
		RecordSecretAccess(ctx, "prod-key", "unauthorized", "denied")
		RecordSecretAccess(ctx, "prod-key", "unauthorized", "denied")
	})

	require.NotEmpty(t, metrics)
	for _, m := range metrics {
		if m.Name == "talon.secrets.access.total" {
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.Equal(t, int64(2), total)
		}
	}
}

func TestRecordSecretAccess_MixedOutcomes(t *testing.T) {
	metrics := collectSecretsMetrics(t, func(ctx context.Context) {
		RecordSecretAccess(ctx, "key-1", "agent-a", "allowed")
		RecordSecretAccess(ctx, "key-1", "agent-b", "denied")
		RecordSecretAccess(ctx, "key-2", "agent-a", "allowed")
	})

	require.NotEmpty(t, metrics)
	for _, m := range metrics {
		if m.Name == "talon.secrets.access.total" {
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.Equal(t, int64(3), total)
		}
	}
}

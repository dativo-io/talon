package classifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectClassifierMetrics(t *testing.T, fn func(ctx context.Context)) []metricdata.Metrics {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	classifierMeter = provider.Meter("test")

	var err error
	piiDetectionsCounter, err = classifierMeter.Int64Counter("talon.pii.detections.total")
	require.NoError(t, err)
	piiRedactionsCounter, err = classifierMeter.Int64Counter("talon.pii.redactions.total")
	require.NoError(t, err)

	fn(context.Background())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	if len(rm.ScopeMetrics) == 0 {
		return nil
	}
	return rm.ScopeMetrics[0].Metrics
}

func TestRecordPIIDetection(t *testing.T) {
	metrics := collectClassifierMetrics(t, func(ctx context.Context) {
		RecordPIIDetection(ctx, "email", "request", "detected")
		RecordPIIDetection(ctx, "iban", "request", "detected")
		RecordPIIDetection(ctx, "email", "response", "detected")
	})

	require.NotEmpty(t, metrics)
	found := false
	for _, m := range metrics {
		if m.Name == "talon.pii.detections.total" {
			found = true
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.Equal(t, int64(3), total)
		}
	}
	assert.True(t, found, "talon.pii.detections.total not found")
}

func TestRecordPIIRedaction(t *testing.T) {
	metrics := collectClassifierMetrics(t, func(ctx context.Context) {
		RecordPIIRedaction(ctx, "email", "request")
		RecordPIIRedaction(ctx, "phone", "request")
	})

	require.NotEmpty(t, metrics)
	found := false
	for _, m := range metrics {
		if m.Name == "talon.pii.redactions.total" {
			found = true
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.Equal(t, int64(2), total)
		}
	}
	assert.True(t, found, "talon.pii.redactions.total not found")
}

func TestPIIDetectionWiredInScan(t *testing.T) {
	scanner := MustNewScanner()
	metrics := collectClassifierMetrics(t, func(ctx context.Context) {
		result := scanner.Scan(ctx, "Contact me at user@example.com")
		require.True(t, result.HasPII)
	})

	require.NotEmpty(t, metrics)
	for _, m := range metrics {
		if m.Name == "talon.pii.detections.total" {
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.GreaterOrEqual(t, total, int64(1), "scan should emit at least 1 PII detection")
		}
	}
}

func TestPIIRedactionWiredInRedact(t *testing.T) {
	scanner := MustNewScanner()
	metrics := collectClassifierMetrics(t, func(ctx context.Context) {
		result := scanner.Redact(ctx, "My email is test@company.eu")
		assert.Contains(t, result, "[EMAIL]")
	})

	require.NotEmpty(t, metrics)
	for _, m := range metrics {
		if m.Name == "talon.pii.redactions.total" {
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.GreaterOrEqual(t, total, int64(1), "redact should emit at least 1 redaction")
		}
	}
}

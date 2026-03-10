package evidence

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collectEvidenceMetrics(t *testing.T, fn func(ctx context.Context)) []metricdata.Metrics {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	evidenceMeter = provider.Meter("test")

	var err error
	recordsCounter, err = evidenceMeter.Int64Counter("talon.evidence.records.total")
	require.NoError(t, err)
	verificationCounter, err = evidenceMeter.Int64Counter("talon.evidence.signature_verifications")
	require.NoError(t, err)

	fn(context.Background())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	if len(rm.ScopeMetrics) == 0 {
		return nil
	}
	return rm.ScopeMetrics[0].Metrics
}

func TestRecordEvidenceStored(t *testing.T) {
	metrics := collectEvidenceMetrics(t, func(ctx context.Context) {
		RecordEvidenceStored(ctx, "gateway")
		RecordEvidenceStored(ctx, "agent")
		RecordEvidenceStored(ctx, "gateway")
	})

	require.NotEmpty(t, metrics)
	found := false
	for _, m := range metrics {
		if m.Name == "talon.evidence.records.total" {
			found = true
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.Equal(t, int64(3), total)
		}
	}
	assert.True(t, found, "talon.evidence.records.total not found")
}

func TestRecordSignatureVerification(t *testing.T) {
	metrics := collectEvidenceMetrics(t, func(ctx context.Context) {
		RecordSignatureVerification(ctx, true)
		RecordSignatureVerification(ctx, false)
		RecordSignatureVerification(ctx, true)
	})

	require.NotEmpty(t, metrics)
	found := false
	for _, m := range metrics {
		if m.Name == "talon.evidence.signature_verifications" {
			found = true
			sum := m.Data.(metricdata.Sum[int64])
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			assert.Equal(t, int64(3), total)
		}
	}
	assert.True(t, found, "talon.evidence.signature_verifications not found")
}

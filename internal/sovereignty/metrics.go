package sovereignty

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var sovereigntyMeter = otel.Meter("github.com/dativo-io/talon/internal/sovereignty")

var (
	providerExcludedCounter metric.Int64Counter

	sovMetricsOnce       sync.Once
	sovMetricsRegistered bool
)

func initSovereigntyMetrics() {
	var err error

	providerExcludedCounter, err = sovereigntyMeter.Int64Counter("talon.sovereignty.provider_excluded_total",
		metric.WithDescription("Declared providers excluded at startup under eu_strict"),
		metric.WithUnit("{provider}"))
	if err != nil {
		return
	}

	sovMetricsRegistered = true
}

// RecordProviderExcluded increments the startup exclusion counter.
func RecordProviderExcluded(ctx context.Context, provider, scope string) {
	sovMetricsOnce.Do(initSovereigntyMetrics)
	if !sovMetricsRegistered {
		return
	}
	providerExcludedCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("provider", provider),
			attribute.String("scope", scope),
		))
}

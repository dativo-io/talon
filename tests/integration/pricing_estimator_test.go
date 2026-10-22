//go:build integration

package integration

import (
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/pricing"
)

// realPricingEstimator is the production estimator over the embedded
// pricing catalog, exactly what `talon serve` wires: integration fixtures
// never fake pricing, so a provider or model outside the catalog is denied
// pricing_unavailable in these tests just as it is in production.
func realPricingEstimator() gateway.CostEstimator {
	return gateway.PricingTableEstimator(pricing.LoadOrDefault(""))
}

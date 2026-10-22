package server

import "github.com/dativo-io/talon/internal/gateway"

// serverTestEstimator is a table-known flat estimator: the gateway denies a
// capped request on an unpriced model (pricing_unavailable), and the
// organization baseline always binds a cap, so black-box fixtures price
// every model as if it were in the shipped table.
func serverTestEstimator(_, _ string, usage gateway.Usage) gateway.CostResult {
	n := float64(usage.Input+usage.CacheRead+usage.CacheWrite+usage.Output) / 1000
	return gateway.CostResult{Amount: n * 0.002, PricingKnown: true, PricingBasis: gateway.PricingBasisTable}
}

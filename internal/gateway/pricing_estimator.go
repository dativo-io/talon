package gateway

import "github.com/dativo-io/talon/internal/pricing"

// PricingTableEstimator prices a gateway request against the routed
// provider's entry in the operator's pricing table, cache-aware (#196). It
// is THE production estimator (`talon serve`) and what black-box tests wire
// so pricing semantics are never faked: a provider or model absent from the
// table is reported PricingKnown=false with a flat default amount, which a
// capped request turns into a pricing_unavailable denial (decidePreDispatch);
// a provider declared `models: {}` is known and free.
func PricingTableEstimator(table *pricing.PricingTable) CostEstimator {
	return func(provider, model string, usage Usage) CostResult {
		cost, known, cacheFallback := table.EstimateCached(provider, model, usage.Input, usage.CacheRead, usage.CacheWrite, usage.Output)
		if !known {
			r := defaultCostEstimator(provider, model, usage)
			return r
		}
		basis := PricingBasisTable
		if cacheFallback {
			basis = PricingBasisCacheFalling
		}
		return CostResult{Amount: cost, PricingKnown: true, PricingBasis: basis}
	}
}

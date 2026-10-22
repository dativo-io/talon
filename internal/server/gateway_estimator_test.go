package server

import (
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/pricing"
)

// serverTestEstimator is the production estimator over the embedded pricing
// catalog: black-box fixtures price exactly as `talon serve` does, so a
// provider or model the catalog does not know is denied pricing_unavailable
// here too — never a faked "known".
var serverTestEstimator = gateway.PricingTableEstimator(pricing.LoadOrDefault(""))

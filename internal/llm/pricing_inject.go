package llm

import (
	"github.com/dativo-io/talon/internal/pricing"
)

// PricingAware is implemented by providers that support config-driven cost estimation.
// SetPricing injects the loaded pricing table; called at startup after buildProviders.
type PricingAware interface {
	SetPricing(pt *pricing.PricingTable)
}

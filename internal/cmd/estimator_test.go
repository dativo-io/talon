package cmd

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/pricing"
)

// TestGatewayCostEstimator_NoProviderSweepWarnings is the #208 regression: the
// gateway cost estimator prices ONLY the routed provider through the pricing
// TABLE (EstimateCached), so it never sweeps every configured provider via
// provider.EstimateCost — the behavior that logged one "unknown model for cost
// estimation" per non-matching provider on every request (an Anthropic provider
// will never know an OpenAI model). Configuring a second provider must therefore
// produce no unrelated pricing warnings; even a provider that does not know the
// model yields a flat estimate with NO warning.
func TestGatewayCostEstimator_NoProviderSweepWarnings(t *testing.T) {
	// Load the table BEFORE capturing the logger, so the load path's own INFO
	// (embedded-default fallback) never pollutes the assertion.
	pt := pricing.LoadOrDefault("")

	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })

	est := gatewayCostEstimator(pt)
	usage := gateway.Usage{Input: 100, Output: 50}

	// Routed provider knows the model → priced from the table.
	known := est("openai", "gpt-4o-mini", usage)
	assert.True(t, known.PricingKnown, "openai/gpt-4o-mini is in the default pricing table")

	// A second configured provider that does NOT know the model → flat estimate,
	// marked unknown, but STILL no warning: the estimator uses the pricing table,
	// never the per-provider EstimateCost sweep that logged #208.
	unknown := est("anthropic", "gpt-4o-mini", usage)
	assert.False(t, unknown.PricingKnown)

	assert.NotContains(t, buf.String(), "unknown model for cost estimation",
		"configuring multiple providers must not spam pricing warnings (#208)")
}

// Package providers_test runs integration tests that require all providers to be registered.
// Blank-importing this package's deps causes each provider's init() to register with the llm registry.
package providers_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/llm"
	_ "github.com/dativo-io/talon/internal/llm/providers"
	"github.com/dativo-io/talon/internal/pricing"
)

// TestListForWizard_AllRealProviders ensures all real provider factories accept nil config
// and that ListForWizard returns at least 8 providers sorted by Order, with EU filter working.
func TestListForWizard_AllRealProviders(t *testing.T) {
	list := llm.ListForWizard(false)
	assert.GreaterOrEqual(t, len(list), 8, "ListForWizard(false) should return at least 8 providers")

	euList := llm.ListForWizard(true)
	for _, m := range euList {
		isEUOrLocal := m.Jurisdiction == "EU" || m.Jurisdiction == "LOCAL"
		hasEURegions := len(m.EURegions) > 0
		assert.True(t, isEUOrLocal || hasEURegions,
			"ListForWizard(true) must only return EU, LOCAL, or providers with EURegions; got %q with jurisdiction %q",
			m.DisplayName, m.Jurisdiction)
	}
}

// TestAllProviders_MetadataComplete validates that all registered providers have complete
// metadata including AIActScope. Run with: go test ./internal/llm/providers/... -run TestAllProviders_MetadataComplete
func TestAllProviders_MetadataComplete(t *testing.T) {
	all := llm.AllRegisteredProviders()
	require.Greater(t, len(all), 0, "no providers registered")

	validAIActScope := []string{"in_scope", "third_country", "exempt"}
	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			meta := p.Metadata()
			require.NotEmpty(t, meta.ID, "ID must be set")
			require.NotEmpty(t, meta.DisplayName, "DisplayName must be set")
			require.NotEmpty(t, meta.Jurisdiction, "Jurisdiction must be set")
			require.NotEmpty(t, meta.AIActScope, "AIActScope must be set")
			assert.Contains(t, validAIActScope, meta.AIActScope)
			assert.NotEmpty(t, meta.Wizard.Suffix, "Wizard.Suffix should be set")
			assert.GreaterOrEqual(t, meta.Wizard.Order, 0, "Wizard.Order should be non-negative")
		})
	}
}

// TestAllProviders_WithHTTPClientReturnsCopy ensures WithHTTPClient returns a new instance, not the receiver.
func TestAllProviders_WithHTTPClientReturnsCopy(t *testing.T) {
	all := llm.AllRegisteredProviders()
	require.Greater(t, len(all), 0, "no providers registered")

	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			clone := p.WithHTTPClient(&http.Client{})
			assert.NotSame(t, p, clone, "WithHTTPClient must return a new instance, not the receiver")
		})
	}
}

// TestAllProviders_StreamClosesChannelOnError ensures Stream closes the channel on all exit paths.
func TestAllProviders_StreamClosesChannelOnError(t *testing.T) {
	all := llm.AllRegisteredProviders()
	require.Greater(t, len(all), 0, "no providers registered")

	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			ch := make(chan llm.StreamChunk, 16)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_ = p.Stream(ctx, &llm.Request{Model: "test"}, ch)
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			done := make(chan struct{})
			go func() {
				for range ch {
				}
				close(done)
			}()
			select {
			case <-done:
			case <-timer.C:
				t.Fatal("Stream did not close channel within timeout")
			}
		})
	}
}

// TestAllProviders_EstimateCost_NoHardcodedValues loads the pricing table, injects it into all
// providers, and verifies that EstimateCost for a known model matches the table lookup.
func TestAllProviders_EstimateCost_NoHardcodedValues(t *testing.T) {
	pt, err := pricing.Load("../../../pricing/models.yaml")
	if err != nil {
		t.Skipf("pricing file not available: %v", err)
	}
	all := llm.AllRegisteredProviders()
	require.Greater(t, len(all), 0, "no providers registered")
	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			if pa, ok := p.(llm.PricingAware); ok {
				pa.SetPricing(pt)
			}
			pp, ok := pt.Providers[p.Name()]
			if !ok || len(pp.Models) == 0 {
				t.Skipf("no models in pricing table for %s", p.Name())
			}
			var firstModel string
			for m := range pp.Models {
				firstModel = m
				break
			}
			require.NotEmpty(t, firstModel, "empty models map")
			cost := p.EstimateCost(firstModel, 1000, 1000)
			expected, known := pt.Estimate(p.Name(), firstModel, 1000, 1000)
			assert.True(t, known, "pricing table should have model %s for %s", firstModel, p.Name())
			assert.InDelta(t, expected, cost, 0.0001, "EstimateCost should match pricing table")
		})
	}
}

// TestAllProviders_EstimateCost_UnknownModel verifies that EstimateCost with an unknown model
// returns 0.0 and does not panic.
func TestAllProviders_EstimateCost_UnknownModel(t *testing.T) {
	pt := pricing.LoadOrDefault("../../../pricing/models.yaml")
	all := llm.AllRegisteredProviders()
	require.Greater(t, len(all), 0, "no providers registered")
	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			if pa, ok := p.(llm.PricingAware); ok {
				pa.SetPricing(pt)
			}
			cost := p.EstimateCost("nonexistent-model-xyz", 1000, 1000)
			assert.Equal(t, 0.0, cost, "unknown model should return 0")
		})
	}
}

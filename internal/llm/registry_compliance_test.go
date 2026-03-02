package llm

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllProviders_MetadataComplete validates that all registered providers
// have complete metadata and consistent WizardHint. Run after providers are
// registered (e.g. via blank import of internal/llm/providers).
func TestAllProviders_MetadataComplete(t *testing.T) {
	all := AllRegisteredProviders()
	if len(all) == 0 {
		t.Skip("no providers registered (e.g. providers package not imported)")
	}

	validAIActScope := []string{"in_scope", "third_country", "exempt"}
	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			meta := p.Metadata()
			require.NotEmpty(t, meta.ID, "ID must be set")
			require.NotEmpty(t, meta.DisplayName, "DisplayName must be set")
			require.NotEmpty(t, meta.Jurisdiction, "Jurisdiction must be set")
			require.NotEmpty(t, meta.AIActScope, "AIActScope must be set")
			assert.Contains(t, validAIActScope, meta.AIActScope, "AIActScope must be one of in_scope, third_country, exempt")
			assert.NotEmpty(t, meta.Wizard.Suffix, "Wizard.Suffix should be set for wizard display")
			assert.GreaterOrEqual(t, meta.Wizard.Order, 0, "Wizard.Order should be non-negative")
		})
	}
}

// TestAllProviders_WithHTTPClientReturnsCopy ensures every provider's WithHTTPClient
// returns a new instance (copy), not the receiver, to prevent accidental mutation.
func TestAllProviders_WithHTTPClientReturnsCopy(t *testing.T) {
	all := AllRegisteredProviders()
	if len(all) == 0 {
		t.Skip("no providers registered (e.g. providers package not imported)")
	}

	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			clone := p.WithHTTPClient(&http.Client{})
			assert.NotSame(t, p, clone, "WithHTTPClient must return a new instance, not the receiver")
		})
	}
}

// TestAllProviders_StreamClosesChannelOnError ensures every provider that implements
// Stream closes the channel on all exit paths (success or error) to avoid goroutine leaks.
func TestAllProviders_StreamClosesChannelOnError(t *testing.T) {
	all := AllRegisteredProviders()
	if len(all) == 0 {
		t.Skip("no providers registered (e.g. providers package not imported)")
	}

	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			ch := make(chan StreamChunk, 16)
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // immediately cancelled context forces error path
			_ = p.Stream(ctx, &Request{Model: "test"}, ch)
			// Channel must be closed — ranging must terminate
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
				// ok
			case <-timer.C:
				t.Fatal("Stream did not close channel within timeout")
			}
		})
	}
}

package llm

import (
	"testing"

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

	for _, p := range all {
		t.Run(p.Name(), func(t *testing.T) {
			meta := p.Metadata()
			require.NotEmpty(t, meta.ID, "ID must be set")
			require.NotEmpty(t, meta.DisplayName, "DisplayName must be set")
			require.NotEmpty(t, meta.Jurisdiction, "Jurisdiction must be set")
			assert.NotEmpty(t, meta.Wizard.Suffix, "Wizard.Suffix should be set for wizard display")
			assert.GreaterOrEqual(t, meta.Wizard.Order, 0, "Wizard.Order should be non-negative")
		})
	}
}

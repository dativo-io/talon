package llm

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testMockProvider implements Provider for registry tests without real backends.
type testMockProvider struct {
	meta   ProviderMetadata
	client *http.Client
}

func (p *testMockProvider) Name() string               { return p.meta.ID }
func (p *testMockProvider) Metadata() ProviderMetadata { return p.meta }
func (p *testMockProvider) Generate(context.Context, *Request) (*Response, error) {
	return &Response{Content: "ok", Model: "test"}, nil
}

func (p *testMockProvider) Stream(context.Context, *Request, chan<- StreamChunk) error {
	return ErrNotImplemented
}
func (p *testMockProvider) EstimateCost(string, int, int) float64 { return 0 }
func (p *testMockProvider) ValidateConfig() error                 { return nil }
func (p *testMockProvider) HealthCheck(context.Context) error     { return nil }
func (p *testMockProvider) WithHTTPClient(c *http.Client) Provider {
	return &testMockProvider{meta: p.meta, client: c}
}

func testMockFactory(meta ProviderMetadata) ProviderFactory {
	return func(configYAML []byte) (Provider, error) {
		return &testMockProvider{meta: meta}, nil
	}
}

func TestRegister_DuplicatePanics(t *testing.T) {
	resetRegistryForTest()
	f := testMockFactory(ProviderMetadata{ID: "dup", DisplayName: "Dup", Wizard: WizardHint{Order: 1}})
	Register("dup", f)
	defer resetRegistryForTest()

	var panicked bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				assert.Contains(t, r, "already registered")
				assert.Contains(t, r, "dup")
			}
		}()
		Register("dup", f)
	}()
	assert.True(t, panicked, "second Register must panic")
}

func TestNewProvider_UnknownType(t *testing.T) {
	resetRegistryForTest()
	defer resetRegistryForTest()

	_, err := NewProvider("unknown-provider", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider type")
	assert.Contains(t, err.Error(), "unknown-provider")
}

func TestListForWizard_SortOrder(t *testing.T) {
	resetRegistryForTest()
	defer resetRegistryForTest()

	Register("b", testMockFactory(ProviderMetadata{
		ID: "b", DisplayName: "B", Jurisdiction: "US",
		Wizard: WizardHint{Order: 20},
	}))
	Register("a", testMockFactory(ProviderMetadata{
		ID: "a", DisplayName: "A", Jurisdiction: "EU",
		Wizard: WizardHint{Order: 10},
	}))

	list := ListForWizard(false)
	require.Len(t, list, 2)
	assert.Equal(t, "A", list[0].DisplayName)
	assert.Equal(t, 10, list[0].Wizard.Order)
	assert.Equal(t, "B", list[1].DisplayName)
	assert.Equal(t, 20, list[1].Wizard.Order)
}

func TestListForWizard_EUFilter(t *testing.T) {
	resetRegistryForTest()
	defer resetRegistryForTest()

	Register("us-only", testMockFactory(ProviderMetadata{
		ID: "us-only", DisplayName: "US Only", Jurisdiction: "US",
		EURegions: nil,
		Wizard:    WizardHint{Order: 1},
	}))

	list := ListForWizard(true) // euStrictFilter: exclude non-EU with no EU regions
	assert.Empty(t, list)

	list = ListForWizard(false)
	require.Len(t, list, 1)
	assert.Equal(t, "US Only", list[0].DisplayName)
}

func TestListForWizard_HiddenExcluded(t *testing.T) {
	resetRegistryForTest()
	defer resetRegistryForTest()

	Register("visible", testMockFactory(ProviderMetadata{
		ID: "visible", DisplayName: "Visible", Wizard: WizardHint{Order: 1, Hidden: false},
	}))
	Register("hidden", testMockFactory(ProviderMetadata{
		ID: "hidden", DisplayName: "Hidden", Wizard: WizardHint{Order: 2, Hidden: true},
	}))

	list := ListForWizard(false)
	require.Len(t, list, 1)
	assert.Equal(t, "Visible", list[0].DisplayName)
}

func TestAllRegisteredProviders(t *testing.T) {
	resetRegistryForTest()
	defer resetRegistryForTest()

	Register("p1", testMockFactory(ProviderMetadata{ID: "p1", Wizard: WizardHint{Order: 1}}))
	Register("p2", testMockFactory(ProviderMetadata{ID: "p2", Wizard: WizardHint{Order: 2}}))

	all := AllRegisteredProviders()
	require.Len(t, all, 2)
	names := map[string]bool{all[0].Name(): true, all[1].Name(): true}
	assert.True(t, names["p1"])
	assert.True(t, names["p2"])
}

func TestRegisteredTypes(t *testing.T) {
	resetRegistryForTest()
	defer resetRegistryForTest()

	assert.Empty(t, RegisteredTypes())

	Register("z", testMockFactory(ProviderMetadata{}))
	Register("a", testMockFactory(ProviderMetadata{}))
	types := RegisteredTypes()
	assert.Equal(t, []string{"a", "z"}, types)
}

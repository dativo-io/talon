package scaffold

import "github.com/dativo-io/talon/internal/llm"

func scaffoldMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:            "scaffold",      // TODO: Your provider ID (e.g. "myprovider")
		DisplayName:   "Scaffold",      // TODO: Human-readable name
		Jurisdiction:  "US",            // TODO: EU | US | CN | CA | LOCAL
		DPAAvailable:  false,           // TODO: Data Processing Agreement available?
		EURegions:     []string{},      // TODO: e.g. []string{"westeurope"} if applicable
		GDPRCompliant: false,           // TODO: true if verified
		AIActScope:    "third_country", // TODO: in_scope | third_country | exempt
		DataRetention: "TODO",          // TODO: Human-readable summary; cite source URL
		SOC2:          false,
		ISO27001:      false,
		Wizard: llm.WizardHint{
			Suffix:           "TODO: Short annotation for wizard", // e.g. "EU regions available"
			SuggestEUStrict:  false,
			Order:            100,
			Hidden:           false,
			RequiresRegion:   false,
			AvailableRegions: []llm.WizardRegion{}, // TODO: if RequiresRegion, list regions
		},
	}
}

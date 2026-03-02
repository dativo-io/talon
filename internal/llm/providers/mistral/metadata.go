package mistral

import "github.com/dativo-io/talon/internal/llm"

func mistralMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:            "mistral",
		DisplayName:   "Mistral AI",
		Jurisdiction:  "EU",
		DPAAvailable:  true,
		GDPRCompliant: true,
		Wizard: llm.WizardHint{
			Suffix:          "★ French company — EU jurisdiction by default",
			SuggestEUStrict: true,
			Order:           50,
		},
	}
}

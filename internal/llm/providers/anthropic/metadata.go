package anthropic

import "github.com/dativo-io/talon/internal/llm"

func anthropicMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:            "anthropic",
		DisplayName:   "Anthropic",
		Jurisdiction:  "US",
		DPAAvailable:  true,
		GDPRCompliant: false,
		Wizard: llm.WizardHint{
			Suffix:          "Direct API — US jurisdiction",
			SuggestEUStrict: false,
			Order:           20,
		},
	}
}

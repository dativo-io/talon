package openai

import "github.com/dativo-io/talon/internal/llm"

func openaiMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:            "openai",
		DisplayName:   "OpenAI",
		Jurisdiction:  "US",
		AIActScope:    "in_scope",
		DPAAvailable:  true,
		GDPRCompliant: true,
		Wizard: llm.WizardHint{
			Suffix:          "Direct API — US jurisdiction",
			SuggestEUStrict: false,
			Order:           10,
		},
	}
}

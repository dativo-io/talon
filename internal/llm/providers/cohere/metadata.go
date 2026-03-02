package cohere

import "github.com/dativo-io/talon/internal/llm"

func cohereMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:           "cohere",
		DisplayName:  "Cohere",
		Jurisdiction: "CA",
		AIActScope:   "third_country",
		DPAAvailable: false,
		Wizard: llm.WizardHint{
			Suffix:          "Canadian company",
			SuggestEUStrict: false,
			Order:           90,
		},
	}
}

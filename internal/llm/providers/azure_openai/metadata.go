package azure_openai

import "github.com/dativo-io/talon/internal/llm"

func azureOpenAIMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:            "azure-openai",
		DisplayName:   "Azure OpenAI",
		Jurisdiction:  "EU",
		DPAAvailable:  true,
		GDPRCompliant: true,
		ISO27001:      true,
		SOC2:          true,
		EURegions:     []string{"westeurope", "swedencentral", "francecentral", "uksouth"},
		Wizard: llm.WizardHint{
			Suffix:          "★ EU data residency — recommended for GDPR strict",
			SuggestEUStrict: true,
			Order:           30,
			RequiresRegion:  true,
			AvailableRegions: []llm.WizardRegion{
				{ID: "westeurope", DisplayName: "West Europe (Netherlands)", IsEU: true},
				{ID: "swedencentral", DisplayName: "Sweden Central", IsEU: true},
				{ID: "francecentral", DisplayName: "France Central", IsEU: true},
				{ID: "uksouth", DisplayName: "UK South", IsEU: true},
				{ID: "eastus", DisplayName: "East US", IsEU: false},
			},
		},
	}
}

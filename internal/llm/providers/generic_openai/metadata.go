package generic_openai

import "github.com/dativo-io/talon/internal/llm"

func genericOpenAIMetadata(jurisdiction string) llm.ProviderMetadata {
	if jurisdiction == "" {
		jurisdiction = "US"
	}
	return llm.ProviderMetadata{
		ID:           "generic-openai",
		DisplayName:  "Generic OpenAI-compatible",
		Jurisdiction: jurisdiction,
		Wizard: llm.WizardHint{
			Suffix: "User-declared jurisdiction",
			Order:  100,
		},
	}
}

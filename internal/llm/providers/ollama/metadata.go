package ollama

import "github.com/dativo-io/talon/internal/llm"

func ollamaMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:            "ollama",
		DisplayName:   "Ollama",
		Jurisdiction:  "LOCAL",
		AIActScope:    "exempt",
		DPAAvailable:  false,
		GDPRCompliant: true,
		Wizard: llm.WizardHint{
			Suffix:          "★ Local / on-premises — data never leaves your machine",
			SuggestEUStrict: true,
			Order:           60,
		},
	}
}

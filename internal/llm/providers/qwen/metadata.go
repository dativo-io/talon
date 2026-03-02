package qwen

import "github.com/dativo-io/talon/internal/llm"

func qwenMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:            "qwen",
		DisplayName:   "Qwen (Alibaba Cloud)",
		Jurisdiction:  "CN",
		DPAAvailable:  false,
		GDPRCompliant: false,
		Wizard: llm.WizardHint{
			Suffix:          "(CN jurisdiction — blocked in EU strict mode)",
			SuggestEUStrict: false,
			Order:           80,
		},
	}
}

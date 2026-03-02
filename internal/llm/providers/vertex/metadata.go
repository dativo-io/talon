package vertex

import "github.com/dativo-io/talon/internal/llm"

func vertexMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:           "vertex",
		DisplayName:  "Google Vertex AI",
		Jurisdiction: "US",
		EURegions:    []string{"europe-west1", "europe-west4", "europe-west9"},
		Wizard: llm.WizardHint{
			Suffix:          "EU regions available",
			SuggestEUStrict: true,
			Order:           70,
			RequiresRegion:  true,
			AvailableRegions: []llm.WizardRegion{
				{ID: "europe-west1", DisplayName: "EU (Belgium)", IsEU: true},
				{ID: "europe-west4", DisplayName: "EU (Netherlands)", IsEU: true},
				{ID: "europe-west9", DisplayName: "EU (Paris)", IsEU: true},
				{ID: "us-central1", DisplayName: "US Central", IsEU: false},
			},
		},
	}
}

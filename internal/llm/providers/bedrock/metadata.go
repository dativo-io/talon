package bedrock

import "github.com/dativo-io/talon/internal/llm"

func bedrockMetadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{
		ID:            "bedrock",
		DisplayName:   "AWS Bedrock",
		Jurisdiction:  "US",
		AIActScope:    "in_scope",
		DPAAvailable:  true,
		EURegions:     []string{"eu-central-1", "eu-west-1", "eu-west-3"},
		GDPRCompliant: false,
		Wizard: llm.WizardHint{
			Suffix:          "EU regions available - use for data sovereignty",
			SuggestEUStrict: true,
			Order:           40,
			RequiresRegion:  true,
			AvailableRegions: []llm.WizardRegion{
				{ID: "eu-central-1", DisplayName: "EU (Frankfurt)", IsEU: true},
				{ID: "eu-west-1", DisplayName: "EU (Dublin)", IsEU: true},
				{ID: "eu-west-3", DisplayName: "EU (Paris)", IsEU: true},
				{ID: "us-east-1", DisplayName: "US East (N. Virginia)", IsEU: false},
			},
		},
	}
}

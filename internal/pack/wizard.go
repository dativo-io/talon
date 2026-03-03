// Package pack provides the pack (framework) registry for the talon init wizard.
// Packs are starter templates targeting specific AI frameworks (OpenClaw, LangChain, etc.).
// The wizard calls ListForWizard() to populate the framework selection screen.
// Community packs can be registered via RegisterPack() from init() functions.
package pack

import "sort"

// PackDescriptor describes a starter pack shown in the talon init wizard.
//
//nolint:revive // exported name is clear at call site (pack.PackDescriptor)
type PackDescriptor struct {
	ID          string // matches --pack flag value and template directory name
	DisplayName string
	Description string // one line, <=80 chars
	Order       int    // sort position in wizard list; lower = earlier
	Hidden      bool   // when true, excluded from wizard (e.g. deferred packs)
}

var builtinPacks = []PackDescriptor{
	{
		ID:          "openclaw",
		DisplayName: "OpenClaw",
		Description: "Full governance — memory, soul, skill protection, credential scanning",
		Order:       10,
	},
	{
		// n8n pack deferred to post-v0.2 (requires workflow-node-level interception).
		ID:          "n8n",
		DisplayName: "n8n",
		Description: "Workflow governance — audit all node executions and data flows",
		Order:       20,
		Hidden:      true,
	},
	{
		// Flowise pack deferred to post-v0.2 (requires conversation-level interception).
		ID:          "flowise",
		DisplayName: "Flowise",
		Description: "Conversation audit — GDPR-compliant chat history governance",
		Order:       30,
		Hidden:      true,
	},
	{
		ID:          "langchain",
		DisplayName: "LangChain",
		Description: "Python SDK proxy — govern LangChain agents via HTTP proxy",
		Order:       40,
	},
	{
		ID:          "generic",
		DisplayName: "Custom / Generic",
		Description: "Minimal starter — no framework assumptions",
		Order:       50,
	},
}

var customPacks []PackDescriptor

// RegisterPack adds a community pack to the registry.
// Call from an init() function in the pack's package.
func RegisterPack(p PackDescriptor) {
	customPacks = append(customPacks, p)
}

// ListForWizard returns all non-hidden packs sorted by Order.
func ListForWizard() []PackDescriptor {
	all := make([]PackDescriptor, 0, len(builtinPacks)+len(customPacks))
	for _, p := range builtinPacks {
		if !p.Hidden {
			all = append(all, p)
		}
	}
	for _, p := range customPacks {
		if !p.Hidden {
			all = append(all, p)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Order != all[j].Order {
			return all[i].Order < all[j].Order
		}
		return all[i].DisplayName < all[j].DisplayName
	})
	return all
}

// ValidPackIDs returns all non-hidden pack IDs (for flag validation).
func ValidPackIDs() []string {
	packs := ListForWizard()
	ids := make([]string, len(packs))
	for i, p := range packs {
		ids[i] = p.ID
	}
	return ids
}

// FindByID looks up a pack by ID among all packs (including hidden).
func FindByID(id string) (PackDescriptor, bool) {
	for _, p := range builtinPacks {
		if p.ID == id {
			return p, true
		}
	}
	for _, p := range customPacks {
		if p.ID == id {
			return p, true
		}
	}
	return PackDescriptor{}, false
}

// resetForTest clears custom packs. For tests only.
func resetForTest() {
	customPacks = nil
}

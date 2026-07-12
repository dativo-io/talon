// Package pack provides the pack (framework) registry for the talon init wizard.
// Packs are starter templates targeting specific AI frameworks (OpenClaw, LangChain, etc.).
// The wizard calls ListForWizard() to populate the framework selection screen.
// Community packs can be registered via RegisterPack() from init() functions.
package pack

import (
	"embed"
	"sort"
)

//go:embed all:templates
var templateFS embed.FS

// PackFile describes a template file to render for a pack.
//
//nolint:revive // PackFile is the established name in PROMPT_14 plan and docs
type PackFile struct {
	TemplatePath string // path in embed.FS (e.g. "templates/crewai/agent.talon.yaml")
	OutputPath   string // where to write (e.g. "agent.talon.yaml")
	Description  string // human-readable (e.g. "Agent policy")
}

// PackDescriptor describes a starter pack shown in the talon init wizard.
//
//nolint:revive // exported name is clear at call site (pack.PackDescriptor)
type PackDescriptor struct {
	ID          string // matches --pack flag value and template directory name
	DisplayName string
	Description string // one line, <=80 chars
	Order       int    // sort position in wizard list; lower = earlier
	Hidden      bool   // when true, excluded from wizard (e.g. deferred packs)

	// Optional: when set, init uses these instead of legacy pack_<id> templates.
	Framework   string     // target AI framework (e.g. "LangChain", "CrewAI", "Any")
	Files       []PackFile // template files to render
	PostMessage string     // printed after init completes
}

// Post-init message for CrewAI pack.
const crewaiPostInit = `
Talon initialized for CrewAI! Next steps:

  1. Set your secrets key:
     export TALON_SECRETS_KEY=$(openssl rand -hex 32)

  2. Store your OpenAI API key:
     talon secrets set openai-api-key sk-your-key-here

  3. Store caller keys (one per crew agent; use the api_key value as secret):
     talon secrets set langchain-app-api-key talon-gw-crew-researcher
     (Repeat for writer and reviewer if you use separate keys.)

  4. Start the gateway:
     talon serve --gateway

  5. Point CrewAI at Talon (e.g. in your Python env):
     OPENAI_API_BASE=http://localhost:8080/v1/proxy/openai/v1
     OPENAI_API_KEY=talon-gw-crew-researcher
     (trailing /v1 matters: the SDK appends /chat/completions, #235)

  6. Verify and monitor:
     talon doctor
     open http://localhost:8080/dashboard

  7. Enable enforcement after validation:
     talon enforce report
     talon enforce enable
`

const codingAgentsPostInit = `
Coding-agents pack scaffolded. Next steps:

  1. Set the vault key (same shell for steps 2-4):
     export TALON_SECRETS_KEY=$(openssl rand -hex 32)

  2. Store real provider keys in the vault (Talon injects them upstream;
     the coding tools only ever see their tenant keys):
     talon secrets set anthropic-api-key "sk-ant-..."
     talon secrets set openai-api-key "sk-..."

  3. Start the gateway:
     talon serve --gateway

  4. Point the tools at Talon:
     Claude Code:
       export ANTHROPIC_BASE_URL=http://localhost:8080/v1/proxy/anthropic
       export ANTHROPIC_AUTH_TOKEN=talon-gw-claude-code-001
     Codex CLI (~/.codex/config.toml profile):
       base_url = "http://localhost:8080/v1/proxy/openai/v1"
       wire_api = "responses"   # auth: tenant key talon-gw-codex-001
       (trailing /v1 matters: Codex appends /responses to base_url, #235)

  5. Watch a session:
     talon audit list --session <id>       # per-subagent rollup
     open http://localhost:8080/gateway/dashboard   # Coding Sessions panel

  6. Enforce once the shadow evidence looks right:
     talon enforce report && talon enforce enable

Notes: response_pii_action is "allow" for coding callers because any other
value buffers whole SSE streams today; max_session_cost is a SOFT cap; the
credential recognizers are traffic guards, not a secret scanner — keep
gitleaks/trufflehog in pre-commit. See docs/guides/governing-coding-agents.md.
`

var builtinPacks = []PackDescriptor{
	{
		ID:          "openclaw",
		DisplayName: "OpenClaw",
		Description: "Full governance — memory, soul, skill protection, credential recognizers",
		Order:       10,
		Framework:   "OpenClaw",
	},
	{
		ID:          "copaw",
		DisplayName: "CoPaw",
		Description: "Personal AI assistant governance — PII, cost, audit for CoPaw channels",
		Order:       15,
		Framework:   "CoPaw",
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
		Description: "Conversation audit — chat history governance with supporting controls for GDPR",
		Order:       30,
		Hidden:      true,
	},
	{
		ID:          "langchain",
		DisplayName: "LangChain",
		Description: "Python SDK proxy — govern LangChain agents via HTTP proxy",
		Order:       40,
		Framework:   "LangChain",
	},
	{
		ID:          "crewai",
		DisplayName: "CrewAI",
		Description: "Multi-agent crews — one agent per role, each with its own vault-bound key",
		Order:       45,
		Framework:   "CrewAI",
		Files: []PackFile{
			{TemplatePath: "templates/crewai/agent.talon.yaml", OutputPath: "agent.talon.yaml", Description: "Agent policy (crew-researcher, primary)"},
			{TemplatePath: "templates/crewai/agents/crew-writer.talon.yaml", OutputPath: "agents/crew-writer.talon.yaml", Description: "Agent policy (crew-writer)"},
			{TemplatePath: "templates/crewai/agents/crew-reviewer.talon.yaml", OutputPath: "agents/crew-reviewer.talon.yaml", Description: "Agent policy (crew-reviewer)"},
			{TemplatePath: "templates/crewai/talon.config.yaml", OutputPath: "talon.config.yaml", Description: "Infrastructure config"},
		},
		PostMessage: crewaiPostInit,
	},
	{
		ID:          "coding-agents",
		DisplayName: "Coding Agents",
		Description: "Claude Code + Codex CLI — session budgets, subagent audit, credential recognizers",
		Order:       47,
		Framework:   "Claude Code / Codex CLI",
		Files: []PackFile{
			{TemplatePath: "templates/coding-agents/agent.talon.yaml", OutputPath: "agent.talon.yaml", Description: "Agent policy (claude-code, primary; credential recognizers)"},
			{TemplatePath: "templates/coding-agents/agents/codex.talon.yaml", OutputPath: "agents/codex.talon.yaml", Description: "Agent policy (codex)"},
			{TemplatePath: "templates/coding-agents/talon.config.yaml", OutputPath: "talon.config.yaml", Description: "Gateway config (organization baseline + providers)"},
		},
		PostMessage: codingAgentsPostInit,
	},
	{
		ID:          "generic",
		DisplayName: "Custom / Generic",
		Description: "Minimal starter — no framework assumptions",
		Order:       50,
		Framework:   "Any",
	},
	{
		ID:          "fintech-eu",
		DisplayName: "Fintech EU",
		Description: "Financial services compliance starter — DORA and GDPR defaults",
		Order:       60,
		Framework:   "Industry",
	},
	{
		ID:          "ecommerce-eu",
		DisplayName: "E-commerce EU",
		Description: "E-commerce compliance starter — GDPR-focused retail defaults",
		Order:       70,
		Framework:   "Industry",
	},
	{
		ID:          "saas-eu",
		DisplayName: "SaaS EU",
		Description: "SaaS platform compliance starter — GDPR and NIS2 defaults",
		Order:       80,
		Framework:   "Industry",
	},
	{
		ID:          "telecom-eu",
		DisplayName: "Telecom EU",
		Description: "Telecom compliance starter — NIS2 and GDPR defaults",
		Order:       90,
		Framework:   "Industry",
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

// ReadComplianceOverlay returns the content of a compliance overlay file.
// name must be one of: gdpr, nis2, dora, eu-ai-act.
func ReadComplianceOverlay(name string) ([]byte, error) {
	path := "templates/compliance/" + name + ".talon.yaml"
	return templateFS.ReadFile(path)
}

// ComplianceOverlayNames returns the list of overlay names for "all".
func ComplianceOverlayNames() []string {
	return []string{"gdpr", "nis2", "dora", "eu-ai-act"}
}

// TemplateFS returns the embedded template filesystem for pack templates.
func TemplateFS() embed.FS {
	return templateFS
}

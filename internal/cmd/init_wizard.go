// Package cmd implements the talon init interactive wizard and config builders.
//
// # WizardState → Output File Mapping
//
// agent.talon.yaml:
//
//	AgentName, AgentDescription        → agent.name, agent.description
//	OwnerEmail, Department             → metadata.owner, metadata.department
//	WorkloadType="agent"               → agent.model_tier=1, capabilities.allowed_tools=[sql_query,file_read,web_search]
//	WorkloadType="proxy"               → agent.model_tier=0, capabilities.allowed_tools=[]
//	PackID                             → base template selection (wizard builds struct directly)
//	DataSovereignty="eu_strict"        → compliance.data_residency=eu, policies.model_routing.*.location=EU region
//	DataSovereignty="eu_preferred"     → compliance.data_residency=eu
//	DataSovereignty="global"           → compliance.data_residency=any
//	EnabledFeatures contains "pii"     → policies.data_classification.{input_scan,output_scan,redact_pii}=true
//	EnabledFeatures contains "audit"  → audit.{log_level=detailed,retention_days=2555,include_prompts=false}
//	EnabledFeatures contains "cost"    → policies.cost_limits.{per_request,daily,monthly} with defaults
//	EnabledFeatures contains "injection" → attachment_handling.{mode=strict,scanning.detect_instructions=true}
//	EnabledFeatures contains "eu-ai-act" → compliance.ai_act_risk_level=limited, compliance.frameworks+=[eu-ai-act]
//	EnabledFeatures contains "dora"    → compliance.frameworks+=[dora]
//	RegionID                           → policies.model_routing tier locations when provider has region
//
// talon.config.yaml:
//
//	ProviderID, RegionID               → llm.providers.<id> block (type, config with region/key_env, enabled)
//	ProviderID                         → llm primary provider
//	DataSovereignty                    → llm.routing.data_sovereignty_mode
//	DataSovereignty="eu_strict"        → (OPA handles blocking; no blocked_providers in config)
//	AgentName                          → tenants[0].id (default tenant)
//	(always)                           → llm.pricing_file: "pricing/models.yaml"
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/doctor"
	"github.com/dativo-io/talon/internal/feature"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/pack"
	"github.com/dativo-io/talon/internal/policy"
)

// Valid EU regions from internal/policy/rego/routing.rego (valid_eu_regions).
var validEURegions = map[string]bool{
	"westeurope": true, "swedencentral": true, "francecentral": true, "uksouth": true,
	"eu-central-1": true, "eu-west-1": true, "eu-west-3": true,
	"europe-west1": true, "europe-west4": true, "europe-west9": true,
}

// WizardIO injects I/O for testability.
type WizardIO struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
}

// WizardState accumulates wizard answers.
type WizardState struct {
	AgentName        string
	AgentDescription string
	OwnerEmail       string
	Department       string
	WorkloadType     string // "agent" | "proxy" | "hybrid"
	PackID           string
	ProviderID       string
	RegionID         string
	DataSovereignty  string // "eu_strict" | "eu_preferred" | "global"
	EnabledFeatures  []string
}

// InfraYAML is the structure written to talon.config.yaml.
type InfraYAML struct {
	LLM *struct {
		PricingFile string                   `yaml:"pricing_file"`
		Providers   map[string]ProviderBlock `yaml:"providers"`
		Routing     *struct {
			DataSovereigntyMode string `yaml:"data_sovereignty_mode"`
		} `yaml:"routing"`
	} `yaml:"llm"`
	Evidence *struct {
		Type string `yaml:"type"`
		Path string `yaml:"path"`
	} `yaml:"evidence"`
	SecretsKeyEnv string        `yaml:"secrets_key_env"`
	Tenants       []TenantBlock `yaml:"tenants"`
}

// ProviderBlock is one entry in llm.providers.
type ProviderBlock struct {
	Type    string                 `yaml:"type"`
	Config  map[string]interface{} `yaml:"config"`
	Enabled bool                   `yaml:"enabled"`
}

// TenantBlock is one entry in tenants.
type TenantBlock struct {
	ID          string `yaml:"id"`
	DisplayName string `yaml:"display_name"`
	Budgets     struct {
		Daily   float64 `yaml:"daily"`
		Monthly float64 `yaml:"monthly"`
	} `yaml:"budgets"`
	RateLimit int `yaml:"rate_limit"`
}

// RunWizard runs the interactive wizard. Returns (state, confirmed, error).
// When confirmed is false, the user aborted (e.g. EOF); no files should be written.
//
//nolint:gocyclo // wizard flow is inherently branched
func RunWizard(wio WizardIO) (WizardState, bool, error) {
	out := wio.Out
	if out == nil {
		out = os.Stdout
	}
	in := wio.In
	if in == nil {
		in = os.Stdin
	}
	scan := bufio.NewScanner(in)

	var state WizardState

	fmt.Fprintln(out, "🦅 Dativo Talon — Compliance-First AI Gateway for Europe")
	fmt.Fprintln(out, "─────────────────────────────────────────────────────────")
	fmt.Fprintln(out, "Let's configure your agent. Press Enter to accept defaults.")
	fmt.Fprintln(out)

	// Prologue
	state.AgentName = readLine(scan, out, "Agent name", "my-agent")
	state.AgentDescription = readLine(scan, out, "Description", "AI agent with policy enforcement")
	state.OwnerEmail = readLine(scan, out, "Owner email", "")

	// Q1: Workload type
	workload, err := readChoice(scan, out, "What type of AI workload are you governing?", []string{
		"AI agent framework  (OpenClaw, n8n, Flowise, custom agent)",
		"Direct LLM API calls  (OpenAI SDK, LangChain, bare HTTP calls)",
		"Both — mixed environment",
	}, 1)
	if err != nil {
		return state, false, err
	}
	switch workload {
	case 1:
		state.WorkloadType = "agent"
	case 2:
		state.WorkloadType = "proxy"
	case 3:
		state.WorkloadType = "hybrid"
	default:
		state.WorkloadType = "agent"
	}

	// Q2: Framework pack (skipped for proxy)
	if state.WorkloadType == "proxy" {
		state.PackID = "generic"
	} else {
		packs := pack.ListForWizard()
		opts := make([]string, len(packs))
		for i, p := range packs {
			opts[i] = fmt.Sprintf("%s — %s", p.DisplayName, p.Description)
		}
		choice, err := readChoice(scan, out, "Which agent framework are you governing?", opts, 1)
		if err != nil {
			return state, false, err
		}
		if choice >= 1 && choice <= len(packs) {
			state.PackID = packs[choice-1].ID
		} else {
			state.PackID = "generic"
		}
	}

	// Q3: Primary LLM provider
	providers := llm.ListForWizard(false)
	providerOpts := make([]string, len(providers)+1)
	for i := range providers {
		p := &providers[i]
		suffix := ""
		if p.Wizard.Suffix != "" {
			suffix = "  " + p.Wizard.Suffix
		}
		providerOpts[i] = p.DisplayName + suffix
	}
	providerOpts[len(providers)] = "Other / configure manually"
	choice, err := readChoice(scan, out, "Which LLM provider will you use primarily?", providerOpts, 1)
	if err != nil {
		return state, false, err
	}
	if choice >= 1 && choice <= len(providers) {
		state.ProviderID = providers[choice-1].ID
	} else {
		state.ProviderID = "openai"
	}

	// Q3b: Region follow-up
	if state.ProviderID != "" {
		p, err := llm.NewProvider(state.ProviderID, nil)
		if err == nil {
			meta := p.Metadata()
			if meta.Wizard.RequiresRegion && len(meta.Wizard.AvailableRegions) > 0 {
				regions := meta.Wizard.AvailableRegions
				opts := make([]string, len(regions))
				for i, r := range regions {
					eu := ""
					if r.IsEU {
						eu = "   [EU ✓]"
					}
					opts[i] = r.DisplayName + eu
				}
				regionChoice, err := readChoice(scan, out, "Which region?", opts, 1)
				if err != nil {
					return state, false, err
				}
				if regionChoice >= 1 && regionChoice <= len(regions) {
					state.RegionID = regions[regionChoice-1].ID
				} else if len(regions) > 0 {
					state.RegionID = regions[0].ID
				}
			}
		}
	}

	// Q4: Data residency (default from provider SuggestEUStrict)
	defaultResidency := 3 // global
	if state.ProviderID != "" {
		if p, err := llm.NewProvider(state.ProviderID, nil); err == nil && p.Metadata().Wizard.SuggestEUStrict {
			defaultResidency = 1
		}
	}
	residencyOpts := []string{
		"EU only — strict    (block any request routed outside EU jurisdiction)",
		"EU preferred        (prefer EU, allow US fallback only if all EU providers fail)",
		"No restriction      (global routing optimised for performance)",
	}
	choice, err = readChoice(scan, out, "What are your data residency requirements?", residencyOpts, defaultResidency)
	if err != nil {
		return state, false, err
	}
	switch choice {
	case 1:
		state.DataSovereignty = "eu_strict"
	case 2:
		state.DataSovereignty = "eu_preferred"
	default:
		state.DataSovereignty = "global"
	}

	// Q5: Compliance features (workload-adaptive list)
	featuresForWorkload := feature.DefaultsForWorkload(state.WorkloadType)
	defaultIDs := feature.DefaultEnabledIDs()
	// Build default comma-separated from default-enabled that are in featuresForWorkload
	var defaultFeatureList []string
	for _, id := range defaultIDs {
		for _, f := range featuresForWorkload {
			if f.ID == id {
				defaultFeatureList = append(defaultFeatureList, id)
				break
			}
		}
	}
	defaultFeaturesStr := strings.Join(defaultFeatureList, ",")
	prompt := "Features to enable (comma-separated)"
	fmt.Fprintf(out, "? Which compliance features do you need?\n")
	for _, f := range featuresForWorkload {
		mark := " "
		for _, id := range defaultFeatureList {
			if id == f.ID {
				mark = "x"
				break
			}
		}
		fmt.Fprintf(out, "  [%s] %s\n", mark, f.DisplayName)
	}
	fmt.Fprintf(out, "  %s [%s]: ", prompt, defaultFeaturesStr)
	var line string
	if scan.Scan() {
		line = strings.TrimSpace(scan.Text())
	}
	if line == "" {
		state.EnabledFeatures = defaultFeatureList
	} else {
		parts := strings.Split(line, ",")
		validIDs := make(map[string]bool)
		for _, id := range feature.ValidFeatureIDs() {
			validIDs[id] = true
		}
		for _, p := range parts {
			id := strings.TrimSpace(strings.ToLower(p))
			if validIDs[id] {
				state.EnabledFeatures = append(state.EnabledFeatures, id)
			}
		}
		if len(state.EnabledFeatures) == 0 {
			state.EnabledFeatures = defaultFeatureList
		}
	}

	// Confirmation
	fmt.Fprintln(out)
	fmt.Fprintln(out, "─────────────────────────────────────────────────────────")
	fmt.Fprintln(out, "📋 Configuration Summary")
	fmt.Fprintf(out, "  Agent name:        %s\n", state.AgentName)
	fmt.Fprintf(out, "  Framework:         %s\n", packName(state.PackID))
	fmt.Fprintf(out, "  Primary provider:  %s", providerName(state.ProviderID))
	if state.RegionID != "" {
		fmt.Fprintf(out, "  [%s]", state.RegionID)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  Data residency:    %s\n", dataResidencyLabel(state.DataSovereignty))
	fmt.Fprintf(out, "  Features:          %s\n", strings.Join(state.EnabledFeatures, ", "))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Files to create:")
	fmt.Fprintln(out, "    agent.talon.yaml    — agent policy (capabilities, memory, compliance)")
	fmt.Fprintln(out, "    talon.config.yaml   — infrastructure config (provider, storage, observability)")
	fmt.Fprintln(out, "─────────────────────────────────────────────────────────")
	confirm := readLine(scan, out, "Proceed? [Y/n]", "y")
	if strings.ToLower(strings.TrimSpace(confirm)) == "n" {
		return state, false, nil
	}
	return state, true, nil
}

func packName(id string) string {
	if p, ok := pack.FindByID(id); ok {
		return p.DisplayName
	}
	return id
}

func providerName(id string) string {
	p, err := llm.NewProvider(id, nil)
	if err != nil {
		return id
	}
	return p.Metadata().DisplayName
}

func dataResidencyLabel(s string) string {
	switch s {
	case "eu_strict":
		return "EU Strict — requests blocked outside EU jurisdiction"
	case "eu_preferred":
		return "EU preferred"
	default:
		return "Global"
	}
}

func readLine(scan *bufio.Scanner, out io.Writer, prompt, defaultVal string) string {
	fmt.Fprintf(out, "%s [%s]: ", prompt, defaultVal)
	if scan.Scan() {
		t := strings.TrimSpace(scan.Text())
		if t != "" {
			return t
		}
	}
	return defaultVal
}

func readChoice(scan *bufio.Scanner, out io.Writer, question string, options []string, defaultChoice int) (int, error) {
	fmt.Fprintf(out, "? %s\n\n", question)
	for i, o := range options {
		fmt.Fprintf(out, "  %d) %s\n", i+1, o) // #nosec G705 -- options from wizard built-in lists, out is stdout
	}
	fmt.Fprintf(out, "\nEnter 1-%d [default: %d]: ", len(options), defaultChoice) // #nosec G705 -- format args are integers
	if !scan.Scan() {
		return defaultChoice, io.EOF
	}
	text := strings.TrimSpace(scan.Text())
	if text == "" {
		return defaultChoice, nil
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 || n > len(options) {
		return defaultChoice, nil
	}
	return n, nil
}

// BuildConfigs converts WizardState into agent policy and infra config. Pure function, no I/O.
func BuildConfigs(state WizardState) (*policy.Policy, *InfraYAML, error) {
	agentCfg := baseAgentPolicy(state)
	applyWorkloadType(agentCfg, state.WorkloadType)
	applyDataResidencyToAgent(agentCfg, state)
	for _, id := range state.EnabledFeatures {
		if err := applyFeatureToAgent(agentCfg, id); err != nil {
			return nil, nil, fmt.Errorf("applying feature %q: %w", id, err)
		}
	}
	infraCfg := buildInfraConfig(state)
	agentYAML, err := yaml.Marshal(agentCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling agent config: %w", err)
	}
	if err := policy.ValidateSchema(agentYAML, false); err != nil {
		return nil, nil, fmt.Errorf("agent config validation: %w", err)
	}
	return agentCfg, infraCfg, nil
}

func baseAgentPolicy(state WizardState) *policy.Policy {
	pol := &policy.Policy{
		Agent: policy.AgentConfig{
			Name:        state.AgentName,
			Description: state.AgentDescription,
			Version:     "1.0.0",
			ModelTier:   1,
		},
		Capabilities: &policy.CapabilitiesConfig{
			AllowedTools:      []string{"sql_query", "file_read"},
			ForbiddenPatterns: []string{".env", "secrets", "credentials"},
		},
		Policies: policy.PoliciesConfig{
			CostLimits: &policy.CostLimitsConfig{
				PerRequest: 5.0,
				Daily:      200.0,
				Monthly:    3000.0,
			},
			ResourceLimits: &policy.ResourceLimitsConfig{
				Timeout: &policy.TimeoutConfig{
					Operation:     "60s",
					ToolExecution: "5m",
					AgentTotal:    "30m",
				},
			},
			RateLimits: &policy.RateLimitsConfig{
				RequestsPerMinute:    30,
				ConcurrentExecutions: 1,
			},
		},
		Audit: &policy.AuditConfig{
			LogLevel:       "detailed",
			RetentionDays:  2555,
			IncludePrompts: false, IncludeResponses: false,
		},
		Compliance: &policy.ComplianceConfig{
			Frameworks:    []string{"gdpr", "eu-ai-act"},
			DataResidency: "eu",
		},
		Metadata: &policy.MetadataConfig{
			Owner: state.OwnerEmail,
			Tags:  []string{"ai-agent", "governed"},
		},
	}
	// Model routing defaults (BuildConfigs/applyDataResidency will override locations)
	primary, fallback := defaultModelsForProvider(state.ProviderID)
	location := state.RegionID
	if location == "" {
		location = "any"
	}
	if validEURegions[location] {
		// keep as-is
	} else if state.DataSovereignty == "eu_strict" && state.ProviderID != "" {
		location = defaultEURegionForProvider(state.ProviderID)
	}
	pol.Policies.ModelRouting = &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: primary, Location: "any"},
		Tier1: &policy.TierConfig{Primary: fallback, Fallback: primary, Location: location},
		Tier2: &policy.TierConfig{Primary: fallback, Location: location, BedrockOnly: state.ProviderID == "bedrock"},
	}
	return pol
}

func defaultModelsForProvider(providerID string) (tier0Primary, tier1Primary string) {
	switch providerID {
	case "openai", "generic-openai":
		return "gpt-4o-mini", "gpt-4o"
	case "anthropic":
		return "claude-3-5-haiku-latest", "claude-sonnet-4-20250514"
	case "azure-openai":
		return "gpt-4o-mini", "gpt-4o"
	case "bedrock":
		return "anthropic.claude-3-haiku-20240307-v1:0", "anthropic.claude-sonnet-4-20250514-v1:0"
	case "ollama":
		return "llama3.2", "llama3.2"
	case "mistral":
		return "mistral-small-latest", "mistral-large-latest"
	case "vertex":
		return "gemini-1.5-flash", "gemini-1.5-pro"
	case "qwen":
		return "qwen-turbo", "qwen-plus"
	case "cohere":
		return "command-r", "command-r-plus"
	default:
		return "gpt-4o-mini", "gpt-4o"
	}
}

func defaultEURegionForProvider(providerID string) string {
	switch providerID {
	case "azure-openai":
		return "westeurope"
	case "bedrock":
		return "eu-west-1"
	case "vertex":
		return "europe-west1"
	default:
		return "eu-west-1"
	}
}

func applyWorkloadType(pol *policy.Policy, workload string) {
	if workload == "proxy" {
		pol.Agent.ModelTier = 0
		if pol.Capabilities != nil {
			pol.Capabilities.AllowedTools = nil
		}
	} else {
		pol.Agent.ModelTier = 1
		if pol.Capabilities != nil && len(pol.Capabilities.AllowedTools) == 0 {
			pol.Capabilities.AllowedTools = []string{"sql_query", "file_read"}
		}
	}
}

//nolint:gocyclo // tier/region branching
func applyDataResidencyToAgent(pol *policy.Policy, state WizardState) {
	switch state.DataSovereignty {
	case "eu_strict":
		if pol.Compliance == nil {
			pol.Compliance = &policy.ComplianceConfig{}
		}
		pol.Compliance.DataResidency = "eu"
		loc := state.RegionID
		if loc == "" || !validEURegions[loc] {
			loc = defaultEURegionForProvider(state.ProviderID)
		}
		if pol.Policies.ModelRouting != nil {
			if pol.Policies.ModelRouting.Tier0 != nil {
				pol.Policies.ModelRouting.Tier0.Location = "any"
			}
			if pol.Policies.ModelRouting.Tier1 != nil {
				pol.Policies.ModelRouting.Tier1.Location = loc
			}
			if pol.Policies.ModelRouting.Tier2 != nil {
				pol.Policies.ModelRouting.Tier2.Location = loc
			}
		}
	case "eu_preferred":
		if pol.Compliance == nil {
			pol.Compliance = &policy.ComplianceConfig{}
		}
		pol.Compliance.DataResidency = "eu"
	case "global":
		if pol.Compliance == nil {
			pol.Compliance = &policy.ComplianceConfig{}
		}
		pol.Compliance.DataResidency = "any"
		if pol.Policies.ModelRouting != nil {
			if pol.Policies.ModelRouting.Tier1 != nil {
				pol.Policies.ModelRouting.Tier1.Location = "any"
			}
			if pol.Policies.ModelRouting.Tier2 != nil {
				pol.Policies.ModelRouting.Tier2.Location = "any"
			}
		}
	}
}

func applyFeatureToAgent(pol *policy.Policy, featureID string) error {
	switch featureID {
	case "pii":
		if pol.Policies.DataClassification == nil {
			pol.Policies.DataClassification = &policy.DataClassificationConfig{}
		}
		pol.Policies.DataClassification.InputScan = true
		pol.Policies.DataClassification.OutputScan = true
		pol.Policies.DataClassification.RedactPII = true
	case "audit":
		if pol.Audit == nil {
			pol.Audit = &policy.AuditConfig{}
		}
		pol.Audit.LogLevel = "detailed"
		pol.Audit.RetentionDays = 2555
		pol.Audit.IncludePrompts = false
		pol.Audit.IncludeResponses = false
	case "cost":
		if pol.Policies.CostLimits == nil {
			pol.Policies.CostLimits = &policy.CostLimitsConfig{}
		}
		pol.Policies.CostLimits.PerRequest = 5.0
		pol.Policies.CostLimits.Daily = 200.0
		pol.Policies.CostLimits.Monthly = 3000.0
	case "injection":
		if pol.AttachmentHandling == nil {
			pol.AttachmentHandling = &policy.AttachmentHandlingConfig{}
		}
		pol.AttachmentHandling.Mode = "strict"
		pol.AttachmentHandling.Scanning = &policy.ScanningConfig{
			DetectInstructions: true,
			ActionOnDetection:  "block_and_flag",
		}
	case "eu-ai-act":
		if pol.Compliance == nil {
			pol.Compliance = &policy.ComplianceConfig{}
		}
		pol.Compliance.AIActRiskLevel = "limited"
		pol.Compliance.Frameworks = append(pol.Compliance.Frameworks, "eu-ai-act")
	case "dora":
		if pol.Compliance == nil {
			pol.Compliance = &policy.ComplianceConfig{}
		}
		pol.Compliance.Frameworks = append(pol.Compliance.Frameworks, "dora")
	}
	return nil
}

func buildInfraConfig(state WizardState) *InfraYAML {
	cfg := &InfraYAML{}
	cfg.LLM = &struct {
		PricingFile string                   `yaml:"pricing_file"`
		Providers   map[string]ProviderBlock `yaml:"providers"`
		Routing     *struct {
			DataSovereigntyMode string `yaml:"data_sovereignty_mode"`
		} `yaml:"routing"`
	}{
		PricingFile: "pricing/models.yaml",
		Providers:   make(map[string]ProviderBlock),
		Routing: &struct {
			DataSovereigntyMode string `yaml:"data_sovereignty_mode"`
		}{
			DataSovereigntyMode: state.DataSovereignty,
		},
	}
	keyEnv := vaultSecretEnvVar(state.ProviderID)
	configMap := map[string]interface{}{}
	if state.RegionID != "" {
		configMap["region"] = state.RegionID
	}
	if keyEnv != "" {
		configMap["key_env"] = keyEnv
	}
	cfg.LLM.Providers[state.ProviderID] = ProviderBlock{
		Type:    state.ProviderID,
		Config:  configMap,
		Enabled: true,
	}
	cfg.Evidence = &struct {
		Type string `yaml:"type"`
		Path string `yaml:"path"`
	}{Type: "sqlite", Path: "~/.talon/evidence.db"}
	cfg.SecretsKeyEnv = "TALON_SECRETS_KEY"
	tenantID := state.AgentName
	if tenantID == "" {
		tenantID = "default"
	}
	cfg.Tenants = []TenantBlock{{
		ID:          tenantID,
		DisplayName: "Default Tenant",
		RateLimit:   30,
	}}
	cfg.Tenants[0].Budgets.Daily = 200.0
	cfg.Tenants[0].Budgets.Monthly = 3000.0
	return cfg
}

// vaultSecretEnvVar returns the env var name used to pass the vault secret to the provider, or empty if no key (ollama, bedrock use other auth).
func vaultSecretEnvVar(providerID string) string {
	switch providerID {
	case "ollama", "bedrock":
		return ""
	case "openai":
		return "OPENAI_API_KEY"
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "azure-openai":
		return "AZURE_OPENAI_KEY"
	case "mistral":
		return "MISTRAL_API_KEY"
	case "vertex":
		return "GOOGLE_CLOUD_PROJECT" // or vertex uses ADC
	case "qwen":
		return "DASHSCOPE_API_KEY"
	case "cohere":
		return "COHERE_API_KEY"
	case "generic-openai":
		return "OPENAI_API_KEY"
	default:
		return "TALON_LLM_KEY"
	}
}

// VaultSecretName returns the vault key name for talon secrets set <name>.
func VaultSecretName(providerID string) string {
	switch providerID {
	case "ollama", "bedrock":
		return ""
	case "openai":
		return "openai-api-key"
	case "anthropic":
		return "anthropic-api-key"
	case "azure-openai":
		return "azure-openai-key"
	case "mistral":
		return "mistral-api-key"
	case "vertex":
		return "vertex-api-key"
	case "qwen":
		return "qwen-api-key"
	case "cohere":
		return "cohere-api-key"
	case "generic-openai":
		return "generic-openai-key"
	default:
		return providerID + "-api-key"
	}
}

// WriteOptions configures WriteConfigs.
type WriteOptions struct {
	AgentPath   string
	InfraPath   string
	Force       bool
	Version     string
	ProviderID  string
	RegionID    string
	Sovereignty string
	PackID      string
	Features    []string
}

// marshalWithHeader prepends a YAML comment block to the document.
func marshalWithHeader(agentCfg *policy.Policy, infraCfg *InfraYAML, opts WriteOptions) (agentYAML, infraYAML []byte, err error) {
	agentYAML, err = yaml.Marshal(agentCfg)
	if err != nil {
		return nil, nil, err
	}
	infraYAML, err = yaml.Marshal(infraCfg)
	if err != nil {
		return nil, nil, err
	}
	version := opts.Version
	if version == "" {
		version = "v0.2.0"
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	agentHeader := fmt.Sprintf("# Generated by: talon init (wizard)\n# Talon version: %s\n# Generated at: %s\n# Provider: %s", version, ts, opts.ProviderID)
	if opts.RegionID != "" {
		agentHeader += " (" + opts.RegionID + ")"
	}
	agentHeader += fmt.Sprintf(" | Sovereignty: %s\n# Pack: %s | Features: %s\n# Agent policy (AI governance / compliance team). Edit and run `talon validate` to verify.\n\n", opts.Sovereignty, opts.PackID, strings.Join(opts.Features, ","))
	infraHeader := fmt.Sprintf("# Generated by: talon init (wizard)\n# Talon version: %s\n# Generated at: %s\n# Infrastructure config (DevOps / platform team).\n\n", version, ts)
	return append([]byte(agentHeader), agentYAML...), append([]byte(infraHeader), infraYAML...), nil
}

// WriteConfigs writes both config files atomically (temp file + rename). Refuses overwrite without Force.
func WriteConfigs(agentCfg *policy.Policy, infraCfg *InfraYAML, opts WriteOptions) error {
	if opts.AgentPath == "" {
		opts.AgentPath = "agent.talon.yaml"
	}
	if opts.InfraPath == "" {
		opts.InfraPath = "talon.config.yaml"
	}
	if !opts.Force {
		if _, err := os.Stat(opts.AgentPath); err == nil {
			return fmt.Errorf("%s already exists. Use --force to overwrite, or --agent-output to write to a different path", opts.AgentPath)
		}
		if _, err := os.Stat(opts.InfraPath); err == nil {
			return fmt.Errorf("%s already exists. Use --force to overwrite, or --infra-output to write to a different path", opts.InfraPath)
		}
	}
	agentYAML, infraYAML, err := marshalWithHeader(agentCfg, infraCfg, opts)
	if err != nil {
		return err
	}
	if err := atomicWrite(opts.AgentPath, agentYAML, opts.Force); err != nil {
		return err
	}
	if err := atomicWrite(opts.InfraPath, infraYAML, opts.Force); err != nil {
		return err
	}
	return nil
}

func atomicWrite(path string, data []byte, force bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath) // #nosec G703 -- tmpPath from os.CreateTemp in our dir
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath) // #nosec G703 -- tmpPath from os.CreateTemp
		return err
	}
	if force {
		_ = os.Remove(path)
	}
	if err := os.Rename(tmpPath, path); err != nil { // #nosec G703 -- tmpPath from CreateTemp, path from WriteOptions
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}

// PostInitVerify runs a subset of doctor checks (policy, config load, data dir, crypto keys) and prints results.
func PostInitVerify(agentPath, infraPath string, out io.Writer) (warnings int, fail error) {
	if out == nil {
		out = os.Stdout
	}
	// Doctor uses viper and config.Load() which reads from cwd. So we must be in the dir that has the written files.
	report := doctor.Run(context.Background(), doctor.Options{})
	fmt.Fprintln(out, "Verifying configuration...")
	for _, c := range report.Checks {
		status := "pass"
		if c.Status == "warn" {
			status = "warn"
			warnings++
		}
		if c.Status == "fail" {
			status = "fail"
			if fail == nil {
				fail = fmt.Errorf("%s: %s", c.Name, c.Message)
			}
		}
		fmt.Fprintf(out, "  [%s] %-20s %s\n", status, c.Name, c.Message)
		if c.Fix != "" && (c.Status == "warn" || c.Status == "fail") {
			fmt.Fprintf(out, "         Fix: %s\n", c.Fix)
		}
	}
	if warnings > 0 && fail == nil {
		fmt.Fprintf(out, "\nResult: %d warning(s) — see \"Next steps\" below\n", warnings)
	}
	if report.Status == "fail" {
		if fail == nil {
			fail = fmt.Errorf("verification failed")
		}
	}
	return warnings, fail
}

// PrintNextSteps prints the vault-first next steps block.
func PrintNextSteps(agentName, providerID string, out io.Writer) {
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "✅ agent.talon.yaml written")
	fmt.Fprintln(out, "✅ talon.config.yaml written")
	fmt.Fprintln(out, "✅ Both files validated")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next steps:")
	fmt.Fprintln(out, "  1. Set the vault encryption key (required):")
	fmt.Fprintln(out, "     export TALON_SECRETS_KEY=$(openssl rand -hex 32)")
	fmt.Fprintln(out)
	secretName := VaultSecretName(providerID)
	if secretName != "" {
		fmt.Fprintf(out, "  2. Store your %s API key in the vault:\n", providerName(providerID))
		fmt.Fprintf(out, "     talon secrets set %s \"your-key-here\"\n", secretName)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  3. Start Talon:")
		fmt.Fprintln(out, "     talon serve")
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  4. Run your first query:\n")
		fmt.Fprintf(out, "     talon run \"test query\" --agent %s\n", agentName)
	} else {
		fmt.Fprintln(out, "  2. Start Talon:")
		fmt.Fprintln(out, "     talon serve")
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  3. Run your first query:\n")
		fmt.Fprintf(out, "     talon run \"test query\" --agent %s\n", agentName)
	}
}

// IsTerminal returns true if stdin is a TTY.
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) // #nosec G115 -- stdin Fd() is small on supported platforms
}

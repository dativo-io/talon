package cmd

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/feature"
	"github.com/dativo-io/talon/internal/llm"
	_ "github.com/dativo-io/talon/internal/llm/providers"
	"github.com/dativo-io/talon/internal/pack"
	"github.com/dativo-io/talon/internal/policy"
)

//go:embed templates/init/*.tmpl
var initTemplates embed.FS

//go:embed templates/init/pricing_models.yaml
var initPricingModelsYAML []byte

var (
	initName            string
	initOwner           string
	initMinimal         bool
	initPack            string
	initScaffold        bool
	initDryRun          bool
	initForce           bool
	initVerify          bool
	initSkipVerify      bool
	initAgentOutput     string
	initInfraOutput     string
	initProvider        string
	initRegion          string
	initDataSovereignty string
	initFeatures        string
	initListProviders   bool
	initListPacks       bool
	initListFeatures    bool
	initCompliance      string
)

// supportedPacks are the allowed values for --pack (industry starter packs + wizard packs).
var supportedPacks = []string{"fintech-eu", "ecommerce-eu", "saas-eu", "telecom-eu", "openclaw", "copaw", "langchain", "crewai", "generic"}

// validComplianceValues are the allowed values for --compliance.
var validComplianceValues = []string{"gdpr", "nis2", "dora", "eu-ai-act", "all"}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new Talon project",
	Long:  "Interactive wizard (default) or template-based init. Creates agent.talon.yaml and talon.config.yaml. Use --scaffold for quick defaults without wizard, or --pack for a starter pack.",
	RunE:  runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringVar(&initName, "name", "my-agent", "agent name")
	initCmd.Flags().StringVar(&initOwner, "owner", "", "agent owner email")
	initCmd.Flags().BoolVar(&initMinimal, "minimal", false, "generate minimal agent.talon.yaml (with --scaffold)")
	initCmd.Flags().StringVar(&initPack, "pack", "", "starter pack: openclaw, fintech-eu, ecommerce-eu, saas-eu, telecom-eu, langchain, generic")
	initCmd.Flags().BoolVar(&initScaffold, "scaffold", false, "skip wizard; generate default files from templates")
	initCmd.Flags().BoolVar(&initDryRun, "dry-run", false, "print configs to stdout, write no files")
	initCmd.Flags().BoolVar(&initForce, "force", false, "overwrite existing agent.talon.yaml and talon.config.yaml")
	initCmd.Flags().BoolVar(&initVerify, "verify", true, "run post-init verification (doctor checks)")
	initCmd.Flags().BoolVar(&initSkipVerify, "skip-verify", false, "skip post-init verification")
	initCmd.Flags().BoolVar(&initListProviders, "list-providers", false, "list available LLM providers and exit")
	initCmd.Flags().BoolVar(&initListPacks, "list-packs", false, "list available packs and exit")
	initCmd.Flags().BoolVar(&initListFeatures, "list-features", false, "list compliance features and exit")
	initCmd.Flags().StringVar(&initAgentOutput, "agent-output", "", "path for agent.talon.yaml (default: agent.talon.yaml)")
	initCmd.Flags().StringVar(&initInfraOutput, "infra-output", "", "path for talon.config.yaml (default: talon.config.yaml)")
	initCmd.Flags().StringVar(&initProvider, "provider", "", "primary LLM provider (scripted mode; use with --name)")
	initCmd.Flags().StringVar(&initRegion, "region", "", "provider region when provider requires one (e.g. westeurope for azure-openai)")
	initCmd.Flags().StringVar(&initDataSovereignty, "data-sovereignty", "", "data residency: eu-strict, eu-preferred, or global")
	initCmd.Flags().StringVar(&initFeatures, "features", "", "comma-separated feature IDs (e.g. pii,audit,cost)")
	initCmd.Flags().StringVar(&initCompliance, "compliance", "", "compliance overlay: gdpr, nis2, dora, eu-ai-act, all")
}

//nolint:gocyclo // init dispatch has many branches (wizard, scaffold, pack, scripted, list)
func runInit(cmd *cobra.Command, args []string) error {
	_, span := tracer.Start(cmd.Context(), "init")
	defer span.End()

	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	// 1. List commands
	if initListProviders {
		return runListProviders(out)
	}
	if initListPacks {
		return runListPacks(out)
	}
	if initListFeatures {
		return runListFeatures(out)
	}

	// 2. Pack path (no wizard) — backward compatible
	if initPack != "" {
		return runPackInit(out, errOut)
	}

	// 3. Scaffold path (no wizard)
	if initScaffold {
		return runScaffoldInit(out, errOut)
	}

	// 4. Scripted wizard (flags only)
	if initProvider != "" && initName != "" {
		return runScriptedInit(cmd, out, errOut)
	}

	// 5. Bare init — wizard or fail
	if !IsTerminal() {
		fmt.Fprintln(errOut, "talon init: stdin is not a terminal.")
		fmt.Fprintln(errOut)
		fmt.Fprintln(errOut, "To use the interactive wizard, run in a terminal.")
		fmt.Fprintln(errOut, "To generate configs non-interactively, provide required flags:")
		fmt.Fprintln(errOut)
		fmt.Fprintln(errOut, "  talon init --scaffold                          # Quick start with defaults")
		fmt.Fprintln(errOut, "  talon init --pack openclaw --name my-agent     # Pack-based init")
		fmt.Fprintln(errOut, "  talon init --provider openai --name my-agent \\")
		fmt.Fprintln(errOut, "    --data-sovereignty global --features pii,audit,cost")
		fmt.Fprintln(errOut)
		fmt.Fprintln(errOut, "See: talon init --help")
		return fmt.Errorf("non-interactive init requires --scaffold, --pack, or scripted flags")
	}

	// Interactive wizard
	wio := WizardIO{In: cmd.InOrStdin(), Out: out, ErrOut: errOut}
	state, confirmed, err := RunWizard(wio)
	if err != nil {
		return fmt.Errorf("wizard: %w", err)
	}
	if !confirmed {
		fmt.Fprintln(out, "Init aborted.")
		return nil
	}

	agentPath := initAgentOutput
	if agentPath == "" {
		agentPath = "agent.talon.yaml"
	}
	infraPath := initInfraOutput
	if infraPath == "" {
		infraPath = "talon.config.yaml"
	}

	if initDryRun {
		agentCfg, infraCfg, err := BuildConfigs(state)
		if err != nil {
			return err
		}
		opts := WriteOptions{
			AgentPath:   agentPath,
			InfraPath:   infraPath,
			ProviderID:  state.ProviderID,
			RegionID:    state.RegionID,
			Sovereignty: state.DataSovereignty,
			PackID:      state.PackID,
			Features:    state.EnabledFeatures,
		}
		agentYAML, infraYAML, err := marshalWithHeader(agentCfg, infraCfg, opts)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "--- agent.talon.yaml ---")
		fmt.Fprintln(out, string(agentYAML))
		fmt.Fprintln(out, "--- talon.config.yaml ---")
		fmt.Fprintln(out, string(infraYAML))
		return nil
	}

	agentCfg, infraCfg, err := BuildConfigs(state)
	if err != nil {
		return fmt.Errorf("building configs: %w", err)
	}
	opts := WriteOptions{
		AgentPath:   agentPath,
		InfraPath:   infraPath,
		Force:       initForce,
		ProviderID:  state.ProviderID,
		RegionID:    state.RegionID,
		Sovereignty: state.DataSovereignty,
		PackID:      state.PackID,
		Features:    state.EnabledFeatures,
	}
	if err := WriteConfigs(agentCfg, infraCfg, opts); err != nil {
		return err
	}
	if err := writePricingFile(); err != nil {
		return err
	}
	if initVerify && !initSkipVerify {
		_, fail := PostInitVerify(agentPath, infraPath, out)
		if fail != nil {
			log.Warn().Err(fail).Msg("Post-init verification had failures")
		}
	}
	if packRequiresGateway(state.PackID) {
		printOpenClawNextSteps(out)
	} else {
		PrintNextSteps(state.AgentName, state.ProviderID, out)
	}
	return nil
}

func runListProviders(out io.Writer) error {
	list := llm.ListForWizard(false)
	if len(list) == 0 {
		fmt.Fprintln(out, "No providers registered.")
		return nil
	}
	fmt.Fprintln(out, "Available LLM providers:")
	fmt.Fprintln(out)
	for i := range list {
		p := &list[i]
		suffix := ""
		if p.Wizard.Suffix != "" {
			suffix = "  " + p.Wizard.Suffix
		}
		fmt.Fprintf(out, "  %-18s %s%s\n", p.ID, p.DisplayName, suffix)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Add a provider: docs/contributor/adding-a-provider.md")
	return nil
}

func runListPacks(out io.Writer) error {
	list := pack.ListForWizard()
	fmt.Fprintln(out, "Available packs:")
	fmt.Fprintln(out)
	for i := range list {
		p := &list[i]
		fmt.Fprintf(out, "  %-12s %s — %s\n", p.ID, p.DisplayName, p.Description)
	}
	return nil
}

func runListFeatures(out io.Writer) error {
	list := feature.AllFeatures()
	fmt.Fprintln(out, "Available compliance features:")
	fmt.Fprintln(out)
	for _, f := range list {
		defaultMark := " "
		if f.DefaultEnabled {
			defaultMark = "x"
		}
		fmt.Fprintf(out, "  [%s] %-8s %s\n", defaultMark, f.ID, f.DisplayName)
	}
	return nil
}

//nolint:gocyclo // runPackInit dispatches pack validation, init, and post-message by pack type
func runPackInit(out, errOut io.Writer) error {
	ok := false
	for _, p := range supportedPacks {
		if p == initPack {
			ok = true
			break
		}
	}
	if !ok {
		if _, found := pack.FindByID(initPack); found {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("unsupported --pack %q; use one of: %s, or run: talon init --list-packs", initPack, strings.Join(supportedPacks, ", "))
	}
	if initCompliance != "" {
		valid := false
		for _, c := range validComplianceValues {
			if strings.EqualFold(c, initCompliance) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unsupported --compliance %q; use one of: %s", initCompliance, strings.Join(validComplianceValues, ", "))
		}
	}
	if err := initializeProject(); err != nil {
		return fmt.Errorf("initializing project: %w", err)
	}
	log.Info().Str("name", initName).Str("pack", initPack).Msg("Initialized Talon project")
	fmt.Fprintln(out, "Initialized Talon project")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Created files:")
	fmt.Fprintln(out, "  - agent.talon.yaml     (agent policy — governance/compliance team)")
	fmt.Fprintln(out, "  - talon.config.yaml    (infrastructure config — DevOps/platform team)")
	fmt.Fprintln(out, "  - pricing/models.yaml  (LLM cost estimation table)")
	fmt.Fprintln(out)
	if p, ok := pack.FindByID(initPack); ok && p.PostMessage != "" {
		fmt.Fprintln(out, strings.TrimSpace(p.PostMessage))
	} else if initPack == "openclaw" {
		printOpenClawNextSteps(out)
	} else {
		fmt.Fprintln(out, "Next steps:")
		fmt.Fprintln(out, "  1. Set the vault encryption key: export TALON_SECRETS_KEY=$(openssl rand -hex 32)")
		fmt.Fprintln(out, "  2. Store your LLM API key: talon secrets set <key-name> \"your-key\"")
		fmt.Fprintln(out, "  3. talon validate")
		fmt.Fprintln(out, "  4. talon run \"your query\"")
	}
	if initVerify && !initSkipVerify {
		_, _ = PostInitVerify("agent.talon.yaml", "talon.config.yaml", out)
	}
	return nil
}

func runScaffoldInit(out, errOut io.Writer) error {
	if err := initializeProject(); err != nil {
		return fmt.Errorf("initializing project: %w", err)
	}
	log.Info().Str("name", initName).Bool("scaffold", true).Msg("Initialized Talon project (scaffold)")
	fmt.Fprintln(out, "Initialized Talon project (scaffold)")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Created files:")
	fmt.Fprintln(out, "  - agent.talon.yaml")
	fmt.Fprintln(out, "  - talon.config.yaml")
	fmt.Fprintln(out, "  - pricing/models.yaml")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next steps:")
	fmt.Fprintln(out, "  1. export TALON_SECRETS_KEY=$(openssl rand -hex 32)")
	fmt.Fprintln(out, "  2. talon secrets set openai-api-key \"your-key\"")
	fmt.Fprintln(out, "  3. talon validate")
	fmt.Fprintln(out, "  4. talon run \"your query\"")
	if initVerify && !initSkipVerify {
		_, _ = PostInitVerify("agent.talon.yaml", "talon.config.yaml", out)
	}
	return nil
}

//nolint:gocyclo // scripted init has many flag combinations
func runScriptedInit(cmd *cobra.Command, out, errOut io.Writer) error {
	state := WizardState{
		AgentName:        initName,
		AgentDescription: "AI agent with policy enforcement",
		OwnerEmail:       initOwner,
		WorkloadType:     "agent",
		PackID:           "generic",
		ProviderID:       initProvider,
		RegionID:         initRegion,
		DataSovereignty:  "global",
		EnabledFeatures:  feature.DefaultEnabledIDs(),
	}
	if initDataSovereignty != "" {
		state.DataSovereignty = strings.ReplaceAll(strings.ToLower(initDataSovereignty), "-", "_")
		if state.DataSovereignty != "eu_strict" && state.DataSovereignty != "eu_preferred" && state.DataSovereignty != "global" {
			return fmt.Errorf("--data-sovereignty must be eu-strict, eu-preferred, or global")
		}
	}
	if initFeatures != "" {
		parts := strings.Split(initFeatures, ",")
		valid := make(map[string]bool)
		for _, id := range feature.ValidFeatureIDs() {
			valid[id] = true
		}
		for _, p := range parts {
			id := strings.TrimSpace(strings.ToLower(p))
			if valid[id] {
				state.EnabledFeatures = append(state.EnabledFeatures, id)
			}
		}
	}
	// Validate provider
	providers := llm.ListForWizard(false)
	found := false
	for i := range providers {
		if providers[i].ID == state.ProviderID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unknown --provider %q; run: talon init --list-providers", state.ProviderID)
	}

	agentPath := initAgentOutput
	if agentPath == "" {
		agentPath = "agent.talon.yaml"
	}
	infraPath := initInfraOutput
	if infraPath == "" {
		infraPath = "talon.config.yaml"
	}

	if initDryRun {
		agentCfg, infraCfg, err := BuildConfigs(state)
		if err != nil {
			return err
		}
		opts := WriteOptions{
			AgentPath:   agentPath,
			InfraPath:   infraPath,
			ProviderID:  state.ProviderID,
			RegionID:    state.RegionID,
			Sovereignty: state.DataSovereignty,
			PackID:      state.PackID,
			Features:    state.EnabledFeatures,
		}
		agentYAML, infraYAML, err := marshalWithHeader(agentCfg, infraCfg, opts)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "--- agent.talon.yaml ---")
		fmt.Fprintln(out, string(agentYAML))
		fmt.Fprintln(out, "--- talon.config.yaml ---")
		fmt.Fprintln(out, string(infraYAML))
		return nil
	}

	agentCfg, infraCfg, err := BuildConfigs(state)
	if err != nil {
		return fmt.Errorf("building configs: %w", err)
	}
	opts := WriteOptions{
		AgentPath:   agentPath,
		InfraPath:   infraPath,
		Force:       initForce,
		ProviderID:  state.ProviderID,
		RegionID:    state.RegionID,
		Sovereignty: state.DataSovereignty,
		PackID:      state.PackID,
		Features:    state.EnabledFeatures,
	}
	if err := WriteConfigs(agentCfg, infraCfg, opts); err != nil {
		return err
	}
	if err := writePricingFile(); err != nil {
		return err
	}
	if initVerify && !initSkipVerify {
		_, _ = PostInitVerify(agentPath, infraPath, out)
	}
	PrintNextSteps(state.AgentName, state.ProviderID, out)
	return nil
}

func writePricingFile() error {
	if err := os.MkdirAll("pricing", 0o755); err != nil {
		return fmt.Errorf("creating pricing directory: %w", err)
	}
	path := filepath.Join("pricing", "models.yaml")
	//nolint:gosec // G306: pricing file is not secret
	if err := os.WriteFile(path, initPricingModelsYAML, 0o644); err != nil {
		return fmt.Errorf("creating pricing/models.yaml: %w", err)
	}
	return nil
}

func printOpenClawNextSteps(out io.Writer) {
	fmt.Fprintln(out, "Next steps (OpenClaw gateway):")
	fmt.Fprintln(out, "  1. Set the vault key (use the same shell for steps 2–3):")
	fmt.Fprintln(out, "     export TALON_SECRETS_KEY=$(openssl rand -hex 32)")
	fmt.Fprintln(out, "  2. Store your real OpenAI key in the vault:")
	fmt.Fprintln(out, "     talon secrets set openai-api-key \"sk-your-key\"")
	fmt.Fprintln(out, "  3. Start the gateway (keep TALON_SECRETS_KEY set):")
	fmt.Fprintln(out, "     talon serve --gateway")
	fmt.Fprintln(out, "  4. Point OpenClaw at Talon:")
	fmt.Fprintln(out, "     Base URL:  http://localhost:8080/v1/proxy/openai/v1  (trailing /v1 required for correct paths)")
	fmt.Fprintln(out, "     API key:   talon-gw-openclaw-001")
	fmt.Fprintln(out, "  5. Send a message through OpenClaw, then check the audit trail:")
	fmt.Fprintln(out, "     talon audit list")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  The gateway starts in shadow mode (log only, no blocking).")
	fmt.Fprintln(out, "  Switch to enforce mode in talon.config.yaml when ready.")
}

//nolint:gocyclo // initializeProject branches on pack templates vs legacy, compliance overlay, and file paths
func initializeProject() error {
	agentPath := "agent.talon.yaml"
	configPath := "talon.config.yaml"
	if _, err := os.Stat(agentPath); err == nil && !initForce {
		return fmt.Errorf("%s already exists. Use --force to overwrite", agentPath)
	}
	if _, err := os.Stat(configPath); err == nil && !initForce {
		return fmt.Errorf("%s already exists. Use --force to overwrite", configPath)
	}

	if initPack != "" && initMinimal {
		return fmt.Errorf("cannot use both --pack and --minimal; choose one")
	}

	data := map[string]interface{}{
		"Name":  initName,
		"Owner": initOwner,
		"Date":  time.Now().Format(time.RFC3339),
	}

	p, hasPack := pack.FindByID(initPack)
	usePackTemplates := hasPack && len(p.Files) > 0

	if usePackTemplates {
		fs := pack.TemplateFS()
		for _, f := range p.Files {
			content, err := fs.ReadFile(f.TemplatePath)
			if err != nil {
				return fmt.Errorf("reading pack template %s: %w", f.TemplatePath, err)
			}
			var outPath string
			switch f.OutputPath {
			case "agent.talon.yaml":
				outPath = agentPath
			case "talon.config.yaml":
				outPath = configPath
			default:
				outPath = f.OutputPath
			}
			//nolint:gosec // G306: config files are not secret
			if err := os.WriteFile(outPath, content, 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", outPath, err)
			}
		}
	} else {
		agentTmpl := "templates/init/agent.talon.yaml.tmpl"
		switch {
		case initPack != "":
			agentTmpl = "templates/init/pack_" + strings.ReplaceAll(initPack, "-", "_") + ".talon.yaml.tmpl"
			if _, err := initTemplates.ReadFile(agentTmpl); err != nil {
				agentTmpl = "templates/init/agent.talon.yaml.tmpl"
			}
		case initMinimal:
			agentTmpl = "templates/init/agent.talon.yaml.minimal.tmpl"
		}

		if err := renderTemplate(agentTmpl, agentPath, data); err != nil {
			return fmt.Errorf("creating agent.talon.yaml: %w", err)
		}

		configTmpl := "templates/init/talon.config.yaml.tmpl"
		if initPack != "" {
			packConfig := "templates/init/pack_" + strings.ReplaceAll(initPack, "-", "_") + ".config.yaml.tmpl"
			if _, err := initTemplates.ReadFile(packConfig); err == nil {
				configTmpl = packConfig
			}
		}

		if err := renderTemplate(configTmpl, configPath, data); err != nil {
			return fmt.Errorf("creating talon.config.yaml: %w", err)
		}
	}

	if err := writePricingFile(); err != nil {
		return err
	}

	if initCompliance != "" {
		if err := applyComplianceOverlays(agentPath); err != nil {
			return fmt.Errorf("applying compliance overlay: %w", err)
		}
	}

	return nil
}

// applyComplianceOverlays reads agent.talon.yaml, merges the selected compliance overlay(s), and writes back.
func applyComplianceOverlays(agentPath string) error {
	content, err := os.ReadFile(agentPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", agentPath, err)
	}
	var base policy.Policy
	if err := yaml.Unmarshal(content, &base); err != nil {
		return fmt.Errorf("parsing agent policy: %w", err)
	}

	lower := strings.ToLower(initCompliance)
	names := []string{lower}
	if lower == "all" {
		names = pack.ComplianceOverlayNames()
	}
	for _, name := range names {
		overlayContent, err := pack.ReadComplianceOverlay(name)
		if err != nil {
			return fmt.Errorf("reading compliance overlay %q: %w", name, err)
		}
		var overlay policy.Policy
		if err := yaml.Unmarshal(overlayContent, &overlay); err != nil {
			return fmt.Errorf("parsing overlay %q: %w", name, err)
		}
		mergeComplianceOverlay(&base, &overlay)
	}

	out, err := yaml.Marshal(&base)
	if err != nil {
		return fmt.Errorf("marshaling merged policy: %w", err)
	}
	//nolint:gosec // G306: agent policy is not secret
	if err := os.WriteFile(agentPath, out, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", agentPath, err)
	}
	return nil
}

// mergeComplianceOverlay merges overlay onto base in place. Stricter settings win (e.g. higher retention, union frameworks).
//
//nolint:gocyclo // merge is inherently branchy per policy section
func mergeComplianceOverlay(base, overlay *policy.Policy) {
	if overlay.Policies.CostLimits != nil {
		if base.Policies.CostLimits == nil {
			base.Policies.CostLimits = overlay.Policies.CostLimits
		} else {
			if overlay.Policies.CostLimits.Daily > 0 {
				base.Policies.CostLimits.Daily = overlay.Policies.CostLimits.Daily
			}
			if overlay.Policies.CostLimits.Monthly > 0 {
				base.Policies.CostLimits.Monthly = overlay.Policies.CostLimits.Monthly
			}
		}
	}
	if overlay.Policies.RateLimits != nil {
		if base.Policies.RateLimits == nil {
			base.Policies.RateLimits = overlay.Policies.RateLimits
		} else {
			if overlay.Policies.RateLimits.RequestsPerMinute > 0 {
				base.Policies.RateLimits.RequestsPerMinute = overlay.Policies.RateLimits.RequestsPerMinute
			}
			if overlay.Policies.RateLimits.ConcurrentExecutions > 0 {
				base.Policies.RateLimits.ConcurrentExecutions = overlay.Policies.RateLimits.ConcurrentExecutions
			}
		}
	}
	if overlay.Policies.DataClassification != nil {
		if base.Policies.DataClassification == nil {
			base.Policies.DataClassification = overlay.Policies.DataClassification
		} else {
			base.Policies.DataClassification.InputScan = base.Policies.DataClassification.InputScan || overlay.Policies.DataClassification.InputScan
			base.Policies.DataClassification.OutputScan = base.Policies.DataClassification.OutputScan || overlay.Policies.DataClassification.OutputScan
			base.Policies.DataClassification.RedactPII = base.Policies.DataClassification.RedactPII || overlay.Policies.DataClassification.RedactPII
			base.Policies.DataClassification.BlockOnPII = base.Policies.DataClassification.BlockOnPII || overlay.Policies.DataClassification.BlockOnPII
		}
	}
	if overlay.Policies.ModelRouting != nil {
		if base.Policies.ModelRouting == nil {
			base.Policies.ModelRouting = overlay.Policies.ModelRouting
		} else {
			mergeModelRouting(base.Policies.ModelRouting, overlay.Policies.ModelRouting)
		}
	}
	if overlay.Policies.TimeRestrictions != nil {
		base.Policies.TimeRestrictions = overlay.Policies.TimeRestrictions
	}
	if overlay.Audit != nil {
		if base.Audit == nil {
			base.Audit = overlay.Audit
		} else {
			if overlay.Audit.RetentionDays > base.Audit.RetentionDays {
				base.Audit.RetentionDays = overlay.Audit.RetentionDays
			}
			if overlay.Audit.LogLevel != "" {
				base.Audit.LogLevel = overlay.Audit.LogLevel
			}
			base.Audit.IncludePrompts = base.Audit.IncludePrompts || overlay.Audit.IncludePrompts
			base.Audit.IncludeResponses = base.Audit.IncludeResponses || overlay.Audit.IncludeResponses
		}
	}
	if overlay.Compliance != nil {
		if base.Compliance == nil {
			base.Compliance = overlay.Compliance
		} else {
			base.Compliance.Frameworks = uniqueStrings(append(base.Compliance.Frameworks, overlay.Compliance.Frameworks...))
			if overlay.Compliance.DataResidency != "" {
				base.Compliance.DataResidency = overlay.Compliance.DataResidency
			}
			if overlay.Compliance.AIActRiskLevel != "" {
				base.Compliance.AIActRiskLevel = overlay.Compliance.AIActRiskLevel
			}
			if overlay.Compliance.HumanOversight != "" {
				base.Compliance.HumanOversight = overlay.Compliance.HumanOversight
			}
			if overlay.Compliance.PlanReview != nil {
				base.Compliance.PlanReview = overlay.Compliance.PlanReview
			}
		}
	}
}

func mergeModelRouting(base, overlay *policy.ModelRoutingConfig) {
	if overlay.Tier0 != nil {
		if base.Tier0 == nil {
			base.Tier0 = overlay.Tier0
		} else if overlay.Tier0.Location != "" {
			base.Tier0.Location = overlay.Tier0.Location
		}
	}
	if overlay.Tier1 != nil {
		if base.Tier1 == nil {
			base.Tier1 = overlay.Tier1
		} else {
			if overlay.Tier1.Location != "" {
				base.Tier1.Location = overlay.Tier1.Location
			}
			base.Tier1.BedrockOnly = base.Tier1.BedrockOnly || overlay.Tier1.BedrockOnly
		}
	}
	if overlay.Tier2 != nil {
		if base.Tier2 == nil {
			base.Tier2 = overlay.Tier2
		} else {
			if overlay.Tier2.Location != "" {
				base.Tier2.Location = overlay.Tier2.Location
			}
			base.Tier2.BedrockOnly = base.Tier2.BedrockOnly || overlay.Tier2.BedrockOnly
		}
	}
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func renderTemplate(tmplPath, outPath string, data interface{}) error {
	tmplContent, err := initTemplates.ReadFile(tmplPath)
	if err != nil {
		return fmt.Errorf("reading template %s: %w", tmplPath, err)
	}

	tmpl, err := template.New(outPath).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer out.Close()

	if err := tmpl.Execute(out, data); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return nil
}

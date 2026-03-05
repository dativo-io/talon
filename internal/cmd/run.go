package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	_ "github.com/dativo-io/talon/internal/llm/providers"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/pricing"
	"github.com/dativo-io/talon/internal/secrets"
)

var (
	runAgentName        string
	runTenantID         string
	runDryRun           bool
	runValidate         bool
	runAttachments      []string
	runPolicyPath       string
	runNoMemory         bool
	runActiveRunTracker = &agent.ActiveRunTracker{} // shared so rate-limit policy sees concurrent runs (e.g. multiple talon run in parallel)
)

var runCmd = &cobra.Command{
	Use:   "run [prompt]",
	Short: "Run an AI agent with policy enforcement",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgent,
}

func init() {
	runCmd.Flags().StringVar(&runAgentName, "agent", "default", "Agent name (when omitted, taken from the loaded policy file)")
	runCmd.Flags().StringVar(&runTenantID, "tenant", "default", "Tenant ID")
	runCmd.Flags().BoolVar(&runDryRun, "dry-run", false, "Show policy decision without LLM call")
	runCmd.Flags().BoolVar(&runValidate, "validate", false, "Validate policy before running (same as talon validate)")
	runCmd.Flags().StringSliceVar(&runAttachments, "attach", nil, "Attachment files")
	runCmd.Flags().StringVar(&runPolicyPath, "policy", "", "Path to .talon.yaml")
	runCmd.Flags().BoolVar(&runNoMemory, "no-memory", false, "Skip memory write for this run")
	rootCmd.AddCommand(runCmd)
}

//nolint:gocyclo // orchestration flow is inherently branched
func runAgent(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()

	ctx, span := tracer.Start(ctx, "cmd.run")
	defer span.End()

	prompt := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	cfg.WarnIfDefaultKeys()

	if verbose {
		log.Info().Msg("Initializing agent pipeline...")
	}

	policyPath := runPolicyPath
	if policyPath == "" {
		policyPath = cfg.DefaultPolicy
	}

	baseDir := "."
	safePath, err := policy.ResolvePathUnderBase(baseDir, policyPath)
	if err != nil {
		// Allow absolute paths (e.g. e2e or Docker): constrain to the path's directory.
		if filepath.IsAbs(filepath.Clean(policyPath)) {
			safePath, err = filepath.Abs(filepath.Clean(policyPath))
			if err != nil {
				return fmt.Errorf("policy path: %w", err)
			}
			baseDir = filepath.Dir(safePath)
			if _, err := policy.ResolvePathUnderBase(baseDir, safePath); err != nil {
				return fmt.Errorf("policy path: %w", err)
			}
		} else {
			return fmt.Errorf("policy path: %w", err)
		}
	}
	if _, err := os.Stat(safePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("policy file not found: %s — create a project first with: talon init", safePath)
		}
		return fmt.Errorf("policy file: %w", err)
	}
	policyPath = safePath
	baseDir = filepath.Dir(safePath) // so pricing and other project paths resolve relative to policy directory

	agentName := resolveRunAgentName(ctx, policyPath, baseDir, runAgentName)

	if runValidate {
		if err := validatePolicyFile(ctx, policyPath, baseDir); err != nil {
			return fmt.Errorf("pre-flight validation failed: %w", err)
		}
		if verbose {
			log.Info().Str("policy", policyPath).Msg("policy validated")
		}
	}

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(cfg.MaxAttachmentMB)

	providers := buildProviders(cfg)
	pricingTable := loadPricingTable(cfg, baseDir)
	injectPricingInProviders(providers, pricingTable)
	routing, costLimits := loadRoutingAndCostLimits(ctx, policyPath, baseDir)
	router := llm.NewRouter(routing, providers, costLimits)

	secretsStore, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	if err != nil {
		return fmt.Errorf("initializing secrets: %w", err)
	}
	defer secretsStore.Close()

	evidenceStore, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("initializing evidence: %w", err)
	}
	defer evidenceStore.Close()

	var memStore *memory.Store
	memStore, err = memory.NewStore(cfg.MemoryDBPath())
	if err != nil {
		log.Warn().Err(err).Msg("memory store unavailable, running without memory")
	} else {
		defer memStore.Close()
	}

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:        ".",
		Classifier:       cls,
		AttScanner:       attScanner,
		Extractor:        extractor,
		Router:           router,
		Secrets:          secretsStore,
		Evidence:         evidenceStore,
		ToolRegistry:     tools.NewRegistry(),
		ActiveRunTracker: runActiveRunTracker,
		Memory:           memStore,
		Pricing:          pricingTable,
	})

	var attachments []agent.Attachment
	for _, path := range runAttachments {
		content, err := os.ReadFile(path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("failed to read attachment")
			return fmt.Errorf("attachment file not found or unreadable: %s: %w", path, err)
		}
		attachments = append(attachments, agent.Attachment{
			Filename: filepath.Base(path),
			Content:  content,
		})
	}

	req := &agent.RunRequest{
		TenantID:       runTenantID,
		AgentName:      agentName,
		Prompt:         prompt,
		Attachments:    attachments,
		InvocationType: "manual",
		DryRun:         runDryRun,
		PolicyPath:     policyPath,
		SkipMemory:     runNoMemory,
	}
	if cfg.LLM != nil && cfg.LLM.Routing != nil && cfg.LLM.Routing.DataSovereigntyMode != "" {
		req.SovereigntyMode = cfg.LLM.Routing.DataSovereigntyMode
	}

	resp, err := runner.Run(ctx, req)
	if err != nil {
		return fmt.Errorf("running agent: %w", err)
	}

	if !resp.PolicyAllow {
		fmt.Printf("\u2717 Policy check: DENIED\n")
		fmt.Printf("  Reason: %s\n", resp.DenyReason)
		return nil
	}

	if runDryRun {
		fmt.Printf("\u2713 Policy check: ALLOWED (dry run, no LLM call)\n")
		if len(resp.PIIDetected) > 0 {
			fmt.Printf("  PII detected: %s (input tier: %d)\n", strings.Join(resp.PIIDetected, ", "), resp.InputTier)
		}
		if resp.AttachmentInjectionsDetected > 0 {
			if resp.AttachmentBlocked {
				fmt.Printf("  Attachment injection: %d pattern(s) detected — BLOCKED\n", resp.AttachmentInjectionsDetected)
			} else {
				fmt.Printf("  Attachment injection: %d pattern(s) detected (logged)\n", resp.AttachmentInjectionsDetected)
			}
		}
		return nil
	}

	if resp.PlanPending != "" {
		fmt.Printf("\u2713 Policy check: ALLOWED\n")
		fmt.Printf("\u2713 Plan pending human review: %s\n", resp.PlanPending)
		return nil
	}

	fmt.Printf("\u2713 Policy check: ALLOWED\n")
	fmt.Printf("\n%s\n\n", resp.Response)
	fmt.Printf("\u2713 Evidence stored: %s\n", resp.EvidenceID)
	fmt.Printf("\u2713 Cost: €%s | Duration: %dms\n", formatCost(resp.Cost), resp.DurationMS)

	return nil
}

// buildProviders creates LLM providers from OPERATOR-LEVEL environment variables
// via the provider registry. Ensures openai/anthropic/ollama are always registered
// so vault-only keys work. Use "talon secrets set openai-api-key <key>" etc.
func buildProviders(cfg *config.Config) map[string]llm.Provider {
	providers := make(map[string]llm.Provider)

	openaiCfg := map[string]string{"api_key": os.Getenv("OPENAI_API_KEY")}
	if baseURL := os.Getenv("OPENAI_BASE_URL"); baseURL != "" {
		openaiCfg["base_url"] = baseURL
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		log.Debug().Msg("OPENAI_API_KEY set — using as operator fallback (use vault for production)")
	}
	openaiYAML, _ := yaml.Marshal(openaiCfg)
	if p, err := llm.NewProvider("openai", openaiYAML); err == nil {
		providers["openai"] = p
	}

	anthropicCfg := map[string]string{"api_key": os.Getenv("ANTHROPIC_API_KEY")}
	anthropicYAML, _ := yaml.Marshal(anthropicCfg)
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		log.Debug().Msg("ANTHROPIC_API_KEY set — using as operator fallback (use vault for production)")
	}
	if p, err := llm.NewProvider("anthropic", anthropicYAML); err == nil {
		providers["anthropic"] = p
	}

	ollamaCfg := map[string]string{"base_url": cfg.OllamaBaseURL}
	if ollamaCfg["base_url"] == "" {
		ollamaCfg["base_url"] = "http://localhost:11434"
	}
	ollamaYAML, _ := yaml.Marshal(ollamaCfg)
	if p, err := llm.NewProvider("ollama", ollamaYAML); err == nil {
		providers["ollama"] = p
	}

	if region := os.Getenv("AWS_REGION"); region != "" {
		bedrockCfg := map[string]string{"region": region}
		bedrockYAML, _ := yaml.Marshal(bedrockCfg)
		if p, err := llm.NewProvider("bedrock", bedrockYAML); err == nil {
			providers["bedrock"] = p
		}
	}

	return providers
}

// loadPricingTable returns the pricing table from config path (or default).
// When pricingPath is relative, it is resolved against baseDir (directory containing the policy file)
// so that pricing/models.yaml is loaded from the project directory regardless of process CWD.
func loadPricingTable(cfg *config.Config, baseDir string) *pricing.PricingTable {
	pricingPath := config.DefaultPricingFile
	if cfg.LLM != nil && cfg.LLM.PricingFile != "" {
		pricingPath = cfg.LLM.PricingFile
	}
	if !filepath.IsAbs(pricingPath) && baseDir != "" {
		pricingPath = filepath.Join(baseDir, pricingPath)
	}
	return pricing.LoadOrDefault(pricingPath)
}

// injectPricingInProviders injects the pricing table into all providers that implement llm.PricingAware.
func injectPricingInProviders(providers map[string]llm.Provider, pt *pricing.PricingTable) {
	for _, p := range providers {
		if pa, ok := p.(llm.PricingAware); ok {
			pa.SetPricing(pt)
		}
	}
}

// validatePolicyFile runs the same checks as "talon validate" (schema, engine compile, PII scanner).
func validatePolicyFile(ctx context.Context, policyPath, baseDir string) error {
	pol, err := policy.LoadPolicy(ctx, policyPath, false, baseDir)
	if err != nil {
		return err
	}
	if _, err := policy.NewEngine(ctx, pol); err != nil {
		return fmt.Errorf("policy engine: %w", err)
	}
	if _, err := policy.NewPIIScannerForPolicy(pol, ""); err != nil {
		return fmt.Errorf("PII scanner: %w", err)
	}
	return nil
}

// resolveRunAgentName returns the agent name to use for the run. When runAgentName is the
// default "default", the name is read from the loaded policy file so that config and identity
// come from the same source; otherwise the flag value is used.
func resolveRunAgentName(ctx context.Context, policyPath, baseDir, runAgentName string) string {
	if runAgentName != "default" {
		return runAgentName
	}
	pol, err := policy.LoadPolicy(ctx, policyPath, false, baseDir)
	if err != nil {
		return "default"
	}
	if pol.Agent.Name == "" {
		return "default"
	}
	return pol.Agent.Name
}

// loadRoutingAndCostLimits loads the policy file and returns model routing and cost limits
// for the router (cost limits enable graceful degradation when budget threshold is hit).
func loadRoutingAndCostLimits(ctx context.Context, policyPath, baseDir string) (*policy.ModelRoutingConfig, *policy.CostLimitsConfig) {
	pol, err := policy.LoadPolicy(ctx, policyPath, false, baseDir)
	if err != nil {
		log.Debug().Err(err).Msg("could not pre-load policy for routing/cost config")
		return nil, nil
	}
	return pol.Policies.ModelRouting, pol.Policies.CostLimits
}

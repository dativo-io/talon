package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/cache"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	_ "github.com/dativo-io/talon/internal/llm/providers"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/pricing"
	talonprompt "github.com/dativo-io/talon/internal/prompt"
	"github.com/dativo-io/talon/internal/secrets"
	talonsession "github.com/dativo-io/talon/internal/session"
	"github.com/dativo-io/talon/internal/sovereignty"
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
	runCmd.Flags().StringVar(&runAgentName, "agent", "default", "Agent name. With agents_dir configured, any discovered agent runs under its OWN policy (#267); \"default\" resolves when exactly one agent is discovered. With --policy or a single default file, the name must match that file's agent.name")
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

	// Fleet source (#267): explicit --policy wins; otherwise agents_dir when
	// configured; otherwise the default single file. Every discovered agent
	// gets its own compiled bundle — `talon run --agent <name>` executes any
	// fleet agent under THAT agent's policy, engine, scanner, and routing.
	scan, err := cliAgentScan(ctx, cfg, runPolicyPath)
	if err != nil {
		return err
	}
	ra, err := resolveCatalogAgent(scan, runAgentName)
	if err != nil {
		return err
	}
	agentName := ra.Name
	baseDir := filepath.Dir(ra.Path) // pricing and other project paths resolve relative to the agent's directory

	if runValidate {
		if err := validatePolicyFile(ctx, filepath.Base(ra.Path), baseDir); err != nil {
			return fmt.Errorf("pre-flight validation failed: %w", err)
		}
		if verbose {
			log.Info().Str("policy", ra.Path).Msg("policy validated")
		}
	}

	// agent.tenant_id is authoritative across planes (#266): the same agent
	// file must attribute to the same tenant whether traffic crosses the
	// gateway or runs natively. The flag applies only when the file omits it.
	effectiveTenantID, err := resolveRunTenant(ra.Policy, runTenantID, cmd.Flags().Changed("tenant"))
	if err != nil {
		return err
	}
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(cfg.MaxAttachmentMB)

	sovereignty.ApplySovereigntyGate(cfg, nil)

	providers := buildProviders(cfg)
	pricingTable := loadPricingTable(cfg, baseDir)
	injectPricingInProviders(providers, pricingTable)
	catalog, err := buildCLICatalog(ctx, cfg, scan, providers)
	if err != nil {
		return err
	}

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
	sessionStore, err := talonsession.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return fmt.Errorf("initializing sessions: %w", err)
	}
	defer sessionStore.Close()
	promptStore, err := talonprompt.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return fmt.Errorf("initializing prompt store: %w", err)
	}
	defer promptStore.Close()

	var planReviewStore *agent.PlanReviewStore
	dbPlan, err := sql.Open("sqlite3", cfg.EvidenceDBPath()+"?_journal_mode=WAL&_busy_timeout=5000")
	if err == nil {
		defer dbPlan.Close()
		planReviewStore, err = agent.NewPlanReviewStore(dbPlan)
		if err != nil {
			log.Warn().Err(err).Msg("plan review store unavailable, plans will not be persisted")
			planReviewStore = nil
		}
	} else {
		log.Warn().Err(err).Msg("plan review DB unavailable")
	}

	var idempotencyStore *agent.IdempotencyStore
	dbIdem, err := sql.Open("sqlite3", cfg.EvidenceDBPath()+"?_journal_mode=WAL&_busy_timeout=5000")
	if err == nil {
		defer dbIdem.Close()
		idempotencyStore, err = agent.NewIdempotencyStore(dbIdem)
		if err != nil {
			log.Warn().Err(err).Msg("idempotency store unavailable")
			idempotencyStore = nil
		}
	} else {
		log.Warn().Err(err).Msg("idempotency DB unavailable")
	}

	var memStore *memory.Store
	memStore, err = memory.NewStore(cfg.MemoryDBPath())
	if err != nil {
		log.Warn().Err(err).Msg("memory store unavailable, running without memory")
	} else {
		defer memStore.Close()
	}

	runnerCfg := agent.RunnerConfig{
		Catalog:          catalog,
		PolicyDir:        ".",
		AttScanner:       attScanner,
		Extractor:        extractor,
		Secrets:          secretsStore,
		Evidence:         evidenceStore,
		PlanReview:       planReviewStore,
		SessionStore:     sessionStore,
		PromptStore:      promptStore,
		ToolRegistry:     tools.NewRegistry(),
		ActiveRunTracker: runActiveRunTracker,
		Memory:           memStore,
		Pricing:          pricingTable,
		Idempotency:      idempotencyStore,
	}
	if cfg.Cache != nil && cfg.Cache.Enabled {
		cacheStore, err := cache.NewStore(cfg.CacheDBPath(), cfg.SigningKey)
		if err != nil {
			log.Warn().Err(err).Msg("cache store unavailable, running without semantic cache")
		} else {
			defer cacheStore.Close()
			cachePolicy, err := cache.NewEvaluator(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("cache policy evaluator unavailable, running without semantic cache")
			} else {
				runnerCfg.CacheStore = cacheStore
				runnerCfg.CacheEmbedder = cache.NewBM25()
				runnerCfg.CachePolicy = cachePolicy
				runnerCfg.CacheConfig = &agent.RunnerCacheConfig{
					Enabled:             cfg.Cache.Enabled,
					DefaultTTL:          cfg.Cache.DefaultTTL,
					TTLByTier:           cfg.Cache.TTLByTier,
					SimilarityThreshold: cfg.Cache.SimilarityThreshold,
					MaxEntriesPerTenant: cfg.Cache.MaxEntriesPerTenant,
				}
			}
		}
	}
	runner := agent.NewRunner(runnerCfg)

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
		TenantID:       effectiveTenantID,
		AgentName:      agentName,
		Prompt:         prompt,
		Attachments:    attachments,
		InvocationType: "manual",
		DryRun:         runDryRun,
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
//
// When the effective sovereignty mode is eu_strict, providers that are not
// EU/LOCAL (and have no EU regions) are filtered out; explicitly declared
// non-sovereign providers are logged at ERROR by ApplySovereigntyGate.
func buildProviders(cfg *config.Config) map[string]llm.Provider {
	mode := cfg.EffectiveSovereigntyMode()
	providers := make(map[string]llm.Provider)

	registerRegion := func(providerType, region string, configYAML []byte) {
		if !sovereignty.AllowsProviderRegion(mode, providerType, region) {
			log.Debug().
				Str("provider", providerType).
				Str("region", region).
				Str("sovereignty_mode", mode).
				Msg("provider excluded by sovereignty mode")
			return
		}
		if p, err := llm.NewProvider(providerType, configYAML); err == nil {
			providers[providerType] = p
		}
	}
	register := func(providerType string, configYAML []byte) {
		registerRegion(providerType, "", configYAML)
	}

	openaiCfg := map[string]string{"api_key": os.Getenv("OPENAI_API_KEY")}
	if baseURL := os.Getenv("OPENAI_BASE_URL"); baseURL != "" {
		openaiCfg["base_url"] = baseURL
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		log.Debug().Msg("OPENAI_API_KEY set — using as operator fallback (use vault for production)")
	}
	openaiYAML, _ := yaml.Marshal(openaiCfg)
	register("openai", openaiYAML)

	anthropicCfg := map[string]string{"api_key": os.Getenv("ANTHROPIC_API_KEY")}
	anthropicYAML, _ := yaml.Marshal(anthropicCfg)
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		log.Debug().Msg("ANTHROPIC_API_KEY set — using as operator fallback (use vault for production)")
	}
	register("anthropic", anthropicYAML)

	ollamaCfg := struct {
		BaseURL       string `yaml:"base_url"`
		MaxNumPredict *int   `yaml:"max_num_predict,omitempty"`
	}{BaseURL: cfg.OllamaBaseURL}
	if ollamaCfg.BaseURL == "" {
		ollamaCfg.BaseURL = "http://localhost:11434"
	}
	// Opt-in output ceiling for slow local hosts; omitted (nil) unless set, so
	// the provider honors the caller's MaxTokens verbatim by default.
	if cfg.OllamaMaxNumPredict > 0 {
		n := cfg.OllamaMaxNumPredict
		ollamaCfg.MaxNumPredict = &n
	}
	ollamaYAML, _ := yaml.Marshal(ollamaCfg)
	register("ollama", ollamaYAML)

	if region := os.Getenv("AWS_REGION"); region != "" {
		bedrockCfg := map[string]string{"region": region}
		bedrockYAML, _ := yaml.Marshal(bedrockCfg)
		registerRegion("bedrock", region, bedrockYAML)
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

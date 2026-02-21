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

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

var (
	runAgentName        string
	runTenantID         string
	runDryRun           bool
	runValidate         bool
	runAttachments      []string
	runPolicyPath       string
	runActiveRunTracker = &agent.ActiveRunTracker{} // shared so rate-limit policy sees concurrent runs (e.g. multiple talon run in parallel)
)

var runCmd = &cobra.Command{
	Use:   "run [prompt]",
	Short: "Run an AI agent with policy enforcement",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgent,
}

func init() {
	runCmd.Flags().StringVar(&runAgentName, "agent", "default", "Agent name")
	runCmd.Flags().StringVar(&runTenantID, "tenant", "default", "Tenant ID")
	runCmd.Flags().BoolVar(&runDryRun, "dry-run", false, "Show policy decision without LLM call")
	runCmd.Flags().BoolVar(&runValidate, "validate", false, "Validate policy before running (same as talon validate)")
	runCmd.Flags().StringSliceVar(&runAttachments, "attach", nil, "Attachment files")
	runCmd.Flags().StringVar(&runPolicyPath, "policy", "", "Path to .talon.yaml")
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

	if _, err := os.Stat(policyPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("policy file not found: %s — create a project first with: talon init", policyPath)
		}
		return fmt.Errorf("policy file: %w", err)
	}

	if runValidate {
		if err := validatePolicyFile(ctx, policyPath); err != nil {
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
	routing, costLimits := loadRoutingAndCostLimits(ctx, policyPath)
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
	})

	var attachments []agent.Attachment
	for _, path := range runAttachments {
		content, err := os.ReadFile(path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("failed to read attachment")
			continue
		}
		attachments = append(attachments, agent.Attachment{
			Filename: filepath.Base(path),
			Content:  content,
		})
	}

	req := &agent.RunRequest{
		TenantID:       runTenantID,
		AgentName:      runAgentName,
		Prompt:         prompt,
		Attachments:    attachments,
		InvocationType: "manual",
		DryRun:         runDryRun,
		PolicyPath:     policyPath,
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
	fmt.Printf("\u2713 Cost: \u20ac%.4f | Duration: %dms\n", resp.Cost, resp.DurationMS)

	return nil
}

// buildProviders creates LLM providers from OPERATOR-LEVEL environment variables
// and ensures openai/anthropic are always registered so vault-only keys work.
//
// Env vars (OPENAI_API_KEY, ANTHROPIC_API_KEY) are used as fallbacks when set.
// When not set, the provider is still registered with an empty key; the runner
// resolves the key from the vault at request time (resolveProvider). Use
// "talon secrets set openai-api-key <key>" or "talon secrets set anthropic-api-key <key>".
func buildProviders(cfg *config.Config) map[string]llm.Provider {
	providers := make(map[string]llm.Provider)

	// OpenAI: env fallback or placeholder so vault-only works
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		log.Debug().Msg("OPENAI_API_KEY set — using as operator fallback (use vault for production)")
		if baseURL := os.Getenv("OPENAI_BASE_URL"); baseURL != "" {
			providers["openai"] = llm.NewOpenAIProviderWithBaseURL(key, baseURL)
		} else {
			providers["openai"] = llm.NewOpenAIProvider(key)
		}
	} else {
		providers["openai"] = llm.NewOpenAIProvider("")
	}
	// Anthropic: env fallback or placeholder so vault-only works
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		log.Debug().Msg("ANTHROPIC_API_KEY set — using as operator fallback (use vault for production)")
		providers["anthropic"] = llm.NewAnthropicProvider(key)
	} else {
		providers["anthropic"] = llm.NewAnthropicProvider("")
	}

	providers["ollama"] = llm.NewOllamaProvider(cfg.OllamaBaseURL)

	if region := os.Getenv("AWS_REGION"); region != "" {
		providers["bedrock"] = llm.NewBedrockProvider(region)
	}

	return providers
}

// validatePolicyFile runs the same checks as "talon validate" (schema, engine compile, PII scanner).
func validatePolicyFile(ctx context.Context, policyPath string) error {
	pol, err := policy.LoadPolicy(ctx, policyPath, false)
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

// loadRoutingAndCostLimits loads the policy file and returns model routing and cost limits
// for the router (cost limits enable graceful degradation when budget threshold is hit).
func loadRoutingAndCostLimits(ctx context.Context, policyPath string) (*policy.ModelRoutingConfig, *policy.CostLimitsConfig) {
	pol, err := policy.LoadPolicy(ctx, policyPath, false)
	if err != nil {
		log.Debug().Err(err).Msg("could not pre-load policy for routing/cost config")
		return nil, nil
	}
	return pol.Policies.ModelRouting, pol.Policies.CostLimits
}

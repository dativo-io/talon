package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

var (
	runAgentName   string
	runTenantID    string
	runDryRun      bool
	runAttachments []string
	runPolicyPath  string
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
	runCmd.Flags().StringSliceVar(&runAttachments, "attach", nil, "Attachment files")
	runCmd.Flags().StringVar(&runPolicyPath, "policy", "", "Path to .talon.yaml")
	rootCmd.AddCommand(runCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()

	_, span := tracer.Start(ctx, "cmd.run")
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

	cls := classifier.MustNewScanner()
	attScanner := attachment.MustNewScanner()
	extractor := attachment.NewExtractor(cfg.MaxAttachmentMB)

	providers := buildProviders(cfg)
	routing := loadRoutingConfig(ctx, policyPath)
	router := llm.NewRouter(routing, providers)

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

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:    ".",
		Classifier:   cls,
		AttScanner:   attScanner,
		Extractor:    extractor,
		Router:       router,
		Secrets:      secretsStore,
		Evidence:     evidenceStore,
		ToolRegistry: tools.NewRegistry(),
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
		return nil
	}

	fmt.Printf("\u2713 Policy check: ALLOWED\n")
	fmt.Printf("\n%s\n\n", resp.Response)
	fmt.Printf("\u2713 Evidence stored: %s\n", resp.EvidenceID)
	fmt.Printf("\u2713 Cost: \u20ac%.4f | Duration: %dms\n", resp.CostEUR, resp.DurationMS)

	return nil
}

// buildProviders creates LLM providers from OPERATOR-LEVEL environment variables.
//
// These are fallback providers for single-tenant development / quickstart.
// In production, tenant-scoped API keys should be stored in the secrets
// vault via "talon secrets set <provider>-api-key <key>". The agent runner
// resolves vault keys at runtime and overrides these fallbacks per-request.
func buildProviders(cfg *config.Config) map[string]llm.Provider {
	providers := make(map[string]llm.Provider)

	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		log.Debug().Msg("OPENAI_API_KEY set — using as operator fallback (use vault for production)")
		providers["openai"] = llm.NewOpenAIProvider(key)
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		log.Debug().Msg("ANTHROPIC_API_KEY set — using as operator fallback (use vault for production)")
		providers["anthropic"] = llm.NewAnthropicProvider(key)
	}

	providers["ollama"] = llm.NewOllamaProvider(cfg.OllamaBaseURL)

	if region := os.Getenv("AWS_REGION"); region != "" {
		providers["bedrock"] = llm.NewBedrockProvider(region)
	}

	return providers
}

// loadRoutingConfig attempts to load model routing from the policy file.
func loadRoutingConfig(ctx context.Context, policyPath string) *policy.ModelRoutingConfig {
	pol, err := policy.LoadPolicy(ctx, policyPath, false)
	if err != nil {
		log.Debug().Err(err).Msg("could not pre-load policy for routing config")
		return nil
	}
	return pol.Policies.ModelRouting
}

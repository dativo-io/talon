package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/cache"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	_ "github.com/dativo-io/talon/internal/llm/providers"
	"github.com/dativo-io/talon/internal/memory"
	"github.com/dativo-io/talon/internal/policy"
	talonprompt "github.com/dativo-io/talon/internal/prompt"
	"github.com/dativo-io/talon/internal/secrets"
	talonsession "github.com/dativo-io/talon/internal/session"
)

var (
	planTenantID     string
	planReviewedBy   string
	planRejectReason string
	planApproverKey  string
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Inspect and execute reviewed plans",
}

var planPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending plans for review",
	RunE:  runPlanPending,
}

var planApproveCmd = &cobra.Command{
	Use:   "approve [plan-id]",
	Short: "Approve a pending plan",
	Args:  cobra.ExactArgs(1),
	RunE:  runPlanApprove,
}

var planRejectCmd = &cobra.Command{
	Use:   "reject [plan-id]",
	Short: "Reject a pending plan",
	Args:  cobra.ExactArgs(1),
	RunE:  runPlanReject,
}

var planExecuteCmd = &cobra.Command{
	Use:   "execute [plan-id]",
	Short: "Execute an approved plan in non-serve mode",
	Args:  cobra.ExactArgs(1),
	RunE:  runPlanExecute,
}

func init() {
	planPendingCmd.Flags().StringVar(&planTenantID, "tenant", "default", "Tenant ID")
	planApproveCmd.Flags().StringVar(&planTenantID, "tenant", "default", "Tenant ID")
	planApproveCmd.Flags().StringVar(&planReviewedBy, "reviewed-by", "cli", "Reviewer identity")
	planApproveCmd.Flags().StringVar(&planApproverKey, "key", "", "Approver bearer key (talon_appr_...)")
	planRejectCmd.Flags().StringVar(&planTenantID, "tenant", "default", "Tenant ID")
	planRejectCmd.Flags().StringVar(&planReviewedBy, "reviewed-by", "cli", "Reviewer identity")
	planRejectCmd.Flags().StringVar(&planRejectReason, "reason", "rejected in CLI", "Rejection reason")
	planRejectCmd.Flags().StringVar(&planApproverKey, "key", "", "Approver bearer key (talon_appr_...)")
	planExecuteCmd.Flags().StringVar(&planTenantID, "tenant", "default", "Tenant ID")
	planCmd.AddCommand(planPendingCmd)
	planCmd.AddCommand(planApproveCmd)
	planCmd.AddCommand(planRejectCmd)
	planCmd.AddCommand(planExecuteCmd)
	rootCmd.AddCommand(planCmd)
}

func openPlanReviewStore() (*agent.PlanReviewStore, *evidence.Store, *sql.DB, *config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("creating data directory: %w", err)
	}
	cfg.WarnIfDefaultKeys()
	evidenceStore, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("initializing evidence: %w", err)
	}
	dbPlan, err := sql.Open("sqlite3", cfg.EvidenceDBPath()+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		evidenceStore.Close()
		return nil, nil, nil, nil, fmt.Errorf("opening plan review DB: %w", err)
	}
	planReviewStore, err := agent.NewPlanReviewStore(dbPlan)
	if err != nil {
		dbPlan.Close()
		evidenceStore.Close()
		return nil, nil, nil, nil, fmt.Errorf("plan review store unavailable: %w", err)
	}
	return planReviewStore, evidenceStore, dbPlan, cfg, nil
}

func runPlanPending(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	store, evidenceStore, dbPlan, cfg, err := openPlanReviewStore()
	if err != nil {
		return err
	}
	defer evidenceStore.Close()
	defer dbPlan.Close()
	if planApproverKey != "" {
		approverStore, aerr := approver.NewStore(cfg.EvidenceDBPath())
		if aerr != nil {
			return aerr
		}
		defer approverStore.Close()
		if rec, aerr := approverStore.Resolve(ctx, planApproverKey); aerr == nil && rec != nil {
			planReviewedBy = rec.Name
		}
	}

	plans, err := store.GetPending(ctx, planTenantID)
	if err != nil {
		return fmt.Errorf("listing pending plans: %w", err)
	}
	if len(plans) == 0 {
		fmt.Println("No pending plans.")
		return nil
	}
	for _, p := range plans {
		fmt.Printf("%s\t%s\t%s\t%s\n", p.ID, p.TenantID, p.AgentID, p.CreatedAt.Format(time.RFC3339))
	}
	return nil
}

func runPlanApprove(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	store, evidenceStore, dbPlan, cfg, err := openPlanReviewStore()
	if err != nil {
		return err
	}
	defer evidenceStore.Close()
	defer dbPlan.Close()
	if planApproverKey != "" {
		approverStore, aerr := approver.NewStore(cfg.EvidenceDBPath())
		if aerr != nil {
			return aerr
		}
		defer approverStore.Close()
		if rec, aerr := approverStore.Resolve(ctx, planApproverKey); aerr == nil && rec != nil {
			planReviewedBy = rec.Name
		}
	}

	plan, err := store.Get(ctx, args[0], planTenantID)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			return fmt.Errorf("plan %s not found for tenant %s", args[0], planTenantID)
		}
		return fmt.Errorf("loading plan %s: %w", args[0], err)
	}
	if err := store.Approve(ctx, args[0], planTenantID, planReviewedBy); err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			return fmt.Errorf("plan %s not found for tenant %s", args[0], planTenantID)
		}
		if errors.Is(err, agent.ErrPlanNotPending) {
			return fmt.Errorf("plan %s is not pending", args[0])
		}
		return fmt.Errorf("approving plan %s: %w", args[0], err)
	}
	gen := evidence.NewGenerator(evidenceStore)
	_, _ = gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  plan.CorrelationID,
		SessionID:      plan.SessionID,
		TenantID:       plan.TenantID,
		AgentID:        plan.AgentID,
		InvocationType: "plan_review",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  "plan_approved",
			Reasons: []string{"human_oversight"},
		},
		Classification: evidence.Classification{},
		InputPrompt:    "plan_approved:" + plan.ID,
		OutputResponse: planReviewedBy,
		PlanReview: &evidence.PlanReviewEvent{
			PlanID:         plan.ID,
			EventType:      "plan_approved",
			ReviewedBy:     planReviewedBy,
			PreviousStatus: string(plan.Status),
		},
	})
	fmt.Printf("✓ Plan approved: %s\n", args[0])
	return nil
}

func runPlanReject(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	store, evidenceStore, dbPlan, _, err := openPlanReviewStore()
	if err != nil {
		return err
	}
	defer evidenceStore.Close()
	defer dbPlan.Close()

	plan, err := store.Get(ctx, args[0], planTenantID)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			return fmt.Errorf("plan %s not found for tenant %s", args[0], planTenantID)
		}
		return fmt.Errorf("loading plan %s: %w", args[0], err)
	}
	if err := store.Reject(ctx, args[0], planTenantID, planReviewedBy, planRejectReason); err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			return fmt.Errorf("plan %s not found for tenant %s", args[0], planTenantID)
		}
		if errors.Is(err, agent.ErrPlanNotPending) {
			return fmt.Errorf("plan %s is not pending", args[0])
		}
		return fmt.Errorf("rejecting plan %s: %w", args[0], err)
	}
	gen := evidence.NewGenerator(evidenceStore)
	_, _ = gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  plan.CorrelationID,
		SessionID:      plan.SessionID,
		TenantID:       plan.TenantID,
		AgentID:        plan.AgentID,
		InvocationType: "plan_review",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  "plan_rejected",
			Reasons: []string{"human_oversight"},
		},
		Classification: evidence.Classification{},
		InputPrompt:    "plan_rejected:" + plan.ID,
		OutputResponse: planReviewedBy,
		PlanReview: &evidence.PlanReviewEvent{
			PlanID:         plan.ID,
			EventType:      "plan_rejected",
			ReviewedBy:     planReviewedBy,
			PreviousStatus: string(plan.Status),
			Reason:         planRejectReason,
		},
	})
	fmt.Printf("✓ Plan rejected: %s\n", args[0])
	return nil
}

//nolint:gocyclo // orchestration flow is inherently branched
func runPlanExecute(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()

	planID := args[0]
	planReviewStore, evidenceStore, dbPlan, cfg, err := openPlanReviewStore()
	if err != nil {
		return err
	}
	defer evidenceStore.Close()
	defer dbPlan.Close()
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

	plan, err := planReviewStore.Get(ctx, planID, planTenantID)
	if err != nil {
		if errors.Is(err, agent.ErrPlanNotFound) {
			return fmt.Errorf("plan %s not found for tenant %s", planID, planTenantID)
		}
		return fmt.Errorf("loading plan %s: %w", planID, err)
	}
	if plan.Status != agent.PlanApproved {
		return fmt.Errorf("plan %s is %q, must be %q before execute", plan.ID, plan.Status, agent.PlanApproved)
	}
	if plan.Prompt == "" {
		return fmt.Errorf("plan %s cannot be executed: prompt is empty", plan.ID)
	}

	baseDir := "."
	policyPath := plan.PolicyPath
	if policyPath == "" {
		policyPath = cfg.DefaultPolicy
	}
	safePath, err := policy.ResolvePathUnderBase(baseDir, policyPath)
	if err != nil {
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
	policyPath = safePath
	baseDir = filepath.Dir(safePath)

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

	var memStore *memory.Store
	memStore, err = memory.NewStore(cfg.MemoryDBPath())
	if err != nil {
		log.Warn().Err(err).Msg("memory store unavailable, running without memory")
	} else {
		defer memStore.Close()
	}

	runnerCfg := agent.RunnerConfig{
		PolicyDir:        ".",
		Classifier:       cls,
		AttScanner:       attScanner,
		Extractor:        extractor,
		Router:           router,
		Secrets:          secretsStore,
		Evidence:         evidenceStore,
		SessionStore:     sessionStore,
		PromptStore:      promptStore,
		PlanReview:       planReviewStore,
		ToolRegistry:     tools.NewRegistry(),
		ActiveRunTracker: runActiveRunTracker,
		Memory:           memStore,
		Pricing:          pricingTable,
	}
	if cfg.Cache != nil && cfg.Cache.Enabled {
		cacheStore, cacheErr := cache.NewStore(cfg.CacheDBPath(), cfg.SigningKey)
		if cacheErr != nil {
			log.Warn().Err(cacheErr).Msg("cache store unavailable, running without semantic cache")
		} else {
			defer cacheStore.Close()
			cachePolicy, cacheEvalErr := cache.NewEvaluator(ctx)
			if cacheEvalErr != nil {
				log.Warn().Err(cacheEvalErr).Msg("cache policy evaluator unavailable, running without semantic cache")
			} else {
				runnerCfg.CacheStore = cacheStore
				runnerCfg.CacheEmbedder = cache.NewBM25()
				runnerCfg.CacheScrubber = cache.NewPIIScrubber(cls)
				runnerCfg.CachePolicy = cachePolicy
				runnerCfg.CacheConfig = &agent.RunnerCacheConfig{
					Enabled:             cfg.Cache.Enabled,
					DefaultTTL:          cfg.Cache.DefaultTTL,
					SimilarityThreshold: cfg.Cache.SimilarityThreshold,
					MaxEntriesPerTenant: cfg.Cache.MaxEntriesPerTenant,
				}
			}
		}
	}
	runner := agent.NewRunner(runnerCfg)

	resp, err := runner.Run(ctx, &agent.RunRequest{
		TenantID:         plan.TenantID,
		AgentName:        plan.AgentID,
		Prompt:           plan.Prompt,
		SessionID:        plan.SessionID,
		InvocationType:   "plan_dispatch_manual",
		PolicyPath:       policyPath,
		BypassPlanReview: true,
	})
	if err != nil {
		_ = planReviewStore.MarkDispatched(ctx, plan.ID, plan.TenantID, "manual execute failed: "+err.Error())
		return fmt.Errorf("executing approved plan %s: %w", plan.ID, err)
	}
	if !resp.PolicyAllow {
		msg := "manual execute denied by policy"
		if resp.DenyReason != "" {
			msg += ": " + resp.DenyReason
		}
		_ = planReviewStore.MarkDispatched(ctx, plan.ID, plan.TenantID, msg)
		return fmt.Errorf("approved plan execution denied: %s", resp.DenyReason)
	}
	if err := planReviewStore.MarkDispatched(ctx, plan.ID, plan.TenantID, ""); err != nil {
		log.Warn().Err(err).Str("plan_id", plan.ID).Str("tenant_id", plan.TenantID).Msg("mark_dispatched_failed_after_manual_execute")
	}

	fmt.Printf("✓ Executed approved plan: %s\n", plan.ID)
	fmt.Printf("\n%s\n\n", resp.Response)
	fmt.Printf("✓ Evidence stored: %s\n", resp.EvidenceID)
	fmt.Printf("✓ Cost: €%s | Duration: %dms\n", formatCost(resp.Cost), resp.DurationMS)
	return nil
}

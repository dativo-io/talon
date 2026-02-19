// Package agent implements the core agent orchestration pipeline.
//
// The pipeline executes in a fixed sequence: load policy → classify input →
// scan attachments → evaluate OPA policy → resolve secrets → route LLM →
// call provider → classify output → generate evidence. Every invocation
// produces a signed evidence record, even on failures or policy denials.
//
// Extension points:
//   - Hooks: register pre/post callbacks at any pipeline stage (see HookRegistry).
//   - Plan review: gate LLM calls behind human approval (see PlanReviewStore).
//   - Tools: register MCP-compatible tools via agent/tools.ToolRegistry.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	talonctx "github.com/dativo-io/talon/internal/context"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/memory"
	talonotel "github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/agent")

// Runner executes the full agent orchestration pipeline.
type Runner struct {
	policyDir         string
	defaultPolicyPath string // used by RunFromTrigger when PolicyPath is not set (e.g. serve uses cfg.DefaultPolicy)
	classifier        *classifier.Scanner
	attScanner        *attachment.Scanner
	extractor         *attachment.Extractor
	router            *llm.Router
	secrets           *secrets.SecretStore
	evidence          *evidence.Generator
	evidenceStore     *evidence.Store
	planReview        *PlanReviewStore
	toolRegistry      *tools.ToolRegistry
	hooks             *HookRegistry
	memory            *memory.Store
	governance        *memory.Governance
}

// RunnerConfig holds the dependencies for constructing a Runner.
type RunnerConfig struct {
	PolicyDir         string // base directory for policy path resolution
	DefaultPolicyPath string // path to default .talon.yaml (e.g. agent.talon.yaml); used by RunFromTrigger when request has no PolicyPath
	Classifier        *classifier.Scanner
	AttScanner        *attachment.Scanner
	Extractor         *attachment.Extractor
	Router            *llm.Router
	Secrets           *secrets.SecretStore
	Evidence          *evidence.Store
	PlanReview        *PlanReviewStore
	ToolRegistry      *tools.ToolRegistry
	Hooks             *HookRegistry // optional; nil = no hooks
	Memory            *memory.Store // optional; nil = memory disabled
}

// NewRunner creates an agent runner with the given dependencies.
func NewRunner(cfg RunnerConfig) *Runner {
	r := &Runner{
		policyDir:         cfg.PolicyDir,
		defaultPolicyPath: cfg.DefaultPolicyPath,
		classifier:        cfg.Classifier,
		attScanner:        cfg.AttScanner,
		extractor:         cfg.Extractor,
		router:            cfg.Router,
		secrets:           cfg.Secrets,
		evidence:          evidence.NewGenerator(cfg.Evidence),
		evidenceStore:     cfg.Evidence,
		planReview:        cfg.PlanReview,
		toolRegistry:      cfg.ToolRegistry,
		hooks:             cfg.Hooks,
		memory:            cfg.Memory,
	}
	if cfg.Memory != nil && cfg.Classifier != nil {
		r.governance = memory.NewGovernance(cfg.Memory, cfg.Classifier)
	}
	return r
}

// RunRequest is the input for a single agent invocation.
type RunRequest struct {
	TenantID       string
	AgentName      string
	Prompt         string
	Attachments    []Attachment
	InvocationType string // "manual", "scheduled", "webhook:name"
	DryRun         bool
	PolicyPath     string // explicit path to .talon.yaml
}

// Attachment is a file attached to a run request.
type Attachment struct {
	Filename string
	Content  []byte
}

// RunResponse is the output of an agent invocation.
type RunResponse struct {
	Response    string
	EvidenceID  string
	CostEUR     float64
	DurationMS  int64
	PolicyAllow bool
	DenyReason  string
	PlanPending string   // set when execution is gated for human review (EU AI Act Art. 14)
	ModelUsed   string   // LLM model used for generation
	ToolsCalled []string // MCP tools invoked
}

// Run executes the complete agent pipeline:
//  1. Load policy
//  2. Classify input (PII detection)
//  3. Process attachments (extract + scan + sandbox)
//  4. Evaluate policy (OPA)
//  5. Check secrets access
//  6. Route LLM (tier-based)
//  7. Call LLM provider
//  8. Classify output
//  9. Generate evidence
//
//nolint:gocyclo // orchestration flow is inherently branched; splitting would obscure the pipeline
func (r *Runner) Run(ctx context.Context, req *RunRequest) (*RunResponse, error) {
	startTime := time.Now()
	correlationID := "corr_" + uuid.New().String()[:12]

	ctx, span := tracer.Start(ctx, "agent.run",
		trace.WithAttributes(
			attribute.String("correlation_id", correlationID),
			attribute.String("tenant_id", req.TenantID),
			attribute.String("agent_id", req.AgentName),
			attribute.String("invocation_type", req.InvocationType),
			attribute.Bool("dry_run", req.DryRun),
		))
	defer span.End()

	log.Info().
		Str("correlation_id", correlationID).
		Str("tenant_id", req.TenantID).
		Str("agent_id", req.AgentName).
		Msg("agent_run_started")

	// Step 1: Load policy
	policyPath := req.PolicyPath
	if policyPath == "" {
		policyPath = filepath.Join(r.policyDir, req.AgentName+".talon.yaml")
	}

	pol, err := policy.LoadPolicy(ctx, policyPath, false)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	// Step 2: Classify input
	inputClass := r.classifier.Scan(ctx, req.Prompt)
	inputEntityNames := entityNames(inputClass.Entities)
	span.SetAttributes(
		attribute.Int("classification.input_tier", inputClass.Tier),
		attribute.StringSlice("classification.pii_detected", inputEntityNames),
	)

	// Step 3: Scan attachments
	processedPrompt, attachmentScan, err := r.processAttachments(ctx, req, pol)
	if err != nil {
		return nil, err
	}
	if attachmentScan != nil {
		span.SetAttributes(
			attribute.Int("attachments.processed", attachmentScan.FilesProcessed),
			attribute.Int("attachments.injections", attachmentScan.InjectionsDetected),
		)
	}

	// Step 4: Evaluate policy (with real cost totals for budget checks)
	var dailyCost, monthlyCost float64
	if r.evidenceStore != nil {
		now := time.Now().UTC()
		dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		dayEnd := dayStart.Add(24 * time.Hour)
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		monthEnd := monthStart.AddDate(0, 1, 0)
		dailyCost, _ = r.evidenceStore.CostTotal(ctx, req.TenantID, "", dayStart, dayEnd)
		monthlyCost, _ = r.evidenceStore.CostTotal(ctx, req.TenantID, "", monthStart, monthEnd)
	}
	costCtx := &llm.CostContext{
		DailyTotal:   dailyCost,
		MonthlyTotal: monthlyCost,
		AgentName:    req.AgentName,
		TenantID:     req.TenantID,
	}

	engine, err := policy.NewEngine(ctx, pol)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("creating policy engine: %w", err)
	}

	// Wire OPA engine into memory governance for unified policy enforcement.
	if r.governance != nil {
		r.governance.SetPolicyEvaluator(engine)
	}

	policyInput := map[string]interface{}{
		"tenant_id":          req.TenantID,
		"agent_id":           req.AgentName,
		"tier":               inputClass.Tier,
		"estimated_cost":     0.01,
		"daily_cost_total":   dailyCost,
		"monthly_cost_total": monthlyCost,
	}

	decision, err := engine.Evaluate(ctx, policyInput)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("evaluating policy: %w", err)
	}

	complianceInfo := complianceFromPolicy(pol)

	// Hook: post-policy (fires for both allow and deny)
	if resp, err := r.checkHook(ctx, HookPostPolicy, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
		"decision": boolToDecision(decision.Allowed),
		"action":   decision.Action,
		"tier":     inputClass.Tier,
	}); resp != nil || err != nil {
		return resp, err
	}

	if !decision.Allowed {
		r.recordPolicyDenial(ctx, span, correlationID, req, pol, decision, inputClass.Tier, inputEntityNames, attachmentScan, complianceInfo)
		return &RunResponse{PolicyAllow: false, DenyReason: decision.Action}, nil
	}

	if req.DryRun {
		return &RunResponse{PolicyAllow: true}, nil
	}

	// Step 4.5: Plan Review Gate (EU AI Act Art. 14)
	if resp, err := r.checkHook(ctx, HookPrePlanReview, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
		"tier": inputClass.Tier,
	}); resp != nil || err != nil {
		return resp, err
	}

	resp, ok, err := r.maybeGateForPlanReview(ctx, pol, req, correlationID, inputClass.Tier, processedPrompt)
	if err != nil {
		return nil, err
	}
	if ok {
		_, _ = r.fireHook(ctx, HookPostPlanReview, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
			"plan_id": resp.PlanPending,
			"gated":   true,
		})
		return resp, nil
	}

	// Step 4.75: Pre-LLM memory + context enrichment
	finalPrompt := processedPrompt
	effectiveTier := inputClass.Tier
	var memoryReads []evidence.MemoryRead

	var memoryTokens int

	if pol.Memory != nil && pol.Memory.Enabled && r.memory != nil {
		memIndex, memErr := r.memory.ListIndex(ctx, req.TenantID, req.AgentName, 50)
		if memErr != nil {
			log.Warn().Err(memErr).Msg("failed to load memory index")
		} else if len(memIndex) > 0 {
			// Filter by prompt_categories so operators control which categories enter context
			if len(pol.Memory.PromptCategories) > 0 {
				memIndex = filterByPromptCategories(memIndex, pol.Memory.PromptCategories)
			}

			// Apply max_prompt_tokens cap: evict oldest/lowest-trust entries if over budget
			if pol.Memory.MaxPromptTokens > 0 {
				memIndex = capMemoryByTokens(memIndex, pol.Memory.MaxPromptTokens)
			}

			memPrompt := formatMemoryIndexForPrompt(memIndex)
			finalPrompt = memPrompt + "\n\n" + finalPrompt
			memoryTokens = len(memPrompt) / 4

			for i := range memIndex {
				memoryReads = append(memoryReads, evidence.MemoryRead{
					EntryID:    memIndex[i].ID,
					TrustScore: memIndex[i].TrustScore,
				})
			}

			span.SetAttributes(attribute.Int("memory.tokens_injected", memoryTokens))

			// Re-classify memory content to detect tier upgrades from persisted
			// classified data — prevents sending tier-1/tier-2 memory content
			// to a lower-tier model (data sovereignty protection).
			memClass := r.classifier.Scan(ctx, memPrompt)
			if memClass.Tier > effectiveTier {
				effectiveTier = memClass.Tier
				span.SetAttributes(attribute.Int("classification.tier_upgraded_by_memory", effectiveTier))
			}
		}
	}

	if pol.Context != nil && len(pol.Context.SharedMounts) > 0 {
		sharedCtx, ctxErr := talonctx.LoadSharedContext(pol)
		if ctxErr != nil {
			log.Warn().Err(ctxErr).Msg("failed to load shared context")
		} else if len(sharedCtx.Mounts) > 0 {
			ctxPrompt := sharedCtx.FormatForPrompt()
			if ctxPrompt != "" {
				finalPrompt = ctxPrompt + "\n\n" + finalPrompt
			}
			if sharedCtx.GetMaxTier() > effectiveTier {
				effectiveTier = sharedCtx.GetMaxTier()
				span.SetAttributes(attribute.Int("classification.tier_upgraded_to", effectiveTier))
			}
			for _, m := range sharedCtx.Mounts {
				if m.PrivateStripped > 0 {
					log.Info().Str("mount", m.Name).Int("stripped", m.PrivateStripped).Msg("private_tags_stripped_from_context")
				}
			}
		}
	}

	return r.executeLLMPipeline(ctx, span, startTime, correlationID, req, pol,
		effectiveTier, inputEntityNames, finalPrompt, attachmentScan, complianceInfo, costCtx, memoryReads, memoryTokens)
}

// checkHook fires a hook and returns a deny RunResponse if the hook aborts the pipeline.
// Returns (nil, nil) when the hook allows continuation.
func (r *Runner) checkHook(ctx context.Context, point HookPoint, tenantID, agentID, correlationID string, payload interface{}) (*RunResponse, error) {
	cont, err := r.fireHook(ctx, point, tenantID, agentID, correlationID, payload)
	if err != nil {
		return nil, fmt.Errorf("%s hook: %w", point, err)
	}
	if !cont {
		return &RunResponse{PolicyAllow: false, DenyReason: "blocked by " + string(point) + " hook"}, nil
	}
	return nil, nil
}

// recordPolicyDenial logs and records evidence for a policy-denied request.
func (r *Runner) recordPolicyDenial(ctx context.Context, span trace.Span, correlationID string, req *RunRequest, pol *policy.Policy, decision *policy.Decision, tier int, piiNames []string, attScan *evidence.AttachmentScan, compliance evidence.Compliance) {
	span.SetStatus(codes.Error, "policy denied")
	log.Warn().
		Str("correlation_id", correlationID).
		Str("deny_reason", decision.Action).
		Msg("policy_denied")

	_, _ = r.evidence.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  correlationID,
		TenantID:       req.TenantID,
		AgentID:        req.AgentName,
		InvocationType: req.InvocationType,
		PolicyDecision: evidence.PolicyDecision{
			Allowed:       false,
			Action:        decision.Action,
			Reasons:       decision.Reasons,
			PolicyVersion: pol.VersionTag,
		},
		Classification: evidence.Classification{InputTier: tier, PIIDetected: piiNames},
		AttachmentScan: attScan,
		InputPrompt:    req.Prompt,
		Compliance:     compliance,
	})
}

// executeLLMPipeline runs steps 5-9: route provider, call LLM, classify output, generate evidence.
func (r *Runner) executeLLMPipeline(ctx context.Context, span trace.Span, startTime time.Time, correlationID string, req *RunRequest, pol *policy.Policy, tier int, piiNames []string, prompt string, attScan *evidence.AttachmentScan, compliance evidence.Compliance, costCtx *llm.CostContext, memReads []evidence.MemoryRead, memTokens int) (*RunResponse, error) {
	// Step 5+6: Route LLM (with optional graceful degradation) and resolve tenant-scoped API key
	provider, model, degraded, originalModel, secretsAccessed, err := r.resolveProvider(ctx, req, tier, costCtx)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	span.SetAttributes(
		attribute.String("gen_ai.system", provider.Name()),
		attribute.String("gen_ai.request.model", model),
		attribute.Bool("cost.degraded", degraded),
	)

	// Hook: pre-LLM
	if resp, err := r.checkHook(ctx, HookPreLLM, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
		"model":         model,
		"cost_estimate": 0.01,
	}); resp != nil || err != nil {
		return resp, err
	}

	// Step 7: Call LLM
	llmReq := &llm.Request{
		Model: model,
		Messages: []llm.Message{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.7,
		MaxTokens:   2000,
	}

	llmResp, err := provider.Generate(ctx, llmReq)
	if err != nil {
		span.RecordError(err)
		duration := time.Since(startTime)
		_, _ = r.evidence.Generate(ctx, evidence.GenerateParams{
			CorrelationID:   correlationID,
			TenantID:        req.TenantID,
			AgentID:         req.AgentName,
			InvocationType:  req.InvocationType,
			PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: pol.VersionTag},
			Classification:  evidence.Classification{InputTier: tier, PIIDetected: piiNames},
			AttachmentScan:  attScan,
			ModelUsed:       model,
			OriginalModel:   originalModel,
			Degraded:        degraded,
			DurationMS:      duration.Milliseconds(),
			Error:           err.Error(),
			SecretsAccessed: secretsAccessed,
			InputPrompt:     req.Prompt,
			Compliance:      compliance,
		})
		return nil, fmt.Errorf("calling LLM: %w", err)
	}

	// Hook: post-LLM
	costEUR := provider.EstimateCost(model, llmResp.InputTokens, llmResp.OutputTokens)
	llm.RecordCostMetrics(ctx, costEUR, req.AgentName, model, degraded)
	_, _ = r.fireHook(ctx, HookPostLLM, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
		"model":         model,
		"cost_estimate": costEUR,
		"input_tokens":  llmResp.InputTokens,
		"output_tokens": llmResp.OutputTokens,
	})

	// Step 8: Classify output
	outputClass := r.classifier.Scan(ctx, llmResp.Content)
	outputEntityNames := entityNames(outputClass.Entities)

	// Step 9: Generate evidence
	duration := time.Since(startTime)
	ev, err := r.evidence.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  correlationID,
		TenantID:       req.TenantID,
		AgentID:        req.AgentName,
		InvocationType: req.InvocationType,
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: pol.VersionTag},
		Classification: evidence.Classification{
			InputTier:   tier,
			OutputTier:  outputClass.Tier,
			PIIDetected: append(piiNames, outputEntityNames...),
			PIIRedacted: false,
		},
		AttachmentScan:  attScan,
		ModelUsed:       model,
		OriginalModel:   originalModel,
		Degraded:        degraded,
		CostEUR:         costEUR,
		Tokens:          evidence.TokenUsage{Input: llmResp.InputTokens, Output: llmResp.OutputTokens},
		DurationMS:      duration.Milliseconds(),
		SecretsAccessed: secretsAccessed,
		MemoryReads:     memReads,
		MemoryTokens:    memTokens,
		InputPrompt:     req.Prompt,
		OutputResponse:  llmResp.Content,
		Compliance:      compliance,
	})
	evidenceID := ""
	if err != nil {
		log.Error().Err(err).Msg("failed_to_generate_evidence")
	} else {
		evidenceID = ev.ID
	}

	// Hook: post-evidence
	_, _ = r.fireHook(ctx, HookPostEvidence, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
		"evidence_id": evidenceID,
		"cost_eur":    costEUR,
	})

	log.Info().
		Str("correlation_id", correlationID).
		Str("evidence_id", evidenceID).
		Float64("cost_eur", costEUR).
		Int64("duration_ms", duration.Milliseconds()).
		Msg("agent_run_completed")

	resp := &RunResponse{
		Response:    llmResp.Content,
		EvidenceID:  evidenceID,
		CostEUR:     costEUR,
		DurationMS:  duration.Milliseconds(),
		PolicyAllow: true,
		ModelUsed:   model,
		ToolsCalled: []string{},
	}

	// Post-LLM: governed memory write
	r.writeMemoryObservation(ctx, req, pol, resp, ev)

	return resp, nil
}

// processAttachments scans, sandboxes, and appends attachment content to the prompt.
func (r *Runner) processAttachments(ctx context.Context, req *RunRequest, pol *policy.Policy) (string, *evidence.AttachmentScan, error) {
	if len(req.Attachments) == 0 {
		return req.Prompt, nil, nil
	}

	sandboxToken, err := attachment.GenerateSandboxToken()
	if err != nil {
		return "", nil, fmt.Errorf("generating sandbox token: %w", err)
	}

	scan := &evidence.AttachmentScan{FilesProcessed: len(req.Attachments)}
	processedPrompt := req.Prompt

	for _, att := range req.Attachments {
		var text string
		if r.extractor != nil {
			var extractErr error
			text, extractErr = r.extractor.ExtractBytes(ctx, att.Filename, att.Content)
			if extractErr != nil {
				return "", nil, fmt.Errorf("extracting %s: %w", att.Filename, extractErr)
			}
		} else {
			text = string(att.Content)
		}
		scanResult := r.attScanner.Scan(ctx, text)

		if !scanResult.Safe {
			scan.InjectionsDetected += len(scanResult.InjectionsFound)

			actionOnDetection := "warn"
			if pol.AttachmentHandling != nil && pol.AttachmentHandling.Scanning != nil {
				actionOnDetection = pol.AttachmentHandling.Scanning.ActionOnDetection
			}

			if actionOnDetection == "block_and_flag" {
				scan.ActionTaken = "blocked"
				scan.BlockedFiles = append(scan.BlockedFiles, att.Filename)
				continue
			}
		}

		sandboxed := attachment.Sandbox(ctx, att.Filename, text, scanResult, sandboxToken)
		processedPrompt += "\n\n" + sandboxed.SandboxedText
	}

	if scan.ActionTaken == "" {
		scan.ActionTaken = "sandboxed"
	}
	return processedPrompt, scan, nil
}

// resolveProvider routes to an LLM provider (with optional cost degradation) and resolves
// a tenant-scoped API key from the vault. Returns (provider, model, degraded, originalModel, secrets, err).
func (r *Runner) resolveProvider(ctx context.Context, req *RunRequest, tier int, costCtx *llm.CostContext) (provider llm.Provider, model string, degraded bool, originalModel string, secretsAccessed []string, err error) {
	if costCtx != nil {
		var routeErr error
		provider, model, degraded, originalModel, routeErr = r.router.GracefulRoute(ctx, tier, costCtx)
		if routeErr != nil {
			return nil, "", false, "", nil, fmt.Errorf("routing LLM: %w", routeErr)
		}
	} else {
		provider, model, err = r.router.Route(ctx, tier)
		if err != nil {
			return nil, "", false, "", nil, fmt.Errorf("routing LLM: %w", err)
		}
	}

	providerName := provider.Name()

	if llm.ProviderUsesAPIKey(providerName) && r.secrets != nil {
		secretName := providerName + "-api-key"
		secret, secretErr := r.secrets.Get(ctx, secretName, req.TenantID, req.AgentName)
		if secretErr == nil {
			secretsAccessed = append(secretsAccessed, secretName)
			if p := llm.NewProviderWithKey(providerName, string(secret.Value)); p != nil {
				provider = p
			}
		} else {
			log.Debug().
				Str("provider", providerName).
				Str("tenant_id", req.TenantID).
				Msg("no tenant key in vault, using operator fallback")
		}
	}

	return provider, model, degraded, originalModel, secretsAccessed, nil
}

// entityNames extracts type strings from PIIEntity slice for evidence records.
func entityNames(entities []classifier.PIIEntity) []string {
	if len(entities) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var names []string
	for _, e := range entities {
		if !seen[e.Type] {
			seen[e.Type] = true
			names = append(names, e.Type)
		}
	}
	return names
}

// complianceFromPolicy extracts compliance info from policy for evidence.
func complianceFromPolicy(pol *policy.Policy) evidence.Compliance {
	c := evidence.Compliance{}
	if pol.Compliance != nil {
		c.Frameworks = pol.Compliance.Frameworks
		c.DataLocation = pol.Compliance.DataResidency
	}
	return c
}

// maybeGateForPlanReview runs the plan review gate; returns (response, true, nil) if execution is gated.
func (r *Runner) maybeGateForPlanReview(ctx context.Context, pol *policy.Policy, req *RunRequest, correlationID string, dataTier int, processedPrompt string) (*RunResponse, bool, error) {
	if r.planReview == nil {
		return nil, false, nil
	}
	humanOversight := ""
	var planCfg *PlanReviewConfig
	if pol.Compliance != nil {
		humanOversight = pol.Compliance.HumanOversight
		if pol.Compliance.PlanReview != nil {
			planCfg = planReviewConfigFromPolicy(pol.Compliance.PlanReview)
		}
	}
	costEstimate := 0.01
	hasTools := r.toolRegistry != nil && len(r.toolRegistry.List()) > 0
	if !RequiresReview(humanOversight, dataTier, costEstimate, hasTools, planCfg) {
		return nil, false, nil
	}
	timeoutMin := 30
	if planCfg != nil && planCfg.TimeoutMinutes > 0 {
		timeoutMin = planCfg.TimeoutMinutes
	}
	plan := GenerateExecutionPlan(
		correlationID, req.TenantID, req.AgentName, "pending",
		dataTier, nil, costEstimate, "allow",
		"", processedPrompt, timeoutMin,
	)
	if err := r.planReview.Save(ctx, plan); err != nil {
		return nil, false, fmt.Errorf("saving plan for review: %w", err)
	}
	return &RunResponse{PolicyAllow: true, PlanPending: plan.ID}, true, nil
}

// fireHook is a nil-safe helper that fires a hook at the given point.
// Returns (continue=true) when hooks is nil or no hook aborts the pipeline.
func (r *Runner) fireHook(ctx context.Context, point HookPoint, tenantID, agentID, correlationID string, payload interface{}) (bool, error) {
	if r.hooks == nil {
		return true, nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return true, nil
	}
	result, err := r.hooks.Execute(ctx, point, &HookData{
		TenantID:      tenantID,
		AgentID:       agentID,
		CorrelationID: correlationID,
		Stage:         point,
		Payload:       raw,
	})
	if err != nil {
		return true, err
	}
	return result.Continue, nil
}

func boolToDecision(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

// memoryMode returns the effective memory mode from policy, defaulting to "active".
func memoryMode(pol *policy.Policy) string {
	if pol.Memory == nil {
		return "disabled"
	}
	if !pol.Memory.Enabled {
		return "disabled"
	}
	switch pol.Memory.Mode {
	case "shadow", "disabled":
		return pol.Memory.Mode
	default:
		return "active"
	}
}

// writeMemoryObservation compresses the run result into a memory observation
// and writes it through the governance pipeline.
// In shadow mode, all checks run and results are logged, but no entry is persisted.
func (r *Runner) writeMemoryObservation(ctx context.Context, req *RunRequest, pol *policy.Policy, resp *RunResponse, ev *evidence.Evidence) {
	if r.memory == nil || r.governance == nil || pol.Memory == nil || !pol.Memory.Enabled {
		return
	}
	if ev == nil {
		return
	}

	mode := memoryMode(pol)
	if mode == "disabled" {
		return
	}

	// Strip private tags from response before persisting to memory (GDPR Art. 25).
	// Both Title and Content must be derived from clean content so <private> is never persisted.
	privacyResult := memory.StripPrivateTags(resp.Response)

	observation := memory.Entry{
		TenantID:         req.TenantID,
		AgentID:          req.AgentName,
		Category:         inferCategory(resp),
		Title:            compressTitle(resp, privacyResult.CleanContent),
		Content:          compressObservation(resp, privacyResult.CleanContent),
		ObservationType:  inferObservationType(resp),
		EvidenceID:       ev.ID,
		SourceType:       sourceTypeFromInvocation(req.InvocationType),
		SourceEvidenceID: ev.ID,
	}

	if err := r.governance.ValidateWrite(ctx, &observation, pol); err != nil {
		log.Warn().Err(err).
			Str("agent_id", req.AgentName).
			Str("category", observation.Category).
			Bool("memory.shadow", mode == "shadow").
			Msg("memory_write_denied")
		return
	}

	if mode == "shadow" {
		log.Info().
			Str("category", observation.Category).
			Int("trust_score", observation.TrustScore).
			Str("review_status", observation.ReviewStatus).
			Str("evidence_id", ev.ID).
			Bool("memory.shadow", true).
			Msg("memory_shadow_observation")
		return
	}

	if err := r.memory.Write(ctx, &observation); err != nil {
		log.Error().Err(err).Msg("memory_write_failed")
		return
	}

	log.Info().
		Str("entry_id", observation.ID).
		Int("trust_score", observation.TrustScore).
		Str("review_status", observation.ReviewStatus).
		Msg("memory_observation_written")
}

// filterByPromptCategories keeps only entries whose category is in the allowed list.
func filterByPromptCategories(entries []memory.IndexEntry, categories []string) []memory.IndexEntry {
	allowed := make(map[string]bool, len(categories))
	for _, c := range categories {
		allowed[c] = true
	}
	var filtered []memory.IndexEntry
	for i := range entries {
		if allowed[entries[i].Category] {
			filtered = append(filtered, entries[i])
		}
	}
	return filtered
}

// capMemoryByTokens trims the memory index to fit within a token budget.
// It keeps entries from newest to oldest, dropping the oldest when over budget.
func capMemoryByTokens(entries []memory.IndexEntry, maxTokens int) []memory.IndexEntry {
	var result []memory.IndexEntry
	totalTokens := 0
	for i := range entries {
		entryTokens := entries[i].TokenCount
		if entryTokens == 0 {
			entryTokens = (len(entries[i].Title) + len(entries[i].Category) + 40) / 4 // estimate per index line
		}
		if totalTokens+entryTokens > maxTokens && len(result) > 0 {
			break
		}
		result = append(result, entries[i])
		totalTokens += entryTokens
	}
	return result
}

// formatMemoryIndexForPrompt creates a lightweight prompt section from memory entries.
// Entries with pending_review status are excluded — unvalidated entries must not
// influence LLM decisions (governance integrity).
func formatMemoryIndexForPrompt(entries []memory.IndexEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("[AGENT MEMORY INDEX]\n")
	included := 0
	for i := range entries {
		if entries[i].ReviewStatus == "pending_review" {
			continue
		}
		fmt.Fprintf(&b, "\u2713 %s | %s | %s | trust:%d | %s\n",
			entries[i].ID, entries[i].Category, entries[i].Title, entries[i].TrustScore,
			entries[i].Timestamp.Format("2006-01-02"))
		included++
	}
	if included == 0 {
		return ""
	}
	b.WriteString("[END MEMORY INDEX]\n")
	return b.String()
}

// compressObservation creates a ~500-token summary of the run for memory storage.
func compressObservation(resp *RunResponse, cleanContent string) string {
	summary := fmt.Sprintf("Model: %s | Cost: EUR%.4f | Duration: %dms",
		resp.ModelUsed, resp.CostEUR, resp.DurationMS)
	if resp.DenyReason != "" {
		summary += " | Denied: " + resp.DenyReason
	}
	const maxLen = 1600
	if len(cleanContent) > maxLen {
		cleanContent = cleanContent[:maxLen] + "..."
	}
	return summary + "\n" + cleanContent
}

// compressTitle derives a short title from the response using only privacy-stripped content.
// Using cleanContent ensures <private> sections are never persisted in the title (GDPR Art. 25).
func compressTitle(resp *RunResponse, cleanContent string) string {
	if resp.DenyReason != "" {
		return "Denied: " + resp.DenyReason
	}
	text := cleanContent
	if idx := strings.IndexAny(text, ".\n"); idx > 0 && idx < 80 {
		return text[:idx]
	}
	if len(text) > 80 {
		return text[:80]
	}
	return text
}

func inferCategory(resp *RunResponse) string {
	if resp.DenyReason != "" {
		return memory.CategoryPolicyHit
	}
	return memory.CategoryDomainKnowledge
}

func inferObservationType(resp *RunResponse) string {
	if resp.DenyReason != "" {
		return memory.ObsDecision
	}
	return memory.ObsLearning
}

func sourceTypeFromInvocation(invocationType string) string {
	switch {
	case invocationType == "manual":
		return memory.SourceManual
	case invocationType == "scheduled":
		return memory.SourceAgentRun
	case strings.HasPrefix(invocationType, "webhook:"):
		return memory.SourceWebhook
	default:
		return memory.SourceAgentRun
	}
}

// RunFromTrigger implements the trigger.AgentRunner interface for cron/webhook execution.
// It uses the runner's default policy path so cron/webhook runs load the same .talon.yaml
// as the process (e.g. agent.talon.yaml), instead of deriving agentName+".talon.yaml".
func (r *Runner) RunFromTrigger(ctx context.Context, agentName, prompt, invocationType string) error {
	req := &RunRequest{
		TenantID:       "default",
		AgentName:      agentName,
		Prompt:         prompt,
		InvocationType: invocationType,
	}
	if r.defaultPolicyPath != "" {
		req.PolicyPath = r.defaultPolicyPath
	}
	_, err := r.Run(ctx, req)
	return err
}

// planReviewConfigFromPolicy converts policy-level plan review config to agent type.
func planReviewConfigFromPolicy(cfg *policy.PlanReviewConfig) *PlanReviewConfig {
	if cfg == nil {
		return nil
	}
	return &PlanReviewConfig{
		RequireForTools:  cfg.RequireForTools,
		RequireForTier:   cfg.RequireForTier,
		CostThresholdEUR: cfg.CostThresholdEUR,
		TimeoutMinutes:   cfg.TimeoutMinutes,
		NotifyWebhook:    cfg.NotifyWebhook,
	}
}

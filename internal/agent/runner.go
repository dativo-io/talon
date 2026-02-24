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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

// ActiveRunTracker counts in-flight runs per tenant for rate-limit policy (concurrent_executions).
// Safe for concurrent use. When nil, rate-limit policy input concurrent_executions is not set.
type ActiveRunTracker struct {
	mu     sync.Mutex
	counts map[string]int
}

// Increment adds one in-flight run for the tenant.
func (t *ActiveRunTracker) Increment(tenantID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.counts == nil {
		t.counts = make(map[string]int)
	}
	t.counts[tenantID]++
}

// Decrement removes one in-flight run for the tenant.
func (t *ActiveRunTracker) Decrement(tenantID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.counts == nil {
		return
	}
	t.counts[tenantID]--
	if t.counts[tenantID] <= 0 {
		delete(t.counts, tenantID)
	}
}

// Count returns the current in-flight run count for the tenant (including the run that just called Increment).
func (t *ActiveRunTracker) Count(tenantID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counts[tenantID]
}

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
	activeRuns        *ActiveRunTracker // optional; when set, used for rate-limit policy concurrent_executions
	hooks             *HookRegistry
	memory            *memory.Store
	governance        *memory.Governance
	consolidator      *memory.Consolidator // optional; when set, memory writes go through AUDN consolidation
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
	ActiveRunTracker  *ActiveRunTracker // optional; when set, rate-limit policy receives concurrent_executions
	Hooks             *HookRegistry     // optional; nil = no hooks
	Memory            *memory.Store     // optional; nil = memory disabled
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
		activeRuns:        cfg.ActiveRunTracker,
		hooks:             cfg.Hooks,
		memory:            cfg.Memory,
	}
	if cfg.Memory != nil && cfg.Classifier != nil {
		r.governance = memory.NewGovernance(cfg.Memory, cfg.Classifier)
	}
	if cfg.Memory != nil {
		r.consolidator = memory.NewConsolidator(cfg.Memory)
	}
	return r
}

// RunRequest is the input for a single agent invocation.
type RunRequest struct {
	TenantID        string
	AgentName       string
	Prompt          string
	Attachments     []Attachment
	InvocationType  string // "manual", "scheduled", "webhook:name"
	DryRun          bool
	PolicyPath      string           // explicit path to .talon.yaml
	ToolInvocations []ToolInvocation // optional; when set, each is policy-checked and executed, and names recorded in evidence
	SkipMemory      bool             // if true, do not write memory observation for this run (e.g. --no-memory)
}

// ToolInvocation represents a single tool call (e.g. from MCP or a future agent loop).
type ToolInvocation struct {
	Name   string          `json:"name"`
	Params json.RawMessage `json:"params"`
}

// Attachment is a file attached to a run request.
type Attachment struct {
	Filename string
	Content  []byte
}

// RunResponse is the output of an agent invocation.
type RunResponse struct {
	Response     string
	EvidenceID   string
	Cost         float64
	DurationMS   int64
	PolicyAllow  bool
	DenyReason   string
	PlanPending  string   // set when execution is gated for human review (EU AI Act Art. 14)
	ModelUsed    string   // LLM model used for generation
	ToolsCalled  []string // MCP tools invoked
	InputTokens  int      // prompt tokens (for OpenAI-compatible API responses)
	OutputTokens int      // completion tokens (for OpenAI-compatible API responses)
	// Dry-run / CLI feedback: PII and injection scan results (set even when DryRun is true).
	PIIDetected                  []string // entity names detected in input
	InputTier                    int      // classification tier of input (0–2)
	AttachmentInjectionsDetected int      // number of injection patterns found in attachments
	AttachmentBlocked            bool     // true if any attachment was blocked due to injection
}

// validateAgentNameForPolicyPath ensures AgentName is safe to use when deriving PolicyPath
// (PolicyPath empty → policyPath = AgentName + ".talon.yaml"). Rejects empty names, names
// that start with or contain path separators, so the derived path cannot be absolute or
// escape policyDir when passed to safePolicyPathUnder.
func validateAgentNameForPolicyPath(agentName string) error {
	if agentName == "" {
		return fmt.Errorf("agent name must not be empty when policy path is not set")
	}
	sep := string(filepath.Separator)
	if strings.HasPrefix(agentName, sep) {
		return fmt.Errorf("agent name must not start with path separator (got %q)", agentName)
	}
	if strings.Contains(agentName, sep) {
		return fmt.Errorf("agent name must not contain path separators (got %q)", agentName)
	}
	// Reject ".." so derived path cannot traverse out of policyDir
	if agentName == ".." || strings.HasPrefix(agentName, ".."+sep) || strings.Contains(agentName, sep+"..") {
		return fmt.Errorf("agent name must not be or contain .. (got %q)", agentName)
	}
	return nil
}

// safePolicyPathUnder resolves path relative to policyDir and returns an absolute path
// that is guaranteed to be under policyDir. Prevents path traversal when path or its
// components (e.g. AgentName) are user-controlled.
func safePolicyPathUnder(policyDir, path string) (string, error) {
	dirAbs, err := filepath.Abs(filepath.Clean(policyDir))
	if err != nil {
		return "", fmt.Errorf("policy directory: %w", err)
	}
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(dirAbs, path)
	}
	full = filepath.Clean(full)
	pathAbs, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("policy path: %w", err)
	}
	rel, err := filepath.Rel(dirAbs, pathAbs)
	if err != nil {
		return "", fmt.Errorf("policy path outside policy directory")
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("policy path outside policy directory")
	}
	return pathAbs, nil
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

	if r.activeRuns != nil {
		r.activeRuns.Increment(req.TenantID)
		defer r.activeRuns.Decrement(req.TenantID)
	}

	log.Info().
		Str("correlation_id", correlationID).
		Str("tenant_id", req.TenantID).
		Str("agent_id", req.AgentName).
		Func(talonotel.LogTraceFields(ctx)).
		Msg("agent_run_started")

	// Step 1: Load policy
	// Operator-provided absolute paths (--policy, cfg.DefaultPolicy, serve default) are trusted so that
	// paths outside CWD work (e.g. Docker volumes at /etc/talon/policies). Relative paths (including
	// when derived from AgentName) are resolved under policyDir to prevent path traversal.
	// When PolicyPath is empty we derive from AgentName; that derived path must never be treated as
	// a trusted absolute path. Enforce contract: AgentName must be a single path segment (no path
	// separators, not empty) so the derived path stays under policyDir via safePolicyPathUnder.
	policyPath := req.PolicyPath
	pathDerivedFromAgent := false
	if policyPath == "" {
		if err := validateAgentNameForPolicyPath(req.AgentName); err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("policy path: %w", err)
		}
		policyPath = req.AgentName + ".talon.yaml"
		pathDerivedFromAgent = true
	}
	var safePath string
	var loadBaseDir string
	if filepath.IsAbs(policyPath) {
		if pathDerivedFromAgent {
			err := fmt.Errorf("agent name must not be an absolute path or start with path separator (got %q)", req.AgentName)
			span.RecordError(err)
			return nil, fmt.Errorf("policy path: %w", err)
		}
		var err error
		safePath, err = filepath.Abs(filepath.Clean(policyPath))
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("policy path: %w", err)
		}
		loadBaseDir = filepath.Dir(safePath)
	} else {
		var err error
		_, err = safePolicyPathUnder(r.policyDir, policyPath)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("policy path: %w", err)
		}
		loadBaseDir = r.policyDir
	}

	pol, err := policy.LoadPolicy(ctx, policyPath, false, loadBaseDir)
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

	// Effective input classification: prompt + attachments (tier and PII)
	effectiveTier := inputClass.Tier
	effectivePIINames := inputEntityNames
	if attachmentScan != nil {
		if attachmentScan.AttachmentTier > effectiveTier {
			effectiveTier = attachmentScan.AttachmentTier
		}
		effectivePIINames = mergePIIEntityNames(inputEntityNames, attachmentScan.PIIDetectedInAttachments)
	}
	effectiveHasPII := inputClass.HasPII || (attachmentScan != nil && len(attachmentScan.PIIDetectedInAttachments) > 0)

	// Block-on-PII gate: deny run when policy requires and input contains PII
	if pol.Policies.DataClassification != nil && pol.Policies.DataClassification.BlockOnPII && effectiveHasPII {
		span.SetStatus(codes.Error, "block_on_pii")
		log.Warn().
			Str("correlation_id", correlationID).
			Str("tenant_id", req.TenantID).
			Str("agent_id", req.AgentName).
			Strs("pii_detected", effectivePIINames).
			Msg("block_on_pii: input contains PII, run denied")
		_, _ = r.evidence.Generate(ctx, evidence.GenerateParams{
			CorrelationID:   correlationID,
			TenantID:        req.TenantID,
			AgentID:         req.AgentName,
			InvocationType:  req.InvocationType,
			RequestSourceID: req.InvocationType,
			PolicyDecision: evidence.PolicyDecision{
				Allowed:       false,
				Action:        "block_on_pii",
				Reasons:       []string{"Input contains PII (policy: block_on_pii)"},
				PolicyVersion: pol.VersionTag,
			},
			Classification: evidence.Classification{InputTier: effectiveTier, PIIDetected: effectivePIINames},
			AttachmentScan: attachmentScan,
			InputPrompt:    req.Prompt,
			Compliance:     complianceFromPolicy(pol),
		})
		return &RunResponse{PolicyAllow: false, DenyReason: "Input contains PII (policy: block_on_pii)"}, nil
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

	emitBudgetAlertIfNeeded(ctx, req.TenantID, dailyCost, monthlyCost, pol.Policies.CostLimits)

	// Per-run engine: do not assign to shared Governance (SetPolicyEvaluator); pass this
	// engine through to executeLLMPipeline so writeMemoryObservation uses it in ValidateWrite.
	// That keeps concurrent Run() (e.g. webhook/cron in talon serve) from racing on g.opa.
	engine, err := policy.NewEngine(ctx, pol)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("creating policy engine: %w", err)
	}

	estimatedCost := 0.01
	if r.router != nil {
		if c, err := r.router.PreRunEstimate(effectiveTier); err == nil {
			estimatedCost = c
		}
	}
	requestsLastMinute := 0
	if r.evidenceStore != nil {
		now := time.Now().UTC()
		from := now.Add(-1 * time.Minute)
		requestsLastMinute, _ = r.evidenceStore.CountInRange(ctx, req.TenantID, "", from, now)
	}
	concurrentExecutions := 0
	if r.activeRuns != nil {
		concurrentExecutions = r.activeRuns.Count(req.TenantID)
	}
	policyInput := map[string]interface{}{
		"tenant_id":             req.TenantID,
		"agent_id":              req.AgentName,
		"tier":                  effectiveTier,
		"estimated_cost":        estimatedCost,
		"daily_cost_total":      dailyCost,
		"monthly_cost_total":    monthlyCost,
		"requests_last_minute":  requestsLastMinute,
		"concurrent_executions": concurrentExecutions,
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
		"tier":     effectiveTier,
	}); resp != nil || err != nil {
		return resp, err
	}

	var observationOverride bool
	var originalDecision *policy.Decision
	if !decision.Allowed {
		if pol.Audit != nil && pol.Audit.ObservationOnly {
			observationOverride = true
			originalDecision = decision
			span.AddEvent("observation_only_override", trace.WithAttributes(
				attribute.String("policy.action", decision.Action),
			))
			log.Info().
				Str("correlation_id", correlationID).
				Str("tenant_id", req.TenantID).
				Str("agent_id", req.AgentName).
				Str("would_deny_reason", decision.Action).
				Msg("observation_only: policy would deny, allowing for audit")
		} else {
			r.recordPolicyDenial(ctx, span, correlationID, req, pol, decision, effectiveTier, effectivePIINames, attachmentScan, complianceInfo)
			denyReason := decision.Action
			if len(decision.Reasons) > 0 {
				denyReason = strings.Join(decision.Reasons, "; ")
			}
			return &RunResponse{PolicyAllow: false, DenyReason: denyReason}, nil
		}
	}

	if req.DryRun {
		// Record evidence for dry-run so audit trail includes policy-check attempts (no LLM call).
		duration := time.Since(startTime)
		_, _ = r.evidence.Generate(ctx, evidence.GenerateParams{
			CorrelationID:   correlationID,
			TenantID:        req.TenantID,
			AgentID:         req.AgentName,
			InvocationType:  req.InvocationType,
			RequestSourceID: req.InvocationType,
			PolicyDecision: evidence.PolicyDecision{
				Allowed:       true,
				Action:        decision.Action,
				Reasons:       decision.Reasons,
				PolicyVersion: pol.VersionTag,
			},
			Classification: evidence.Classification{InputTier: effectiveTier, PIIDetected: effectivePIINames},
			AttachmentScan: attachmentScan,
			DurationMS:     duration.Milliseconds(),
			InputPrompt:    req.Prompt,
			Compliance:     complianceInfo,
		})
		resp := &RunResponse{PolicyAllow: true, PIIDetected: effectivePIINames, InputTier: effectiveTier}
		if attachmentScan != nil {
			resp.AttachmentInjectionsDetected = attachmentScan.InjectionsDetected
			resp.AttachmentBlocked = len(attachmentScan.BlockedFiles) > 0
		}
		return resp, nil
	}

	// Step 4.5: Plan Review Gate (EU AI Act Art. 14)
	if resp, err := r.checkHook(ctx, HookPrePlanReview, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
		"tier": effectiveTier,
	}); resp != nil || err != nil {
		return resp, err
	}

	resp, ok, err := r.maybeGateForPlanReview(ctx, pol, req, correlationID, effectiveTier, processedPrompt, estimatedCost)
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
	// Only inject memory into prompts when mode is "active". In shadow/disabled,
	// memory is not included (MEMORY_GOVERNANCE.md: shadow = "Memory not included").
	// effectiveTier already set from prompt + attachments; may be upgraded by memory/context below.
	finalPrompt := processedPrompt
	var memoryReads []evidence.MemoryRead

	var memoryTokens int

	if pol.Memory != nil && pol.Memory.Enabled && memoryMode(pol) == "active" && r.memory != nil {
		var memIndex []memory.IndexEntry
		var memErr error
		if req.Prompt != "" && pol.Memory.MaxPromptTokens > 0 {
			memIndex, memErr = r.memory.RetrieveScored(ctx, req.TenantID, req.AgentName, req.Prompt, pol.Memory.MaxPromptTokens)
		} else {
			memIndex, memErr = r.memory.ListIndex(ctx, req.TenantID, req.AgentName, 50)
		}
		if memErr != nil {
			log.Warn().Err(memErr).Str("tenant_id", req.TenantID).Str("agent_id", req.AgentName).Msg("failed to load memory index")
		} else if len(memIndex) > 0 {
			// Filter by prompt_categories so operators control which categories enter context
			if len(pol.Memory.PromptCategories) > 0 {
				memIndex = filterByPromptCategories(memIndex, pol.Memory.PromptCategories)
			}

			// Exclude pending_review before evidence: only entries actually injected are recorded (compliance-accurate audit).
			memIndex = filterOutPendingReview(memIndex)

			// Token cap: when using ListIndex (no prompt), apply cap here; RetrieveScored already caps by maxTokens
			if req.Prompt == "" && pol.Memory.MaxPromptTokens > 0 {
				memIndex = capMemoryByTokens(memIndex, pol.Memory.MaxPromptTokens)
			}

			// Order by trust_score descending so highest-trust context is first (prompt and evidence order).
			sort.Slice(memIndex, func(i, j int) bool { return memIndex[i].TrustScore > memIndex[j].TrustScore })

			memPrompt := formatMemoryIndexForPrompt(memIndex)
			if memPrompt != "" {
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
	}

	if pol.Context != nil && len(pol.Context.SharedMounts) > 0 {
		sharedCtx, ctxErr := talonctx.LoadSharedContext(pol)
		if ctxErr != nil {
			log.Warn().Err(ctxErr).Str("tenant_id", req.TenantID).Str("agent_id", req.AgentName).Msg("failed to load shared context")
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

	resp, err = r.executeLLMPipeline(ctx, span, startTime, correlationID, req, pol, engine,
		effectiveTier, effectivePIINames, finalPrompt, attachmentScan, complianceInfo, costCtx, memoryReads, memoryTokens,
		observationOverride, originalDecision, estimatedCost)
	if err != nil {
		return nil, err
	}
	// Lightweight retention: enforce max_entries after each run (full purge by days remains in talon serve).
	// Skip when SkipMemory is set (e.g. --no-memory) so we do not evict entries during a run that requested no memory writes.
	if r.memory != nil && pol.Memory != nil && pol.Memory.Enabled && pol.Memory.MaxEntries > 0 && !req.SkipMemory {
		evicted, evErr := r.memory.EnforceMaxEntries(ctx, req.TenantID, req.AgentName, pol.Memory.MaxEntries)
		if evErr != nil {
			log.Warn().Err(evErr).Msg("cli_retention_failed")
		} else if evicted > 0 {
			log.Info().Int64("evicted", evicted).Msg("memory_max_entries_enforced")
		}
	}
	return resp, nil
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
		Str("tenant_id", req.TenantID).
		Str("agent_id", req.AgentName).
		Str("deny_reason", decision.Action).
		Msg("policy_denied")

	_, _ = r.evidence.Generate(ctx, evidence.GenerateParams{
		CorrelationID:   correlationID,
		TenantID:        req.TenantID,
		AgentID:         req.AgentName,
		InvocationType:  req.InvocationType,
		RequestSourceID: req.InvocationType,
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
// policyEval is the per-run OPA engine used for memory governance to avoid data races when concurrent Run() share one Governance.
// When observationOverride is true, originalDecision holds the policy deny that was overridden for audit-only (shadow) mode.
// costEstimate is the pre-run cost estimate from Run() (same value used for policy input and plan-review gate).
//
//nolint:gocyclo // orchestration flow is inherently branched; splitting would obscure the pipeline
func (r *Runner) executeLLMPipeline(ctx context.Context, span trace.Span, startTime time.Time, correlationID string, req *RunRequest, pol *policy.Policy, policyEval memory.PolicyEvaluator, tier int, piiNames []string, prompt string, attScan *evidence.AttachmentScan, compliance evidence.Compliance, costCtx *llm.CostContext, memReads []evidence.MemoryRead, memTokens int, observationOverride bool, originalDecision *policy.Decision, costEstimate float64) (*RunResponse, error) {
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

	// Hook: pre-LLM (costEstimate was computed once in Run() and passed through)
	if resp, err := r.checkHook(ctx, HookPreLLM, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
		"model":         model,
		"cost_estimate": costEstimate,
	}); resp != nil || err != nil {
		return resp, err
	}

	modelRationale := "primary"
	if degraded && originalModel != "" {
		modelRationale = "degraded from primary " + originalModel + " to fallback " + model
	}
	policyDec := evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: pol.VersionTag}
	if observationOverride && originalDecision != nil {
		policyDec = evidence.PolicyDecision{Allowed: false, Action: originalDecision.Action, Reasons: originalDecision.Reasons, PolicyVersion: pol.VersionTag}
	}

	// Agentic loop: max_iterations from policy (0 or 1 = single call); tools from registry filtered by allowed_tools
	maxIterations := 1
	if pol.Policies.ResourceLimits != nil && pol.Policies.ResourceLimits.MaxIterations > 0 {
		maxIterations = pol.Policies.ResourceLimits.MaxIterations
		if maxIterations > 50 {
			maxIterations = 50
		}
	}
	llmTools := r.buildLLMTools(pol)
	// Only OpenAI supports tool calls in the API; other providers would ignore or error on tool messages
	useAgenticLoop := len(llmTools) > 0 && maxIterations >= 2 && provider.Name() == "openai"

	var messages []llm.Message
	var llmResp *llm.Response
	var cost float64
	var totalInputTokens, totalOutputTokens int
	var toolsCalled []string

	if useAgenticLoop {
		messages = []llm.Message{{Role: "user", Content: prompt}}
		perRequest := 0.0
		if pol.Policies.CostLimits != nil && pol.Policies.CostLimits.PerRequest > 0 {
			perRequest = pol.Policies.CostLimits.PerRequest
		}
		stepIndex := 0
		var toolHistory []map[string]interface{} // passed to OPA for future tool-chain risk scoring
		for iteration := 1; ; iteration++ {
			llmReq := &llm.Request{
				Model:       model,
				Messages:    messages,
				Temperature: 0.7,
				MaxTokens:   2000,
				Tools:       llmTools,
			}
			iterStart := time.Now()
			resp, err := provider.Generate(ctx, llmReq)
			if err != nil {
				span.RecordError(err)
				duration := time.Since(startTime)
				_, _ = r.evidence.Generate(ctx, evidence.GenerateParams{
					CorrelationID: correlationID, TenantID: req.TenantID, AgentID: req.AgentName,
					InvocationType: req.InvocationType, RequestSourceID: req.InvocationType,
					PolicyDecision: policyDec, Classification: evidence.Classification{InputTier: tier, PIIDetected: piiNames},
					AttachmentScan: attScan, ModelUsed: model, OriginalModel: originalModel, Degraded: degraded,
					ModelRoutingRationale: modelRationale, DurationMS: duration.Milliseconds(), Error: err.Error(),
					SecretsAccessed: secretsAccessed, InputPrompt: req.Prompt, Compliance: compliance,
					ObservationModeOverride: observationOverride,
					ToolsCalled:             toolsCalled, Cost: cost,
					Tokens: evidence.TokenUsage{Input: totalInputTokens, Output: totalOutputTokens},
				})
				return nil, fmt.Errorf("calling LLM: %w", err)
			}
			iterDuration := time.Since(iterStart).Milliseconds()
			iterCost := provider.EstimateCost(model, resp.InputTokens, resp.OutputTokens)
			cost += iterCost
			totalInputTokens += resp.InputTokens
			totalOutputTokens += resp.OutputTokens
			llm.RecordCostMetrics(ctx, iterCost, req.AgentName, model, degraded)
			_, _ = r.fireHook(ctx, HookPostLLM, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
				"model": model, "cost_estimate": iterCost, "input_tokens": resp.InputTokens, "output_tokens": resp.OutputTokens,
			})

			// Step-level evidence: one record per LLM call in the loop
			_, _ = r.evidence.GenerateStep(ctx, evidence.StepParams{
				CorrelationID: correlationID, TenantID: req.TenantID, AgentID: req.AgentName,
				StepIndex: stepIndex, Type: "llm_call",
				OutputSummary: evidence.TruncateForSummary(resp.Content, 500),
				DurationMS:    iterDuration, Cost: iterCost,
			})
			stepIndex++

			llmResp = resp
			if perRequest > 0 && cost > perRequest {
				log.Warn().Float64("total_cost", cost).Float64("per_request", perRequest).Msg("agent_loop_stopped_per_request_budget")
				break
			}
			rl := pol.Policies.ResourceLimits
			if rl != nil && rl.MaxToolCallsPerRun > 0 && len(toolsCalled) >= rl.MaxToolCallsPerRun {
				log.Warn().Int("tool_calls", len(toolsCalled)).Int("max", rl.MaxToolCallsPerRun).Msg("agent_loop_stopped_max_tool_calls")
				break
			}
			if rl != nil && rl.MaxCostPerRun > 0 && cost >= rl.MaxCostPerRun {
				log.Warn().Float64("cost", cost).Float64("max", rl.MaxCostPerRun).Msg("agent_loop_stopped_max_cost_per_run")
				break
			}
			if policyEngine, ok := policyEval.(*policy.Engine); ok {
				if dec, err := policyEngine.EvaluateLoopContainment(ctx, iteration, len(toolsCalled), cost); err == nil && dec != nil && !dec.Allowed {
					log.Warn().Strs("reasons", dec.Reasons).Msg("agent_loop_stopped_loop_containment")
					break
				}
			}
			if len(resp.ToolCalls) == 0 || iteration >= maxIterations {
				break
			}
			// Append assistant message with tool calls, then execute each and append tool results.
			// Enforce max_tool_calls_per_run inside this loop so a single LLM response with many
			// tool calls cannot exceed the limit before the next iteration check.
			assistantMsg := llm.Message{Role: "assistant", Content: resp.Content, ToolCalls: resp.ToolCalls}
			messages = append(messages, assistantMsg)
			for _, tc := range resp.ToolCalls {
				atLimit := rl != nil && rl.MaxToolCallsPerRun > 0 && len(toolsCalled) >= rl.MaxToolCallsPerRun
				var resultContent string
				var executed bool
				var toolName string
				if atLimit {
					resultContent = `{"error":"max_tool_calls_per_run limit reached"}`
					toolName = tc.Name
				} else {
					_, _ = r.fireHook(ctx, HookPreTool, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
						"tool": tc.Name, "tool_call_id": tc.ID,
					})
					toolStart := time.Now()
					resultContent, executed, toolName = r.executeOneToolCall(ctx, policyEval, pol, tc, toolHistory)
					toolDuration := time.Since(toolStart).Milliseconds()
					if executed {
						toolsCalled = append(toolsCalled, toolName)
					}
					_, _ = r.evidence.GenerateStep(ctx, evidence.StepParams{
						CorrelationID: correlationID, TenantID: req.TenantID, AgentID: req.AgentName,
						StepIndex: stepIndex, Type: "tool_call", ToolName: toolName,
						OutputSummary: evidence.TruncateForSummary(resultContent, 500),
						DurationMS:    toolDuration, Cost: 0,
					})
					stepIndex++
					_, _ = r.fireHook(ctx, HookPostTool, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
						"tool": tc.Name, "executed": executed,
					})
				}
				// Append to tool_history for next tool's policy evaluation (tool-chain risk scoring)
				toolHistory = append(toolHistory, map[string]interface{}{
					"name":           toolName,
					"params":         tc.Arguments,
					"result_summary": evidence.TruncateForSummary(resultContent, 200),
				})
				if atLimit {
					_, _ = r.evidence.GenerateStep(ctx, evidence.StepParams{
						CorrelationID: correlationID, TenantID: req.TenantID, AgentID: req.AgentName,
						StepIndex: stepIndex, Type: "tool_call", ToolName: toolName,
						OutputSummary: "max_tool_calls_per_run limit reached",
						DurationMS:    0, Cost: 0,
					})
					stepIndex++
				}
				messages = append(messages, llm.Message{Role: "tool", Content: resultContent, ToolCallID: tc.ID})
			}
		}
	} else {
		// Single LLM call (no agentic loop)
		llmReq := &llm.Request{
			Model: model,
			Messages: []llm.Message{
				{Role: "user", Content: prompt},
			},
			Temperature: 0.7,
			MaxTokens:   2000,
		}
		resp, err := provider.Generate(ctx, llmReq)
		if err != nil {
			span.RecordError(err)
			duration := time.Since(startTime)
			_, _ = r.evidence.Generate(ctx, evidence.GenerateParams{
				CorrelationID: correlationID, TenantID: req.TenantID, AgentID: req.AgentName,
				InvocationType: req.InvocationType, RequestSourceID: req.InvocationType,
				PolicyDecision: policyDec, Classification: evidence.Classification{InputTier: tier, PIIDetected: piiNames},
				AttachmentScan: attScan, ModelUsed: model, OriginalModel: originalModel, Degraded: degraded,
				ModelRoutingRationale: modelRationale, DurationMS: duration.Milliseconds(), Error: err.Error(),
				SecretsAccessed: secretsAccessed, InputPrompt: req.Prompt, Compliance: compliance,
				ObservationModeOverride: observationOverride,
			})
			return nil, fmt.Errorf("calling LLM: %w", err)
		}
		llmResp = resp
		cost = provider.EstimateCost(model, resp.InputTokens, resp.OutputTokens)
		totalInputTokens = resp.InputTokens
		totalOutputTokens = resp.OutputTokens
		llm.RecordCostMetrics(ctx, cost, req.AgentName, model, degraded)
		_, _ = r.fireHook(ctx, HookPostLLM, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
			"model": model, "cost_estimate": cost, "input_tokens": resp.InputTokens, "output_tokens": resp.OutputTokens,
		})
		// Step 7.5: Pre-specified tool invocations (legacy path)
		toolsCalled = r.executeToolInvocations(ctx, span, req, policyEval, pol)
	}

	// Step 8: Classify output
	outputClass := r.classifier.Scan(ctx, llmResp.Content)
	outputEntityNames := entityNames(outputClass.Entities)

	// Step 9: Generate evidence
	duration := time.Since(startTime)
	ev, err := r.evidence.Generate(ctx, evidence.GenerateParams{
		CorrelationID:   correlationID,
		TenantID:        req.TenantID,
		AgentID:         req.AgentName,
		InvocationType:  req.InvocationType,
		RequestSourceID: req.InvocationType,
		PolicyDecision:  policyDec,
		Classification: evidence.Classification{
			InputTier:   tier,
			OutputTier:  outputClass.Tier,
			PIIDetected: append(piiNames, outputEntityNames...),
			PIIRedacted: false,
		},
		AttachmentScan:          attScan,
		ModelUsed:               model,
		OriginalModel:           originalModel,
		Degraded:                degraded,
		ModelRoutingRationale:   modelRationale,
		ToolsCalled:             toolsCalled,
		Cost:                    cost,
		Tokens:                  evidence.TokenUsage{Input: totalInputTokens, Output: totalOutputTokens},
		DurationMS:              duration.Milliseconds(),
		SecretsAccessed:         secretsAccessed,
		MemoryReads:             memReads,
		MemoryTokens:            memTokens,
		InputPrompt:             req.Prompt,
		OutputResponse:          llmResp.Content,
		AttachmentHashes:        attachmentHashesFromRequest(req),
		Compliance:              compliance,
		ObservationModeOverride: observationOverride,
	})
	evidenceID := ""
	if err != nil {
		log.Error().Err(err).Func(talonotel.LogTraceFields(ctx)).Msg("failed_to_generate_evidence")
	} else {
		evidenceID = ev.ID
	}

	// Hook: post-evidence
	_, _ = r.fireHook(ctx, HookPostEvidence, req.TenantID, req.AgentName, correlationID, map[string]interface{}{
		"evidence_id": evidenceID,
		"cost":        cost,
	})

	log.Info().
		Str("correlation_id", correlationID).
		Str("evidence_id", evidenceID).
		Float64("cost", cost).
		Int64("duration_ms", duration.Milliseconds()).
		Func(talonotel.LogTraceFields(ctx)).
		Msg("agent_run_completed")

	resp := &RunResponse{
		Response:     llmResp.Content,
		EvidenceID:   evidenceID,
		Cost:         cost,
		DurationMS:   duration.Milliseconds(),
		PolicyAllow:  true,
		ModelUsed:    model,
		ToolsCalled:  toolsCalled,
		InputTokens:  totalInputTokens,
		OutputTokens: totalOutputTokens,
	}

	// Post-LLM: governed memory write
	r.writeMemoryObservation(ctx, req, pol, policyEval, resp, ev)

	return resp, nil
}

// executeToolInvocations runs each requested tool through policy and the registry, and returns the list of tool names actually executed (for evidence).
func (r *Runner) executeToolInvocations(ctx context.Context, span trace.Span, req *RunRequest, policyEval memory.PolicyEvaluator, pol *policy.Policy) []string {
	if len(req.ToolInvocations) == 0 || r.toolRegistry == nil {
		return nil
	}
	policyEngine, _ := policyEval.(*policy.Engine)
	var called []string
	for _, inv := range req.ToolInvocations {
		if policyEngine != nil {
			var paramsMap map[string]interface{}
			_ = json.Unmarshal(inv.Params, &paramsMap)
			if paramsMap == nil {
				paramsMap = make(map[string]interface{})
			}
			dec, err := policyEngine.EvaluateToolAccess(ctx, inv.Name, paramsMap, nil)
			if err != nil {
				log.Warn().Err(err).Str("tool", inv.Name).Msg("tool access policy evaluation failed")
				continue
			}
			if dec != nil && !dec.Allowed {
				log.Warn().Str("tool", inv.Name).Strs("reasons", dec.Reasons).Msg("tool access denied by policy")
				continue
			}
		}
		tool, ok := r.toolRegistry.Get(inv.Name)
		if !ok {
			log.Warn().Str("tool", inv.Name).Msg("tool not in registry")
			continue
		}
		_, err := tool.Execute(ctx, inv.Params)
		if err != nil {
			log.Warn().Err(err).Str("tool", inv.Name).Msg("tool execution failed")
			continue
		}
		called = append(called, inv.Name)
	}
	if len(called) > 0 {
		span.SetAttributes(attribute.StringSlice("tool.called", called))
	}
	return called
}

// buildLLMTools returns LLM tool definitions from the registry, filtered by policy allowed_tools.
// Empty allowed_tools means no tools are passed to the LLM (single-call behavior).
func (r *Runner) buildLLMTools(pol *policy.Policy) []llm.Tool {
	if r.toolRegistry == nil || pol.Capabilities == nil {
		return nil
	}
	allowed := pol.Capabilities.AllowedTools
	list := r.toolRegistry.List()
	if len(allowed) == 0 || len(list) == 0 {
		return nil
	}
	allowedSet := make(map[string]bool)
	for _, n := range allowed {
		allowedSet[n] = true
	}
	var out []llm.Tool
	for _, t := range list {
		if !allowedSet[t.Name()] {
			continue
		}
		schema := t.InputSchema()
		var params map[string]interface{}
		if len(schema) > 0 {
			_ = json.Unmarshal(schema, &params)
		}
		if params == nil {
			params = make(map[string]interface{})
		}
		out = append(out, llm.Tool{
			Name:        t.Name(),
			Description: t.Description(),
			Parameters:  params,
		})
	}
	return out
}

// executeOneToolCall runs policy check, registry lookup, and execution for a single LLM tool call.
// toolHistory is the sequence of tool calls in this run so far (for OPA tool-chain risk scoring).
// Returns (result content for the tool message, whether the tool was executed, tool name).
func (r *Runner) executeOneToolCall(ctx context.Context, policyEval memory.PolicyEvaluator, pol *policy.Policy, tc llm.ToolCall, toolHistory []map[string]interface{}) (resultContent string, executed bool, toolName string) {
	toolName = tc.Name
	if r.toolRegistry == nil {
		return `{"error":"tool registry not available"}`, false, toolName
	}
	policyEngine, _ := policyEval.(*policy.Engine)
	if policyEngine != nil {
		dec, err := policyEngine.EvaluateToolAccess(ctx, tc.Name, tc.Arguments, toolHistory)
		if err != nil {
			log.Warn().Err(err).Str("tool", tc.Name).Msg("tool access policy evaluation failed")
			b, _ := json.Marshal(map[string]string{"error": "policy evaluation failed: " + err.Error()})
			return string(b), false, toolName
		}
		if dec != nil && !dec.Allowed {
			log.Warn().Str("tool", tc.Name).Strs("reasons", dec.Reasons).Msg("tool access denied by policy")
			reasonsJSON, _ := json.Marshal(dec.Reasons)
			return fmt.Sprintf(`{"error":"denied by policy","reasons":%s}`, string(reasonsJSON)), false, toolName
		}
	}
	tool, ok := r.toolRegistry.Get(tc.Name)
	if !ok {
		return `{"error":"tool not in registry"}`, false, toolName
	}
	params, _ := json.Marshal(tc.Arguments)
	if len(params) == 0 {
		params = []byte("{}")
	}
	out, err := tool.Execute(ctx, params)
	if err != nil {
		log.Warn().Err(err).Str("tool", tc.Name).Msg("tool execution failed")
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(b), false, toolName
	}
	if len(out) == 0 {
		return "{}", true, toolName
	}
	return string(out), true, toolName
}

const (
	budgetAlertThresholdPct = 0.8
	budgetAlertCooldown     = 1 * time.Hour // minimum interval between webhook POSTs per (tenant, alert_type)
)

// budgetAlertDedupe ensures we only POST to the budget alert webhook once per (tenant, alert_type) per cooldown.
// Log warnings are still emitted on every Run() over threshold; only the HTTP call is deduplicated.
var budgetAlertDedupe = &struct {
	mu        sync.Mutex
	lastFired map[string]time.Time // key: tenantID+":"+alertType
}{lastFired: make(map[string]time.Time)}

// budgetAlertClaimFire atomically checks whether a webhook should fire for (tenantID, alertType) and, if so,
// records the firing and returns true. Only one caller per (tenant, alertType) per cooldown gets true,
// preventing duplicate POSTs when concurrent Run() calls exceed the threshold.
func budgetAlertClaimFire(tenantID, alertType string) bool {
	budgetAlertDedupe.mu.Lock()
	defer budgetAlertDedupe.mu.Unlock()
	if budgetAlertDedupe.lastFired == nil {
		budgetAlertDedupe.lastFired = make(map[string]time.Time)
	}
	key := tenantID + ":" + alertType
	last, ok := budgetAlertDedupe.lastFired[key]
	if !ok || time.Since(last) >= budgetAlertCooldown {
		budgetAlertDedupe.lastFired[key] = time.Now().UTC()
		return true
	}
	return false
}

// emitBudgetAlertIfNeeded logs a structured warning and optionally POSTs to budget_alert_webhook
// when daily or monthly usage is >= 80% of the configured limit.
// Webhook POSTs are deduplicated per (tenant, alert_type) with a 1-hour cooldown to avoid flooding the endpoint.
func emitBudgetAlertIfNeeded(ctx context.Context, tenantID string, dailyCost, monthlyCost float64, limits *policy.CostLimitsConfig) {
	if limits == nil {
		return
	}
	payload := map[string]interface{}{
		"tenant_id":     tenantID,
		"daily_cost":    dailyCost,
		"monthly_cost":  monthlyCost,
		"daily_limit":   limits.Daily,
		"monthly_limit": limits.Monthly,
	}
	var fired bool
	var alertType string
	if limits.Daily > 0 && dailyCost >= budgetAlertThresholdPct*limits.Daily {
		log.Warn().
			Str("tenant_id", tenantID).
			Float64("daily_cost", dailyCost).
			Float64("daily_limit", limits.Daily).
			Msg("budget_approaching_limit_daily")
		alertType = "daily"
		payload["alert_type"] = alertType
		fired = true
	}
	if limits.Monthly > 0 && monthlyCost >= budgetAlertThresholdPct*limits.Monthly {
		log.Warn().
			Str("tenant_id", tenantID).
			Float64("monthly_cost", monthlyCost).
			Float64("monthly_limit", limits.Monthly).
			Msg("budget_approaching_limit_monthly")
		if !fired {
			alertType = "monthly"
		} else {
			alertType = "daily_and_monthly"
		}
		payload["alert_type"] = alertType
		fired = true
	}
	if fired && limits.BudgetAlertWebhook != "" {
		if budgetAlertClaimFire(tenantID, alertType) {
			go postBudgetAlert(limits.BudgetAlertWebhook, payload)
		}
	}
}

// allowedBudgetAlertURL returns true if the URL is safe for outbound webhook POST (HTTPS, or HTTP to loopback only).
// Used to mitigate SSRF when the URL comes from policy config.
func allowedBudgetAlertURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := strings.ToLower(u.Hostname())
		return h == "localhost" || h == "127.0.0.1" || strings.HasSuffix(h, ".localhost")
	default:
		return false
	}
}

func postBudgetAlert(webhookURL string, payload map[string]interface{}) {
	if !allowedBudgetAlertURL(webhookURL) {
		log.Warn().Str("url", webhookURL).Msg("budget_alert_webhook_url_rejected")
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Warn().Err(err).Msg("budget_alert_marshal_failed")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		log.Warn().Err(err).Str("url", webhookURL).Msg("budget_alert_request_failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	// URL was validated by allowedBudgetAlertURL (HTTPS or HTTP loopback only).
	resp, err := client.Do(req) // #nosec G704
	if err != nil {
		log.Warn().Err(err).Str("url", webhookURL).Msg("budget_alert_post_failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Warn().Int("status", resp.StatusCode).Str("url", webhookURL).Msg("budget_alert_webhook_non_2xx")
	}
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

	piiTypesSeen := make(map[string]bool)
	maxAttachmentTier := 0

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
		if r.classifier != nil {
			attachClass := r.classifier.Scan(ctx, text)
			if attachClass.Tier > maxAttachmentTier {
				maxAttachmentTier = attachClass.Tier
			}
			for _, e := range attachClass.Entities {
				if !piiTypesSeen[e.Type] {
					piiTypesSeen[e.Type] = true
					scan.PIIDetectedInAttachments = append(scan.PIIDetectedInAttachments, e.Type)
				}
			}
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
	scan.AttachmentTier = maxAttachmentTier
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

	if llm.ProviderUsesAPIKey(provider.Name()) && r.secrets != nil {
		provider, secretsAccessed = r.applyProviderKeyFromVaultOrEnv(ctx, req, provider)
	}

	return provider, model, degraded, originalModel, secretsAccessed, nil
}

// applyProviderKeyFromVaultOrEnv resolves the provider's API key from the vault (or env fallback)
// and returns the provider to use and any secret names that were accessed.
func (r *Runner) applyProviderKeyFromVaultOrEnv(ctx context.Context, req *RunRequest, provider llm.Provider) (resolved llm.Provider, secretsAccessed []string) {
	providerName := provider.Name()
	secretName := providerName + "-api-key"
	secret, secretErr := r.secrets.Get(ctx, secretName, req.TenantID, req.AgentName)
	if secretErr != nil && errors.Is(secretErr, secrets.ErrSecretNotFound) {
		alias := secretNameForProviderEnvAlias(providerName)
		if alias != "" {
			secret, secretErr = r.secrets.Get(ctx, alias, req.TenantID, req.AgentName)
			if secretErr == nil {
				secretName = alias
			}
		}
	}

	canonicalName := providerName + "-api-key"
	envVarName := secretNameForProviderEnvAlias(providerName)
	envSet := envVarName != "" && os.Getenv(envVarName) != ""

	if secretErr == nil {
		if envSet {
			r.secrets.RecordEnvFallback(ctx, canonicalName, req.TenantID, req.AgentName)
			log.Debug().
				Str("provider", providerName).
				Str("tenant_id", req.TenantID).
				Msg("operator env set — using env over vault")
			resolved = provider
			return
		}
		secretsAccessed = append(secretsAccessed, secretName)
		if p := llm.NewProviderWithKey(providerName, string(secret.Value)); p != nil {
			resolved = p
			return
		}
		resolved = provider
		return
	}

	if envSet {
		r.secrets.RecordEnvFallback(ctx, canonicalName, req.TenantID, req.AgentName)
		log.Debug().
			Str("provider", providerName).
			Str("tenant_id", req.TenantID).
			Msg("no tenant key in vault, using operator fallback")
	} else {
		r.secrets.RecordVaultMissNoFallback(ctx, canonicalName, req.TenantID, req.AgentName)
	}
	resolved = provider
	return
}

// secretNameForProviderEnvAlias returns the env-var-style secret name for a provider,
// so that "talon secrets set OPENAI_API_KEY ..." works as well as "openai-api-key".
// Returns empty string if there is no standard alias.
func secretNameForProviderEnvAlias(providerName string) string {
	switch providerName {
	case "openai":
		return "OPENAI_API_KEY"
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	default:
		return ""
	}
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

// mergePIIEntityNames merges two slices of PII entity type names and deduplicates.
// Returns a sorted slice so evidence and logs have deterministic ordering.
func mergePIIEntityNames(a, b []string) []string {
	seen := make(map[string]bool)
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		seen[s] = true
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
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
// costEstimate is the pre-run cost estimate from Run() (same value used for policy input).
func (r *Runner) maybeGateForPlanReview(ctx context.Context, pol *policy.Policy, req *RunRequest, correlationID string, dataTier int, processedPrompt string, costEstimate float64) (*RunResponse, bool, error) {
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
// Unknown non-empty mode values are treated as "shadow" (fail-closed) so typos or
// bypassed schema never cause live writes when shadow was intended.
func memoryMode(pol *policy.Policy) string {
	if pol.Memory == nil {
		return "disabled"
	}
	if !pol.Memory.Enabled {
		return "disabled"
	}
	switch pol.Memory.Mode {
	case "active":
		return "active"
	case "shadow", "disabled":
		return pol.Memory.Mode
	default:
		// Unknown or typo (e.g. "shadown"): fail closed to shadow so we never persist by mistake
		if pol.Memory.Mode != "" {
			log.Warn().Str("mode", pol.Memory.Mode).Msg("memory mode unknown, defaulting to shadow")
			return "shadow"
		}
		return "active"
	}
}

// writeMemoryObservation compresses the run result into a memory observation
// and writes it through the governance pipeline.
// In shadow mode, all checks run and results are logged, but no entry is persisted.
// policyEval is the per-run OPA engine for this invocation (avoids data race on shared Governance).
//
//nolint:gocyclo // orchestration flow is inherently branched
func (r *Runner) writeMemoryObservation(ctx context.Context, req *RunRequest, pol *policy.Policy, policyEval memory.PolicyEvaluator, resp *RunResponse, ev *evidence.Evidence) {
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
	if req.SkipMemory {
		log.Info().Str("tenant_id", req.TenantID).Str("agent_id", req.AgentName).Msg("memory_write_skipped_per_request")
		return
	}

	// Input-hash deduplication: skip write if we recently stored an observation for the same input.
	// Only when dedup_window_minutes > 0 (0 = disabled per docs); no default window.
	if ev.AuditTrail.InputHash != "" {
		var dedupWindow time.Duration
		if pol.Memory.Governance != nil && pol.Memory.Governance.DedupWindowMinutes > 0 {
			dedupWindow = time.Duration(pol.Memory.Governance.DedupWindowMinutes) * time.Minute
		}
		if dedupWindow > 0 {
			isDup, err := r.memory.HasRecentWithInputHash(ctx, req.TenantID, req.AgentName, ev.AuditTrail.InputHash, dedupWindow)
			if err != nil {
				log.Warn().Err(err).Msg("memory_dedup_check_failed")
			} else if isDup {
				log.Info().
					Str("input_hash", ev.AuditTrail.InputHash).
					Str("tenant_id", req.TenantID).
					Str("agent_id", req.AgentName).
					Msg("memory_write_skipped_duplicate")
				memory.DedupSkipsAdd(ctx, 1)
				return
			}
		}
	}

	// Strip private tags from response before persisting to memory (GDPR Art. 25).
	// Both Title and Content must be derived from clean content so <private> is never persisted.
	privacyResult := memory.StripPrivateTags(resp.Response)

	category, obsType, memType := inferCategoryTypeAndMemType(resp)
	observation := memory.Entry{
		TenantID:         req.TenantID,
		AgentID:          req.AgentName,
		Category:         category,
		Title:            compressTitle(resp, privacyResult.CleanContent),
		Content:          compressObservation(resp, privacyResult.CleanContent),
		ObservationType:  obsType,
		MemoryType:       memType,
		EvidenceID:       ev.ID,
		SourceType:       sourceTypeFromInvocation(req.InvocationType),
		SourceEvidenceID: ev.ID,
		InputHash:        ev.AuditTrail.InputHash,
	}

	if err := r.governance.ValidateWrite(ctx, &observation, pol, policyEval); err != nil {
		log.Warn().Err(err).
			Str("tenant_id", req.TenantID).
			Str("agent_id", req.AgentName).
			Str("category", observation.Category).
			Bool("memory.shadow", mode == "shadow").
			Msg("memory_write_denied")
		return
	}

	if mode == "shadow" {
		log.Info().
			Str("tenant_id", req.TenantID).
			Str("agent_id", req.AgentName).
			Str("category", observation.Category).
			Int("trust_score", observation.TrustScore).
			Str("review_status", observation.ReviewStatus).
			Str("evidence_id", ev.ID).
			Bool("memory.shadow", true).
			Msg("memory_shadow_observation")
		return
	}

	if r.consolidator != nil {
		result, err := r.consolidator.Evaluate(ctx, &observation)
		if err != nil {
			log.Warn().Err(err).Msg("consolidation_evaluate_failed")
			if writeErr := r.memory.Write(ctx, &observation); writeErr != nil {
				log.Error().Err(writeErr).Str("tenant_id", req.TenantID).Str("agent_id", req.AgentName).Msg("memory_write_failed")
			}
			return
		}
		log.Info().
			Str("action", string(result.Action)).
			Str("reason", result.Reason).
			Float64("similarity", result.Similarity).
			Msg("memory_consolidation_decision")
		if err := r.consolidator.Apply(ctx, &observation, result); err != nil {
			log.Error().Err(err).Str("tenant_id", req.TenantID).Str("agent_id", req.AgentName).Msg("consolidation_apply_failed")
			return
		}
		if result.Action == memory.ActionAdd || result.Action == memory.ActionInvalidate {
			log.Info().
				Str("tenant_id", req.TenantID).
				Str("agent_id", req.AgentName).
				Str("entry_id", observation.ID).
				Int("trust_score", observation.TrustScore).
				Str("review_status", observation.ReviewStatus).
				Msg("memory_observation_written")
		}
	} else {
		if err := r.memory.Write(ctx, &observation); err != nil {
			log.Error().Err(err).Str("tenant_id", req.TenantID).Str("agent_id", req.AgentName).Msg("memory_write_failed")
			return
		}
		log.Info().
			Str("tenant_id", req.TenantID).
			Str("agent_id", req.AgentName).
			Str("entry_id", observation.ID).
			Int("trust_score", observation.TrustScore).
			Str("review_status", observation.ReviewStatus).
			Msg("memory_observation_written")
	}
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

// filterOutPendingReview keeps only entries eligible for prompt injection (excludes pending_review).
// Must run before building memoryReads and capMemoryByTokens so evidence matches what is actually injected.
const reviewStatusPendingReview = "pending_review"

func filterOutPendingReview(entries []memory.IndexEntry) []memory.IndexEntry {
	var filtered []memory.IndexEntry
	for i := range entries {
		if entries[i].ReviewStatus != reviewStatusPendingReview {
			filtered = append(filtered, entries[i])
		}
	}
	return filtered
}

// capMemoryByTokens trims the memory index to fit within a token budget.
// It keeps entries from newest to oldest, dropping the oldest when over budget.
// Token count uses the index-line estimate only: formatMemoryIndexForPrompt emits
// one summary line per entry (~20 tokens), not the full content. Stored TokenCount
// is len(Content)/4 and would massively over-count, allowing far fewer entries than
// the budget intends.
func capMemoryByTokens(entries []memory.IndexEntry, maxTokens int) []memory.IndexEntry {
	var result []memory.IndexEntry
	totalTokens := 0
	for i := range entries {
		entryTokens := (len(entries[i].Title) + len(entries[i].Category) + 40) / 4 // one index line per entry
		if entryTokens < 5 {
			entryTokens = 5
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
// Entries are ordered by trust_score descending so the model sees highest-trust context first.
func formatMemoryIndexForPrompt(entries []memory.IndexEntry) string {
	if len(entries) == 0 {
		return ""
	}
	// Sort by trust descending so highest-trust context appears first in the prompt.
	sorted := make([]memory.IndexEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].TrustScore > sorted[j].TrustScore })

	var b strings.Builder
	b.WriteString("[AGENT MEMORY INDEX]\n")
	included := 0
	for i := range sorted {
		if sorted[i].ReviewStatus == reviewStatusPendingReview {
			continue
		}
		fmt.Fprintf(&b, "\u2713 %s | %s | %s | trust:%d | %s\n",
			sorted[i].ID, sorted[i].Category, sorted[i].Title, sorted[i].TrustScore,
			sorted[i].Timestamp.Format("2006-01-02"))
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
		resp.ModelUsed, resp.Cost, resp.DurationMS)
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
// Newlines are normalized to spaces so the first sentence is complete (e.g. "EUR 2\nMillion" -> "EUR 2 Million").
func compressTitle(resp *RunResponse, cleanContent string) string {
	if resp.DenyReason != "" {
		return "Denied: " + resp.DenyReason
	}
	text := normalizeTitleWhitespace(cleanContent)
	// First sentence ends at period; do not cut at newline (already normalized).
	if idx := strings.IndexByte(text, '.'); idx > 0 && idx < 80 {
		return text[:idx]
	}
	if len(text) > 80 {
		return text[:80]
	}
	return text
}

// normalizeTitleWhitespace replaces newlines and carriage returns with spaces and collapses multiple spaces,
// so the first logical sentence can be taken without losing text that was on the next line (e.g. "2\nMillion").
func normalizeTitleWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		switch r {
		case '\n', '\r', '\t':
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		case ' ':
			if !prevSpace {
				b.WriteRune(r)
				prevSpace = true
			}
		default:
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}

// inferCategoryTypeAndMemType maps run outcome to category, observation type, and memory type (three-type model).
// Order: policy denial → tool use → error → high cost → content keywords → default (domain_knowledge + semantic).
func inferCategoryTypeAndMemType(resp *RunResponse) (category, obsType, memType string) {
	category = memory.CategoryDomainKnowledge
	obsType = memory.ObsLearning
	memType = memory.MemTypeSemanticFact

	if resp.DenyReason != "" {
		return memory.CategoryPolicyHit, memory.ObsDecision, memory.MemTypeEpisodic
	}
	if len(resp.ToolsCalled) > 0 {
		return memory.CategoryToolApproval, memory.ObsToolUse, memory.MemTypeEpisodic
	}
	if resp.Cost > 0.10 {
		return memory.CategoryCostDecision, memory.ObsDecision, memory.MemTypeEpisodic
	}

	lower := strings.ToLower(resp.Response)
	// Use " i like " (with spaces), not "like", to avoid matching "looks like", "likely", "likewise", "would like to".
	switch {
	case containsAny(lower, "prefer", " i like ", "want", "always use", "never use", "favorite"):
		return memory.CategoryUserPreferences, memory.ObsLearning, memory.MemTypeSemanticFact
	case containsAny(lower, "step 1", "procedure", "workflow", "process", "how to", "best practice"):
		return memory.CategoryProcedureImprovements, memory.ObsLearning, memory.MemTypeProcedural
	case containsAny(lower, "correction", "actually", "wrong", "updated", "no longer"):
		return memory.CategoryFactualCorrections, memory.ObsLearning, memory.MemTypeSemanticFact
	}
	return category, obsType, memType
}

func containsAny(s string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// inferCategory returns the memory category for a run response (wrapper for inferCategoryTypeAndMemType).
func inferCategory(resp *RunResponse) string {
	cat, _, _ := inferCategoryTypeAndMemType(resp)
	return cat
}

// inferObservationType returns the observation type for a run response (wrapper for inferCategoryTypeAndMemType).
func inferObservationType(resp *RunResponse) string {
	_, obs, _ := inferCategoryTypeAndMemType(resp)
	return obs
}

// attachmentHashesFromRequest returns SHA256 hex of each attachment's content, sorted for deterministic evidence InputHash.
func attachmentHashesFromRequest(req *RunRequest) []string {
	if len(req.Attachments) == 0 {
		return nil
	}
	hashes := make([]string, 0, len(req.Attachments))
	for _, a := range req.Attachments {
		h := sha256.Sum256(a.Content)
		hashes = append(hashes, hex.EncodeToString(h[:]))
	}
	sort.Strings(hashes)
	return hashes
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
		RequireForTools: cfg.RequireForTools,
		RequireForTier:  cfg.RequireForTier,
		CostThreshold:   cfg.CostThreshold,
		TimeoutMinutes:  cfg.TimeoutMinutes,
		NotifyWebhook:   cfg.NotifyWebhook,
	}
}

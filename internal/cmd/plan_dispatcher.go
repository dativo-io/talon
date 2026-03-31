package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agent"
)

const planDispatchInterval = 2 * time.Second

func startPlanAutoDispatcher(ctx context.Context, store *agent.PlanReviewStore, runner *agent.Runner) {
	if store == nil || runner == nil {
		return
	}
	ticker := time.NewTicker(planDispatchInterval)
	go func() {
		defer ticker.Stop()
		// Initial pass avoids waiting one interval after startup.
		dispatchApprovedPlans(ctx, store, runner)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				dispatchApprovedPlans(ctx, store, runner)
			}
		}
	}()
}

func dispatchApprovedPlans(ctx context.Context, store *agent.PlanReviewStore, runner *agent.Runner) {
	plans, err := store.GetApprovedUndispatched(ctx, "")
	if err != nil {
		log.Warn().Err(err).Msg("plan_dispatch_scan_failed")
		return
	}
	for _, plan := range plans {
		dispatchApprovedPlan(ctx, store, runner, plan)
	}
}

func dispatchApprovedPlan(ctx context.Context, store *agent.PlanReviewStore, runner *agent.Runner, plan *agent.ExecutionPlan) {
	if plan == nil {
		return
	}
	if strings.TrimSpace(plan.Prompt) == "" {
		_ = store.MarkDispatched(ctx, plan.ID, plan.TenantID, "cannot auto-dispatch approved plan: prompt is empty")
		log.Warn().
			Str("plan_id", plan.ID).
			Str("tenant_id", plan.TenantID).
			Msg("approved_plan_skipped_empty_prompt")
		return
	}

	log.Info().
		Str("plan_id", plan.ID).
		Str("session_id", plan.SessionID).
		Str("tenant_id", plan.TenantID).
		Msg("plan_dispatch_starting")

	// Claim the plan before dispatching to prevent duplicate dispatch from
	// concurrent ticker iterations (MarkDispatched is idempotent with
	// dispatched_at IS NULL guard).
	if err := store.MarkDispatched(ctx, plan.ID, plan.TenantID, "dispatching"); err != nil {
		return
	}

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	resp, err := runner.Run(runCtx, &agent.RunRequest{
		TenantID:         plan.TenantID,
		AgentName:        plan.AgentID,
		Prompt:           plan.Prompt,
		SessionID:        plan.SessionID,
		InvocationType:   "plan_dispatch",
		PolicyPath:       plan.PolicyPath,
		BypassPlanReview: true,
	})
	if err != nil {
		msg := fmt.Sprintf("dispatch run failed: %v", err)
		_ = store.UpdateDispatchResult(ctx, plan.ID, plan.TenantID, msg)
		log.Warn().
			Err(err).
			Str("plan_id", plan.ID).
			Str("tenant_id", plan.TenantID).
			Msg("approved_plan_dispatch_failed")
		return
	}
	if !resp.PolicyAllow {
		msg := "dispatch denied by policy"
		if resp.DenyReason != "" {
			msg += ": " + resp.DenyReason
		}
		_ = store.UpdateDispatchResult(ctx, plan.ID, plan.TenantID, msg)
		log.Warn().
			Str("plan_id", plan.ID).
			Str("tenant_id", plan.TenantID).
			Str("deny_reason", resp.DenyReason).
			Msg("approved_plan_dispatch_denied")
		return
	}
	_ = store.UpdateDispatchResult(ctx, plan.ID, plan.TenantID, "")
	log.Info().
		Str("plan_id", plan.ID).
		Str("session_id", plan.SessionID).
		Str("tenant_id", plan.TenantID).
		Str("evidence_id", resp.EvidenceID).
		Str("model", resp.ModelUsed).
		Msg("approved_plan_dispatched")
}

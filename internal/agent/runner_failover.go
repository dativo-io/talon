package agent

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/failover"
	"github.com/dativo-io/talon/internal/llm"
)

// runFailover drives error-driven provider failover for an agent run (issue
// #138). It is a run-level FACTORY: the candidate list is resolved once and
// held immutable, and every Generate call gets its own failover engagement
// with a fresh chain walk and its own failover_group_id — an agentic run
// makes many LLM calls, and each call's failover chain must be independently
// evidenced and verifiable. Candidates were already filtered by the
// compliance routing policy at resolve time (sovereignty: under eu_strict a
// non-EU candidate never enters the list), so failover cannot become a policy
// bypass. Each engagement persists its failed attempts as separate signed
// records plus one terminal record (fallback decision or fail-closed), all
// linked by correlation ID and the shared group ID.
type runFailover struct {
	r               *Runner
	req             *RunRequest
	correlationID   string
	tier            int
	sovereigntyMode string
	complianceMode  bool
	// candidates are the tier's fallback candidates (chain positions >= 1),
	// resolved once and never mutated: every engagement walks a fresh copy.
	candidates []llm.ResolvedCandidate
	// skipped are chain candidates refused by the compliance routing policy
	// at resolve time — never dispatched, evidenced distinctly from failures.
	skipped []evidence.SkippedCandidate
	secrets *[]string
	// dataFlow builds the data-flow section for a failed-attempt record (the
	// prompt did egress to the failed provider). Set by the caller; nil skips.
	dataFlow func(providerName, model string) *evidence.DataFlow
}

// newRunFailover resolves the tier's fallback candidates (positions >= 1).
// Resolution failures disable failover for the run but never fail it — the
// primary path continues exactly as before.
func (r *Runner) newRunFailover(ctx context.Context, req *RunRequest, correlationID string, tier int, routingEngine llm.RoutingPolicyEvaluator, sovereigntyMode string, secrets *[]string) *runFailover {
	fo := &runFailover{
		r:               r,
		req:             req,
		correlationID:   correlationID,
		tier:            tier,
		sovereigntyMode: sovereigntyMode,
		complianceMode:  routingEngine != nil && sovereigntyMode != "",
		secrets:         secrets,
	}
	if r.router == nil {
		return fo
	}
	var opts *llm.RouteOptions
	if fo.complianceMode {
		opts = &llm.RouteOptions{PolicyEngine: routingEngine, SovereigntyMode: sovereigntyMode, DataTier: tier}
	}
	resolved, rejected, err := r.router.ResolveCandidates(ctx, tier, opts)
	if err != nil {
		log.Warn().Err(err).Str("correlation_id", correlationID).Msg("failover_candidates_unavailable")
		return fo
	}
	for _, c := range resolved {
		if c.ChainPosition >= 1 {
			fo.candidates = append(fo.candidates, c)
		}
	}
	for _, rej := range rejected {
		fo.skipped = append(fo.skipped, evidence.SkippedCandidate{
			Provider: rej.ProviderID,
			Filter:   "routing_policy",
			Reason:   rej.Reason,
		})
	}
	return fo
}

// failoverEngagement is the per-LLM-call failover state: one chain walk, one
// group ID, one terminal record.
type failoverEngagement struct {
	fo             *runFailover
	groupID        string
	failedAttempts []string
}

// generate calls provider.Generate and, on a transient failure, opens a fresh
// failover engagement over the tier's fallback candidates. Returns the
// response plus the provider and model actually used so the caller's evidence
// stays truthful.
func (f *runFailover) generate(ctx context.Context, provider llm.Provider, model string, llmReq *llm.Request) (*llm.Response, llm.Provider, string, error) {
	resp, err := provider.Generate(ctx, llmReq)
	if err == nil || f == nil {
		return resp, provider, model, err
	}
	class := llm.ClassifyGenerateError(err)
	if !class.Transient || (len(f.candidates) == 0 && len(f.skipped) == 0) {
		// Permanent failure, or no fallback chain configured at all:
		// failover was never engaged; behave exactly as before.
		return resp, provider, model, err
	}

	eng := &failoverEngagement{fo: f, groupID: "fog_" + uuid.New().String()[:12]}
	originalModel := model
	eng.recordAttempt(ctx, provider.Name(), providerJurisdiction(provider), model, class, 0, "", err, 0)

	remaining := make([]llm.ResolvedCandidate, len(f.candidates))
	copy(remaining, f.candidates)

	for _, cand := range remaining {
		if ctx.Err() != nil {
			break
		}
		if cand.ProviderName == provider.Name() && cand.Model == model {
			continue
		}

		p := cand.Provider
		if llm.ProviderUsesAPIKey(cand.ProviderName) && f.r.secrets != nil {
			var accessed []string
			p, accessed = f.r.applyProviderKeyFromVaultOrEnv(ctx, f.req, p)
			if f.secrets != nil {
				*f.secrets = append(*f.secrets, accessed...)
			}
		}

		log.Info().
			Str("correlation_id", f.correlationID).
			Str("failover_group_id", eng.groupID).
			Str("from_model", model).
			Str("to_model", cand.Model).
			Str("error_class", class.Class).
			Int("chain_position", cand.ChainPosition).
			Msg("llm_failover_attempt")

		attemptReq := *llmReq
		attemptReq.Model = cand.Model
		attemptStart := time.Now()
		resp, err = p.Generate(ctx, &attemptReq)
		if err == nil {
			eng.recordTerminal(ctx, &evidence.FailoverContext{
				Role:              evidence.FailoverRoleFallbackDecision,
				FailoverGroupID:   eng.groupID,
				Provider:          cand.ProviderName,
				Region:            cand.Jurisdiction,
				Model:             cand.Model,
				ChainPosition:     cand.ChainPosition,
				FallbackRuleID:    cand.RuleID,
				SovereigntyMode:   f.sovereigntyMode,
				SovereigntyCheck:  f.sovereigntyCheck(),
				FailedAttemptIDs:  eng.failedAttempts,
				SkippedCandidates: f.skipped,
			}, cand.ProviderName, cand.Model)
			llm.RecordFailover(ctx, originalModel, cand.Model, class.Class)
			return resp, p, cand.Model, nil
		}
		class = llm.ClassifyGenerateError(err)
		eng.recordAttempt(ctx, cand.ProviderName, cand.Jurisdiction, cand.Model, class, cand.ChainPosition, cand.RuleID, err, time.Since(attemptStart).Milliseconds())
		// Once failover is engaged, only success ends the chain: a fallback
		// candidate failing permanently (bad key, model not on that provider)
		// is that candidate's problem, not the request's — keep walking.
	}

	// Chain exhausted: fail closed. The caller receives the error; the
	// refusal to dispatch further is a governance outcome with its own
	// signed terminal record.
	eng.recordTerminal(ctx, &evidence.FailoverContext{
		Role:              evidence.FailoverRoleFailClosed,
		FailoverGroupID:   eng.groupID,
		ErrorClass:        class.Class,
		SovereigntyMode:   f.sovereigntyMode,
		FailedAttemptIDs:  eng.failedAttempts,
		SkippedCandidates: f.skipped,
	}, "", "")
	return nil, provider, model, err
}

func (f *runFailover) sovereigntyCheck() string {
	if f.complianceMode {
		return "allowed"
	}
	return "not_evaluated"
}

// recordAttempt persists one failed provider attempt as a signed evidence
// record linked to the run by correlation ID and to this engagement by
// failover_group_id (evidence-by-default).
func (e *failoverEngagement) recordAttempt(ctx context.Context, providerName, jurisdiction, model string, class failover.Classification, chainPosition int, ruleID string, genErr error, durationMS int64) {
	f := e.fo
	var flow *evidence.DataFlow
	if f.dataFlow != nil {
		flow = f.dataFlow(providerName, model)
	}
	failureReason := evidence.FailureReasonProviderTransient
	if !class.Transient {
		failureReason = evidence.FailureReasonProviderPermanent
	}
	ev, err := f.r.evidence.Generate(ctx, evidence.GenerateParams{
		CorrelationID:   f.correlationID,
		TenantID:        f.req.TenantID,
		AgentID:         f.req.AgentName,
		InvocationType:  "llm_failover_attempt",
		RequestSourceID: f.req.InvocationType,
		PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Classification:  evidence.Classification{InputTier: f.tier},
		ModelUsed:       model,
		DataFlow:        flow,
		DurationMS:      durationMS,
		Error:           genErr.Error(),
		Status:          string(RunStatusFailed),
		FailureReason:   failureReason,
		Failover: &evidence.FailoverContext{
			Role:            evidence.FailoverRoleFailedAttempt,
			FailoverGroupID: e.groupID,
			Provider:        providerName,
			Region:          jurisdiction,
			Model:           model,
			ErrorClass:      class.Class,
			ChainPosition:   chainPosition,
			FallbackRuleID:  ruleID,
			SovereigntyMode: f.sovereigntyMode,
		},
	})
	if err != nil {
		log.Error().Err(err).
			Str("correlation_id", f.correlationID).
			Str("tenant_id", f.req.TenantID).
			Str("agent_id", f.req.AgentName).
			Msg("evidence_write_failed_failover_attempt")
		return
	}
	e.failedAttempts = append(e.failedAttempts, ev.ID)
}

// recordTerminal persists this engagement's terminal record (fallback
// decision or fail-closed) as its own signed evidence record. Each LLM call's
// failover engagement gets exactly one terminal, so the verifier can check
// every (correlation_id, failover_group_id) chain independently.
func (e *failoverEngagement) recordTerminal(ctx context.Context, fc *evidence.FailoverContext, selectedProvider, selectedModel string) {
	f := e.fo
	params := evidence.GenerateParams{
		CorrelationID:   f.correlationID,
		TenantID:        f.req.TenantID,
		AgentID:         f.req.AgentName,
		InvocationType:  "llm_failover_decision",
		RequestSourceID: f.req.InvocationType,
		PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Classification:  evidence.Classification{InputTier: f.tier},
		Status:          string(RunStatusCompleted),
		Failover:        fc,
	}
	if fc.Role == evidence.FailoverRoleFailClosed {
		params.Status = string(RunStatusFailed)
		params.FailureReason = evidence.FailureReasonNoValidFallbackCandidate
		params.Error = "no policy-valid fallback candidate succeeded (fail-closed)"
	} else {
		params.ModelUsed = selectedModel
		if f.dataFlow != nil {
			params.DataFlow = f.dataFlow(selectedProvider, selectedModel)
		}
	}
	if _, err := f.r.evidence.Generate(ctx, params); err != nil {
		log.Error().Err(err).
			Str("correlation_id", f.correlationID).
			Str("failover_group_id", e.groupID).
			Str("tenant_id", f.req.TenantID).
			Str("agent_id", f.req.AgentName).
			Msg("evidence_write_failed_failover_terminal")
	}
}

func providerJurisdiction(p llm.Provider) string {
	if p == nil {
		return ""
	}
	return p.Metadata().Jurisdiction
}

package agent

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/failover"
	"github.com/dativo-io/talon/internal/llm"
)

// runFailover drives error-driven provider failover for a single agent run
// (issue #138): on a transient Generate failure the tier's remaining
// fallback_chain candidates are tried in order. Candidates were already
// filtered by the compliance routing policy at resolve time (sovereignty:
// under eu_strict a non-EU candidate never enters the list), so failover
// cannot become a policy bypass. Each failed runtime attempt is persisted as
// its own signed evidence record; the final run record carries the fallback
// decision (or fail-closed outcome) linked by correlation ID.
type runFailover struct {
	r               *Runner
	req             *RunRequest
	correlationID   string
	tier            int
	sovereigntyMode string
	complianceMode  bool
	remaining       []llm.ResolvedCandidate
	// skipped are chain candidates refused by the compliance routing policy
	// at resolve time — never dispatched, evidenced distinctly from failures.
	skipped        []evidence.SkippedCandidate
	failedAttempts []string
	secrets        *[]string
	// dataFlow builds the data-flow section for a failed-attempt record (the
	// prompt did egress to the failed provider). Set by the caller; nil skips.
	dataFlow func(providerName, model string) *evidence.DataFlow
	// decision is the FailoverContext for the run's final evidence record;
	// nil until failover is engaged.
	decision *evidence.FailoverContext
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
			fo.remaining = append(fo.remaining, c)
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

// generate calls provider.Generate and, on a transient failure, walks the
// remaining fallback candidates. Returns the response plus the provider and
// model actually used so the caller's evidence stays truthful.
func (f *runFailover) generate(ctx context.Context, provider llm.Provider, model string, llmReq *llm.Request) (*llm.Response, llm.Provider, string, error) {
	resp, err := provider.Generate(ctx, llmReq)
	if err == nil || f == nil {
		return resp, provider, model, err
	}
	class := llm.ClassifyGenerateError(err)
	if !class.Transient || (len(f.remaining) == 0 && len(f.skipped) == 0) {
		// Permanent failure, or no fallback chain configured at all:
		// failover was never engaged; behave exactly as before.
		return resp, provider, model, err
	}

	originalModel := model
	f.recordAttempt(ctx, provider.Name(), providerJurisdiction(provider), model, class, 0, "", err, 0)

	for len(f.remaining) > 0 {
		if ctx.Err() != nil {
			break
		}
		cand := f.remaining[0]
		f.remaining = f.remaining[1:]
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
			f.decision = &evidence.FailoverContext{
				Role:              evidence.FailoverRoleFallbackDecision,
				Provider:          cand.ProviderName,
				Region:            cand.Jurisdiction,
				Model:             cand.Model,
				ChainPosition:     cand.ChainPosition,
				FallbackRuleID:    cand.RuleID,
				SovereigntyMode:   f.sovereigntyMode,
				SovereigntyCheck:  f.sovereigntyCheck(),
				FailedAttemptIDs:  f.failedAttempts,
				SkippedCandidates: f.skipped,
			}
			llm.RecordFailover(ctx, originalModel, cand.Model, class.Class)
			return resp, p, cand.Model, nil
		}
		class = llm.ClassifyGenerateError(err)
		f.recordAttempt(ctx, cand.ProviderName, cand.Jurisdiction, cand.Model, class, cand.ChainPosition, cand.RuleID, err, time.Since(attemptStart).Milliseconds())
		// Once failover is engaged, only success ends the chain: a fallback
		// candidate failing permanently (bad key, model not on that provider)
		// is that candidate's problem, not the request's — keep walking.
	}

	// Chain exhausted: fail closed. The caller receives the error; the
	// refusal to dispatch further is a governance outcome recorded on the
	// final run record.
	f.decision = &evidence.FailoverContext{
		Role:              evidence.FailoverRoleFailClosed,
		ErrorClass:        class.Class,
		SovereigntyMode:   f.sovereigntyMode,
		FailedAttemptIDs:  f.failedAttempts,
		SkippedCandidates: f.skipped,
	}
	return nil, provider, model, err
}

func (f *runFailover) sovereigntyCheck() string {
	if f.complianceMode {
		return "allowed"
	}
	return "not_evaluated"
}

// recordAttempt persists one failed provider attempt as a signed evidence
// record linked to the run by correlation ID (evidence-by-default).
func (f *runFailover) recordAttempt(ctx context.Context, providerName, jurisdiction, model string, class failover.Classification, chainPosition int, ruleID string, genErr error, durationMS int64) {
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
	f.failedAttempts = append(f.failedAttempts, ev.ID)
}

func providerJurisdiction(p llm.Provider) string {
	if p == nil {
		return ""
	}
	return p.Metadata().Jurisdiction
}

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/workload"
)

// Delegated response governance (#482 response side).
//
// On the delegated (OpenShell) path Talon decides the request at the
// runtime's PRE_CREDENTIALS hook and, when the response hook is enabled,
// sees the provider's answer at PRE_RETURN before the sandbox does. The two
// halves are joined by the runtime's own request id through the durable
// settlement ledger (settlement_repo.go): the request half writes a pending
// row (estimate, session reservation, the response policy in force); the
// response half claims it, observes actual usage, prices it, settles the
// session budget, applies the response PII policy, and commits a second
// signed record under the SAME correlation id.
//
// Cost truth: while a settlement is pending the decision record carries
// cost 0 with PricingBasisAwaitingSettlement, so spend sums never count an
// estimate and an actual for one request. Exactly one later record carries
// the request's cost: the settlement (actual usage priced from the table, or
// the estimate when the provider sent no usage) or, when no response was
// observed within the settlement window, an unobserved settlement with the
// estimate. A response that arrives after that writes a reconciliation whose
// cost is only the amount by which the actual exceeded the booked estimate,
// so the sum over records is max(estimate, actual), never estimate plus
// actual. Repeated callbacks for one exchange replay the recorded outcome
// and write nothing. Pending estimates still count toward the daily/monthly
// budget check, and the ledger is bounded by refusing NEW delegated
// requests when it is full — never by discarding an obligation.

const (
	// InvocationTypeGatewayResponse is the settlement record of one
	// delegated request (same correlation id as its decision record).
	InvocationTypeGatewayResponse = "gateway_response"

	// PricingBasisAwaitingSettlement: a decision record whose cost will be
	// carried by a later settlement record (cost here is 0).
	PricingBasisAwaitingSettlement = "awaiting_settlement"
	// PricingBasisEstimateNoUsage: a response was observed but carried no
	// usage fields; the pre-request estimate stands as the cost.
	PricingBasisEstimateNoUsage = "estimate_no_usage"
	// PricingBasisEstimateUnsettled: no response was observed within the
	// settlement window; the pre-request estimate stands as the cost.
	PricingBasisEstimateUnsettled = "estimate_unsettled"
	// PricingBasisLateReconciliation: a response observed AFTER the estimate
	// was booked; this record's cost is max(0, actual − estimate).
	PricingBasisLateReconciliation = "late_reconciliation"

	annotationSettlementPending = "response_settlement_pending"
	annotationResponseObserved  = "response_observed"
	annotationResponseUnseen    = "response_unobserved"
	annotationResponseLate      = "response_observed_late"
	annotationDecisionUnmatched = "decision_unmatched"
	annotationBodyUninspectable = "response_body_uninspectable"
	annotationErrorBodyScanned  = "provider_error_body_scanned"
	annotationProviderError     = "provider_error"

	// FailureReasonResponseUnobserved marks an unobserved settlement.
	FailureReasonResponseUnobserved = "response_unobserved"

	// Response plan modes (what the runtime is asked to deliver to Talon).
	ResponseModeSkip        = "skip"
	ResponseModeHeadersOnly = "headers_only"
	ResponseModeWholeBody   = "whole_body"
	ResponseModeStream      = "stream"

	// Codes specific to the response hop.
	CodeResponseScanUnavailable = "output_scan_unavailable"
	// CodeSettlementCapacityExhausted: the ledger holds max_pending
	// obligations; new delegated requests are refused until some settle.
	CodeSettlementCapacityExhausted = "settlement_capacity_exhausted"
	// CodeSettlementUnavailable: the ledger could not be read or written.
	CodeSettlementUnavailable = "settlement_unavailable"
	// CodeSettlementReplayed: a repeated callback for an exchange that was
	// already settled; the recorded verdict was returned, nothing written.
	CodeSettlementReplayed = "settlement_replayed"

	settlementSweepBatch  = 500
	settlementReplayBasis = "replay"
)

// responseGovernanceEnabled reports whether decisions park a settlement.
func (g *Gateway) responseGovernanceEnabled() bool {
	return g.config != nil && g.config.OpenShell.ResponseGovernanceEnabled() && g.settlements != nil
}

func (g *Gateway) settlementTimeout() time.Duration {
	if g.config == nil || g.config.OpenShell == nil || g.config.OpenShell.ResponseGovernance == nil {
		d, _ := time.ParseDuration(DefaultOpenShellSettlementTimeout)
		return d
	}
	return g.config.OpenShell.ResponseGovernance.SettlementTimeoutDuration()
}

// RunDelegatedSettlementSweeper settles pending exchanges whose response
// never arrived within the settlement window, until ctx ends.
func (g *Gateway) RunDelegatedSettlementSweeper(ctx context.Context) {
	if g.settlements == nil {
		return
	}
	interval := g.settlementTimeout() / 4
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			g.SweepDelegatedPending(ctx, now)
		}
	}
}

// SweepDelegatedPending settles every expired pending exchange as
// unobserved: the estimate stands as the cost, the session reservation is
// settled with it, and the record says no response was seen. Each row is
// claimed (pending → unobserved) before anything is written, so a response
// arriving concurrently either wins the claim or reconciles afterwards.
func (g *Gateway) SweepDelegatedPending(ctx context.Context, now time.Time) int {
	if g.settlements == nil {
		return 0
	}
	rows, err := g.settlements.expiredPending(ctx, now.Add(-g.settlementTimeout()), settlementSweepBatch)
	if err != nil {
		log.Warn().Err(err).Msg("delegated_settlement_sweep_failed")
		return 0
	}
	n := 0
	for _, r := range rows {
		claimed, err := g.settlements.claim(ctx, r.key, settlementPending, settlementUnobserved)
		if err != nil || !claimed {
			continue
		}
		g.settleUnobserved(ctx, r)
		n++
	}
	return n
}

func (g *Gateway) settleUnobserved(ctx context.Context, r *settlementRow) {
	ctx = g.delegatedContext(ctx, r.sessionID, r.sessionSource)
	agent := g.settlementAgent(r)
	cost := r.estimate
	if r.isCountTokens {
		cost = 0
	}
	persisted, err := g.recordEvidence(ctx, r.correlationID, agent, r.provider, r.model, r.startedAt, "", nil, nil, cost,
		time.Since(r.startedAt).Milliseconds(), "", true, nil, false, nil, nil, nil, false, "", 0, 0, false, 0, 0, r.estimate,
		g.settlementProvenance(r), func(p *RecordGatewayEvidenceParams) {
			p.InvocationType = InvocationTypeGatewayResponse
			p.Status = evidence.StatusUnknown
			p.FailureReason = FailureReasonResponseUnobserved
			p.PricingBasis = PricingBasisEstimateUnsettled
			p.PricingKnown = false
			p.GatewayAnnotations = append(p.GatewayAnnotations, annotationResponseUnseen)
			p.ExplanationFacts = []explanation.Fact{{
				Code: explanation.CodeExecutionOutcomeUnknown, Decision: explanation.DecisionUnknown, Stage: explanation.StageExecution,
				Trigger: FailureReasonResponseUnobserved,
			}}
		})
	if err != nil {
		// The obligation stays: back to pending so the next sweep retries.
		g.handleEvidenceWriteFailure(ctx, err)
		if _, rerr := g.settlements.claim(ctx, r.key, settlementUnobserved, settlementPending); rerr != nil {
			log.Error().Err(rerr).Str("correlation_id", r.correlationID).Msg("delegated_settlement_revert_failed")
		}
		return
	}
	if err := g.settlements.finish(ctx, r.key, persisted.ID, cost, false, FailureReasonResponseUnobserved, time.Now()); err != nil {
		log.Error().Err(err).Str("correlation_id", r.correlationID).Msg("delegated_settlement_finish_failed")
	}
	g.trackSessionUsage(ctx, r.reservation(), r.sessionID, r.sessionSource, r.tenantID, r.agentName, cost, 0)
	log.Warn().Str("correlation_id", r.correlationID).Str("agent", r.agentName).Msg("delegated_response_unobserved")
}

// settlementAgent resolves the current identity of the row's use case, or a
// minimal identity carrying the row's name/tenant when the binding changed
// meanwhile (the obligation is still attributed to the use case that
// incurred it).
func (g *Gateway) settlementAgent(r *settlementRow) *ResolvedIdentity {
	if reg := g.registry.Current(); reg != nil {
		if id, ok := reg.ResolveWorkload(r.runtime, r.principal.Subject); ok && id.Name == r.agentName {
			return id
		}
	}
	return &ResolvedIdentity{Name: r.agentName, TenantID: r.tenantID, Enabled: true}
}

func (g *Gateway) settlementProvenance(r *settlementRow) func(*RecordGatewayEvidenceParams) {
	return delegatedProvenance(DelegatedRequest{
		Runtime: r.runtime, RuntimeID: r.key.runtimeID, Principal: r.principalFacts(), PolicyRef: r.policyRef,
		Reference: r.key.sandboxRef, RequestID: r.key.requestID,
	})
}

func (g *Gateway) delegatedContext(ctx context.Context, sessionID, sessionSource string) context.Context {
	ctx = context.WithValue(ctx, gatewaySessionIDKey, sessionID)
	ctx = context.WithValue(ctx, gatewaySessionSourceKey, sessionSource)
	return context.WithValue(ctx, gatewayUpstreamAuthMode, UpstreamAuthModeExternalRuntime)
}

// ---- preflight -------------------------------------------------------

// DelegatedResponsePreflight is what the runtime shows Talon before any
// response byte reaches the sandbox.
type DelegatedResponsePreflight struct {
	Runtime, RuntimeID string
	Principal          *workload.Principal
	IdentityFailure    string
	Host               string
	SandboxRef         string
	RequestID          string
	Status             int
	ContentType        string
	ContentEncoding    string
	// BodyInspectable mirrors the runtime's permitted body modes: false when
	// the runtime cannot hand Talon the body (compressed, partial, no body).
	BodyInspectable bool
	StreamPermitted bool
}

// DelegatedResponsePlan tells the hook how to proceed.
type DelegatedResponsePlan struct {
	Mode    string // ResponseMode*
	Block   bool   // deny delivery outright (identity failure, preventive policy without inspectable body)
	Code    string
	Message string
	// Matched is true when the request half was found in the ledger.
	Matched bool
	Agent   string
}

// responseContext is what the plan and the settlement both need to know
// about one exchange: the ledger row when it exists, otherwise the policy
// reconstructed from trusted current configuration.
type responseContext struct {
	row      *settlementRow
	agent    *ResolvedIdentity
	provider string
	action   string
}

func preventive(action string) bool { return action == "block" || action == "redact" }

// resolveResponseContext finds the request half or reconstructs it. It
// never relaxes policy: without a row, the response policy comes from the
// use case's CURRENT effective policy, and an unbound principal is refused.
func (g *Gateway) resolveResponseContext(ctx context.Context, pf DelegatedResponsePreflight) (*responseContext, *DelegatedResponsePlan) {
	key := settlementKey{pf.RuntimeID, pf.SandboxRef, pf.RequestID}
	var row *settlementRow
	if g.settlements != nil {
		r, err := g.settlements.get(ctx, key)
		if err != nil {
			log.Error().Err(err).Msg("delegated_settlement_read_failed")
			return nil, &DelegatedResponsePlan{Block: true, Code: CodeSettlementUnavailable, Message: CodeSettlementUnavailable + ": Talon could not read the settlement ledger (fail-closed)"}
		}
		row = r
	}
	if row != nil {
		return &responseContext{row: row, agent: g.settlementAgent(row), provider: row.provider, action: row.responsePIIAction}, nil
	}
	// No request half: Talon's own API behind the same hostname, a runtime
	// misbinding, or a request decided before a ledger existed. A host with
	// no provider is not a model response — skip. Otherwise the principal
	// must still bind (fail closed) and the policy is the current one.
	provider, governed := g.config.providerForHost(pf.Host)
	if !governed {
		return nil, &DelegatedResponsePlan{Mode: ResponseModeSkip, Code: CodeDestinationNotGoverned}
	}
	agent, ok := g.registry.Current().ResolveWorkload(pf.Runtime, pf.Principal.Subject)
	if !ok {
		RecordGatewayError(ctx, CodeWorkloadIdentityUnbound)
		return nil, &DelegatedResponsePlan{Block: true, Code: CodeWorkloadIdentityUnbound, Message: CodeWorkloadIdentityUnbound + ": verified workload principal is not bound to any Talon AI use case"}
	}
	if !agent.Enabled {
		RecordGatewayError(ctx, CodeAgentDisabled)
		return nil, &DelegatedResponsePlan{Block: true, Code: CodeAgentDisabled, Message: CodeAgentDisabled + ": agent is disabled"}
	}
	prov, _ := g.config.Provider(provider)
	eff := ResolveEffectivePolicy(g.config.OrganizationPolicy, prov, agent.Override)
	return &responseContext{agent: agent, provider: provider, action: eff.ResponsePIIAction}, nil
}

// PlanDelegatedResponse chooses the inspection mode from the exchange's
// response policy and the response shape. It never changes the ledger.
func (g *Gateway) PlanDelegatedResponse(ctx context.Context, pf DelegatedResponsePreflight) DelegatedResponsePlan {
	if pf.Principal == nil {
		code := pf.IdentityFailure
		if code == "" {
			code = workload.FailureMissing
		}
		RecordGatewayError(ctx, code)
		log.Warn().Str("runtime", pf.Runtime).Str("failure", code).Msg("delegated_response_identity_rejected")
		return DelegatedResponsePlan{Block: true, Code: CodeWorkloadIdentityRequired, Message: CodeWorkloadIdentityRequired + ": verified workload identity required (" + code + ")"}
	}
	rc, refused := g.resolveResponseContext(ctx, pf)
	if refused != nil {
		return *refused
	}
	if rc.row != nil && rc.row.settledBlock {
		// Already settled as blocked: a repeated callback stays blocked.
		return DelegatedResponsePlan{Block: true, Code: rc.row.settledCode, Message: "replay of a blocked response", Matched: true, Agent: rc.row.agentName}
	}
	plan := planResponseMode(rc.action, pf)
	plan.Matched, plan.Agent = rc.row != nil, rc.agent.Name
	if plan.Block {
		RecordGatewayError(ctx, plan.Code)
	}
	return plan
}

// planResponseMode maps the response policy and the response shape to an
// inspection mode (or a block). Provider error bodies are NOT assumed to be
// harmless: under an observing policy an inspectable error body is scanned
// like any other, and under a preventive one an uninspectable error body
// is blocked.
func planResponseMode(action string, pf DelegatedResponsePreflight) DelegatedResponsePlan {
	prevent := preventive(action)
	observing := action != "" && action != "allow"
	ct := strings.ToLower(pf.ContentType)
	isSSE := strings.Contains(ct, "text/event-stream")
	isJSON := strings.Contains(ct, "application/json")
	isText := strings.HasPrefix(ct, "text/")
	uninspectable := !pf.BodyInspectable || (pf.ContentEncoding != "" && !strings.EqualFold(pf.ContentEncoding, "identity"))
	if pf.Status >= http.StatusBadRequest {
		return planErrorResponseMode(observing, prevent, uninspectable, isJSON || isText)
	}
	switch {
	case !isSSE && !isJSON:
		// Not a model body: nothing to scan or price; settle from the headers.
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly}
	case uninspectable && prevent:
		// The policy promises prevention and the body cannot be seen: fail
		// closed, never deliver unscanned bytes.
		return DelegatedResponsePlan{Block: true, Code: CodeResponseScanUnavailable, Message: "response body cannot be inspected and the response PII policy is preventive"}
	case uninspectable:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly, Code: annotationBodyUninspectable}
	case isSSE && !prevent && pf.StreamPermitted:
		// Observation: the sandbox streams while Talon watches; the record
		// says post-delivery.
		return DelegatedResponsePlan{Mode: ResponseModeStream}
	default:
		// Preventive (block/redact) or non-streaming: the runtime holds the
		// whole body until Talon answers.
		return DelegatedResponsePlan{Mode: ResponseModeWholeBody}
	}
}

// planErrorResponseMode is the plan for a provider 4xx/5xx: nothing to
// price, but the body is still subject to the response policy.
func planErrorResponseMode(observing, prevent, uninspectable, textual bool) DelegatedResponsePlan {
	switch {
	case !observing:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly}
	case uninspectable && prevent:
		return DelegatedResponsePlan{Block: true, Code: CodeResponseScanUnavailable, Message: "provider error body cannot be inspected and the response PII policy is preventive"}
	case uninspectable || !textual:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly, Code: annotationBodyUninspectable}
	default:
		return DelegatedResponsePlan{Mode: ResponseModeWholeBody}
	}
}

// ---- settlement ------------------------------------------------------

// DelegatedResponseBody is the observed response: the whole body (whole_body
// mode), the bounded capture (stream mode) or nothing (headers_only).
type DelegatedResponseBody struct {
	Preflight DelegatedResponsePreflight
	Mode      string
	Body      []byte
	// Truncated: the stream capture hit its bound; usage/scan are partial.
	Truncated bool
	// Incomplete names why the stream ended abnormally ("" = complete).
	Incomplete string
	BytesSeen  int64
	CaptureCap int64
}

// DelegatedSettlement is the hook's answer for the body: deliver as is,
// deliver a replacement, or block delivery; plus the committed record.
type DelegatedSettlement struct {
	Block       bool
	Body        []byte
	BodyChanged bool
	Code        string
	Message     string
	EvidenceID  string
	PIITypes    []string
	Redacted    bool
	Cost        float64
	Tokens      TokenUsage
	Basis       string
	// Replayed is true when this callback repeated an already settled
	// exchange: the recorded verdict was returned and nothing was written.
	Replayed bool
}

// settlementKind is which ledger transition a settlement performs.
type settlementKind int

const (
	settleFirst     settlementKind = iota // pending → settled
	settleLate                            // unobserved → reconciled
	settleUnmatched                       // no row: observed once under a fresh row
)

// SettleDelegatedResponse observes one response: usage, cost, response PII
// policy, session budget, signed record. It is idempotent per runtime
// exchange: the ledger row is claimed before anything is written, a
// repeated callback replays the recorded verdict, and a response that
// arrives after the sweeper booked the estimate reconciles against it.
//
//nolint:gocyclo // one ordered transition protocol; splitting it would hide the order
func (g *Gateway) SettleDelegatedResponse(ctx context.Context, in DelegatedResponseBody) DelegatedSettlement {
	pf := in.Preflight
	if pf.Principal == nil {
		return DelegatedSettlement{Block: true, Code: CodeWorkloadIdentityRequired}
	}
	rc, refused := g.resolveResponseContext(ctx, pf)
	if refused != nil {
		return DelegatedSettlement{Block: refused.Block, Code: refused.Code, Message: refused.Message}
	}
	key := settlementKey{pf.RuntimeID, pf.SandboxRef, pf.RequestID}
	kind := settleFirst
	switch {
	case rc.row == nil:
		kind = settleUnmatched
		if g.settlements != nil {
			// Give the unmatched exchange a row first so a repeated callback
			// replays instead of observing twice; losing the race to another
			// callback means that callback owns the settlement.
			row := g.newUnmatchedRow(key, pf, rc)
			if err := g.settlements.insert(ctx, row); err != nil {
				if errors.Is(err, errSettlementExists) {
					return g.replaySettlement(ctx, key, in, rc)
				}
				log.Error().Err(err).Msg("delegated_settlement_insert_failed")
				return g.failClosed(rc.action, CodeSettlementUnavailable)
			}
			rc.row = row
		}
	case rc.row.status == settlementSettled, rc.row.status == settlementReconciled:
		return g.replaySettlement(ctx, key, in, rc)
	case rc.row.status == settlementUnobserved:
		kind = settleLate
	}
	if g.settlements != nil {
		from, to := settlementPending, settlementSettled
		if kind == settleLate {
			from, to = settlementUnobserved, settlementReconciled
		}
		claimed, err := g.settlements.claim(ctx, key, from, to)
		if err != nil {
			log.Error().Err(err).Msg("delegated_settlement_claim_failed")
			return g.failClosed(rc.action, CodeSettlementUnavailable)
		}
		if !claimed {
			// A concurrent callback or the sweeper moved the row first.
			return g.replaySettlement(ctx, key, in, rc)
		}
	}
	out := g.observeAndRecord(ctx, in, rc, kind)
	if g.settlements == nil {
		return out
	}
	if out.EvidenceID == "" {
		// Nothing committed: the obligation stays open for the sweeper, and
		// a row that never had a decision is removed again.
		switch kind {
		case settleUnmatched:
			_ = g.settlements.delete(ctx, key)
		case settleLate:
			if _, err := g.settlements.claim(ctx, key, settlementReconciled, settlementUnobserved); err != nil {
				log.Error().Err(err).Msg("delegated_settlement_revert_failed")
			}
		default:
			if _, err := g.settlements.claim(ctx, key, settlementSettled, settlementPending); err != nil {
				log.Error().Err(err).Msg("delegated_settlement_revert_failed")
			}
		}
		return out
	}
	booked := out.Cost
	if kind == settleLate {
		booked = rc.row.settledCost + out.Cost
	}
	if err := g.settlements.finish(ctx, key, out.EvidenceID, booked, out.Block, out.Code, time.Now()); err != nil {
		log.Error().Err(err).Msg("delegated_settlement_finish_failed")
	}
	return out
}

// failClosed answers a ledger failure: a preventive policy blocks delivery
// rather than release an unrecorded response; an observational one passes
// the bytes (nothing is recorded, and the log says so).
func (g *Gateway) failClosed(action, code string) DelegatedSettlement {
	if preventive(action) {
		return DelegatedSettlement{Block: true, Code: code, Message: code + ": Talon could not settle the response (fail-closed)"}
	}
	return DelegatedSettlement{Code: code}
}

// newUnmatchedRow is the ledger row for a response whose request half is
// unknown (Talon restarted before the ledger existed, or the row aged out):
// a fresh correlation id, the current policy, no reservation.
func (g *Gateway) newUnmatchedRow(key settlementKey, pf DelegatedResponsePreflight, rc *responseContext) *settlementRow {
	correlationID := "gw_" + uuid.New().String()[:12]
	return &settlementRow{
		key: key, runtime: pf.Runtime, correlationID: correlationID, tenantID: rc.agent.TenantID, agentName: rc.agent.Name,
		provider: rc.provider, responsePIIAction: rc.action, sessionID: "sess_" + correlationID, sessionSource: "synthetic",
		principal: principalProjection(pf.Principal), startedAt: time.Now(), status: settlementPending,
	}
}

func principalProjection(p *workload.Principal) settlementPrincipal {
	if p == nil {
		return settlementPrincipal{}
	}
	return settlementPrincipal{
		Issuer: p.Issuer, Subject: p.Subject, PrincipalID: p.PrincipalID, Audience: p.Audience, AuthMethod: p.AuthMethod,
		VerifiedAt: p.VerifiedAt.UTC().Format(time.RFC3339),
	}
}

// replaySettlement answers a repeated callback from the ledger: the recorded
// verdict, the recorded evidence id, no new record, no cost. An allowed
// response under a preventive policy is re-inspected so the replacement
// body is reproduced byte for byte.
func (g *Gateway) replaySettlement(ctx context.Context, key settlementKey, in DelegatedResponseBody, rc *responseContext) DelegatedSettlement {
	row := rc.row
	if row == nil && g.settlements != nil {
		row, _ = g.settlements.get(ctx, key)
	}
	if row == nil {
		return g.failClosed(rc.action, CodeSettlementUnavailable)
	}
	out := DelegatedSettlement{Replayed: true, Basis: settlementReplayBasis, Code: CodeSettlementReplayed, EvidenceID: row.settledEvidenceID}
	if row.settledBlock {
		out.Block, out.Code, out.Message = true, row.settledCode, "replay of a blocked response"
		return out
	}
	if in.Mode == ResponseModeWholeBody && len(in.Body) > 0 && preventive(rc.action) && in.Preflight.Status < http.StatusBadRequest {
		body, scan := g.applyResponsePolicy(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), in, rc.action, g.config.providerAPIFamily(rc.provider))
		if scan != nil && scan.Blocked {
			out.Block, out.Code = true, scan.BlockReason
			return out
		}
		out.Body, out.BodyChanged = body, !bytes.Equal(body, in.Body)
	}
	return out
}

// observeAndRecord is the observation proper: usage, cost, policy, record,
// session. kind decides the cost semantics and the annotations.
//
//nolint:gocyclo // one ordered observation; the branches are its facts
func (g *Gateway) observeAndRecord(ctx context.Context, in DelegatedResponseBody, rc *responseContext, kind settlementKind) DelegatedSettlement {
	pf := in.Preflight
	row := rc.row
	agent := rc.agent
	provider, model, correlationID := rc.provider, "", "gw_"+uuid.New().String()[:12]
	var estimate float64
	sessionID, sessionSo := "sess_"+correlationID, "synthetic"
	var reservation *sessionReservation
	start := time.Now()
	provenanceOpt := delegatedProvenance(DelegatedRequest{
		Runtime: pf.Runtime, RuntimeID: pf.RuntimeID, Principal: pf.Principal, Reference: pf.SandboxRef, RequestID: pf.RequestID,
	})
	annotations := []string{annotationResponseObserved}
	if row != nil {
		correlationID, model, estimate = row.correlationID, row.model, row.estimate
		sessionID, sessionSo, reservation, start = row.sessionID, row.sessionSource, row.reservation(), row.startedAt
		provenanceOpt = g.settlementProvenance(row)
	}
	switch kind {
	case settleUnmatched:
		annotations = append(annotations, annotationDecisionUnmatched)
	case settleLate:
		annotations = append(annotations, annotationResponseLate)
		reservation = nil // the unobserved settlement already settled the reservation
	}
	ctx = g.delegatedContext(ctx, sessionID, sessionSo)
	wire := g.config.providerAPIFamily(provider)
	action := rc.action
	providerError := pf.Status >= http.StatusBadRequest

	// Usage and cost.
	var usage TokenUsage
	isSSE := strings.Contains(strings.ToLower(pf.ContentType), "text/event-stream")
	if len(in.Body) > 0 && !providerError {
		if isSSE {
			for _, block := range bytes.Split(in.Body, []byte("\n\n")) {
				extractUsageFromSSELine(block, &usage)
			}
		} else {
			parseUsageFromJSON(in.Body, wire, &usage)
		}
		if model == "" {
			model = responseModel(in.Body, isSSE)
		}
	}
	cost, basis, known := estimate, PricingBasisEstimateNoUsage, false
	if usage.Input+usage.Output+usage.CacheRead+usage.CacheWrite > 0 {
		cr := g.costEstimate(provider, model, Usage{Input: usage.Input, CacheRead: usage.CacheRead, CacheWrite: usage.CacheWrite, Output: usage.Output})
		cost, basis, known = cr.Amount, cr.PricingBasis, cr.PricingKnown
	}
	if row != nil && row.isCountTokens {
		cost = 0
	}
	if providerError {
		// The provider refused: nothing was generated and nothing is billed.
		cost, basis, known = 0, PricingBasisEstimateNoUsage, false
		annotations = append(annotations, annotationProviderError)
	}
	if kind == settleLate {
		// The estimate is already booked by the unobserved settlement: this
		// record carries only the excess, so the sum is max(estimate, actual).
		cost -= row.settledCost
		if cost < 0 {
			cost = 0
		}
		basis = PricingBasisLateReconciliation
	}

	// Response PII policy.
	var scan *ResponsePIIScanResult
	body := in.Body
	bodyChanged := false
	observing := action != "" && action != "allow"
	switch {
	case !observing || len(in.Body) == 0:
	case providerError && in.Mode == ResponseModeWholeBody:
		scan = g.scanErrorBody(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), in.Body, action)
		annotations = append(annotations, annotationErrorBodyScanned)
	case in.Mode == ResponseModeWholeBody:
		body, scan = g.applyResponsePolicy(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), in, action, wire)
		bodyChanged = scan != nil && !scan.Blocked && !bytes.Equal(body, in.Body)
	case in.Mode == ResponseModeStream:
		scan = g.observeDelegatedStream(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), in, action)
	}
	if scan != nil && in.Incomplete != "" && scan.Status == evidence.ResponseScanStatusComplete {
		scan.markIncomplete(in.Incomplete)
	}
	blocked := scan != nil && scan.Blocked
	var reasons []string
	if blocked {
		reason := scan.BlockReason
		if reason == "" {
			reason = "output_pii_blocked"
		}
		reasons = []string{reason}
		RecordGatewayError(ctx, reason)
	}
	if in.Mode == ResponseModeHeadersOnly && len(in.Body) == 0 {
		annotations = append(annotations, annotationBodyUninspectable)
	}

	persisted, err := g.recordEvidence(ctx, correlationID, agent, provider, model, start, "", nil, &usage, cost,
		time.Since(start).Milliseconds(), "", !blocked, reasons, false, scan, nil, nil, false, "", 0, 0, false, 0, 0, estimate,
		provenanceOpt, func(p *RecordGatewayEvidenceParams) {
			p.InvocationType = InvocationTypeGatewayResponse
			p.PricingBasis = basis
			p.PricingKnown = known
			p.GatewayAnnotations = append(p.GatewayAnnotations, annotations...)
			if providerError {
				p.Status = evidence.StatusFailed
				p.FailureReason = FailureReasonProviderPermanentOrTransient(pf.Status)
			}
		})
	out := DelegatedSettlement{Block: blocked, Body: body, BodyChanged: bodyChanged, Cost: cost, Tokens: usage, Basis: basis}
	if scan != nil {
		out.PIITypes, out.Redacted = scan.PIITypes, scan.Redacted
		if blocked {
			out.Code, out.Message = scan.BlockReason, "response blocked by Talon response policy"
		}
	}
	if err != nil {
		g.handleEvidenceWriteFailure(ctx, err)
		if preventive(action) {
			// A preventive policy whose verdict cannot be recorded does not
			// release the body: evidence-before-delivery (fail closed).
			out.Block, out.Code, out.Message = true, "evidence_unavailable", "Talon could not commit the signed record (fail-closed)"
		}
		return out
	}
	out.EvidenceID = persisted.ID
	tokens := usage.Input + usage.Output
	switch {
	case kind == settleLate && cost > 0:
		g.trackSessionUsage(ctx, nil, sessionID, sessionSo, agent.TenantID, agent.Name, cost, tokens)
	case kind != settleLate:
		g.trackSessionUsage(ctx, reservation, sessionID, sessionSo, agent.TenantID, agent.Name, cost, tokens)
	}
	return out
}

// applyResponsePolicy runs the proxy path's response scan helpers over a
// held body and returns the body to deliver (possibly a replacement).
func (g *Gateway) applyResponsePolicy(ctx context.Context, in DelegatedResponseBody, action, wire string) ([]byte, *ResponsePIIScanResult) {
	if strings.Contains(strings.ToLower(in.Preflight.ContentType), "text/event-stream") {
		capture := &responseCapture{statusCode: in.Preflight.Status}
		capture.body.Write(in.Body)
		capture.Header().Set("Content-Type", in.Preflight.ContentType)
		sink := &bufferResponseWriter{header: http.Header{}}
		scan := handleStreamingPIIScan(ctx, sink, capture, wire, action, g.classifier)
		if scan != nil && !scan.Blocked {
			return sink.body.Bytes(), scan
		}
		return in.Body, scan
	}
	return scanResponseForPII(ctx, wire, in.Body, action, g.classifier)
}

// scanErrorBody inspects a provider ERROR body under the response policy.
// Error bodies echo inputs and validation detail, so the whole text is
// scanned, not only model content fields. Under a preventive policy any PII
// blocks delivery (a sanitized error is not reconstructible without
// understanding the vendor's envelope); under warn it is observed.
func (g *Gateway) scanErrorBody(ctx context.Context, body []byte, action string) *ResponsePIIScanResult {
	result := newResponseScanResult(action, false)
	text := string(body)
	if strings.TrimSpace(text) == "" {
		result.markIncomplete(evidence.ResponseScanIncompleteNoTextContent)
		return result
	}
	if g.classifier == nil {
		result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		if preventive(action) {
			result.Blocked, result.BlockReason = true, "output_scanner_unavailable"
		}
		return result
	}
	cls, err := g.classifier.Analyze(ctx, text)
	if err != nil {
		result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		result.ScannerFailure = scannerFailureKind(err)
		if preventive(action) {
			result.Blocked, result.BlockReason = true, "output_scanner_unavailable"
		}
		return result
	}
	if cls == nil || !cls.HasPII {
		return result
	}
	result.PIIDetected = true
	result.PIITypes = uniqueSortedEntityTypes(cls.Entities)
	result.Entities = classifier.MergeEntitySpans(text, cls.Entities)
	result.Tier = cls.Tier
	if preventive(action) {
		result.Blocked, result.BlockReason = true, "output_pii_blocked"
		log.Warn().Strs("pii_types", result.PIITypes).Msg("delegated_provider_error_body_blocked")
	} else {
		log.Warn().Strs("pii_types", result.PIITypes).Msg("delegated_provider_error_body_pii_detected")
	}
	return result
}

// observeDelegatedStream is the post-delivery observation of a streamed
// response (warn policy): it never changes bytes, and reports every gap as
// an incomplete observation rather than a clean scan.
func (g *Gateway) observeDelegatedStream(ctx context.Context, in DelegatedResponseBody, action string) *ResponsePIIScanResult {
	result := &ResponsePIIScanResult{
		Action: action, Enforcement: evidence.ResponseScanEnforcementPostDelivery, Streamed: true,
		Status: evidence.ResponseScanStatusComplete, BytesObserved: in.BytesSeen, CaptureLimit: in.CaptureCap,
	}
	if in.Incomplete != "" {
		result.markIncomplete(in.Incomplete)
	} else if in.Truncated {
		result.markIncomplete(evidence.ResponseScanIncompleteCaptureLimitExceeded)
	}
	contentText := ""
	if completed := extractCompletedResponseFromSSE(in.Body); completed != nil {
		contentText = extractResponseContentText(completed)
	}
	if contentText == "" {
		contentText = accumulateSSEContent(in.Body)
	}
	if contentText == "" {
		if result.Status == evidence.ResponseScanStatusComplete {
			result.markIncomplete(evidence.ResponseScanIncompleteNoTextContent)
		}
		return result
	}
	if g.classifier == nil {
		result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		return result
	}
	cls, err := g.classifier.Analyze(ctx, contentText)
	if err != nil {
		result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		result.ScannerFailure = scannerFailureKind(err)
		return result
	}
	if cls != nil && cls.HasPII {
		result.PIIDetected = true
		result.PIITypes = uniqueSortedEntityTypes(cls.Entities)
		result.Entities = classifier.MergeEntitySpans(contentText, cls.Entities)
		result.Tier = cls.Tier
		log.Warn().Strs("pii_types", result.PIITypes).Msg("delegated_response_pii_detected_post_delivery")
	}
	return result
}

// bufferResponseWriter collects what the proxy-path scan helpers would have
// written to a client, so the same helpers can produce the hook's
// replacement body.
type bufferResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (b *bufferResponseWriter) Header() http.Header         { return b.header }
func (b *bufferResponseWriter) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferResponseWriter) WriteHeader(code int)        { b.status = code }

// FailureReasonProviderPermanentOrTransient maps a provider HTTP status to
// the evidence failure vocabulary.
func FailureReasonProviderPermanentOrTransient(status int) string {
	if status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
		return evidence.FailureReasonProviderTransient
	}
	return evidence.FailureReasonProviderPermanent
}

// responseModel reads the model name a provider response names, for a
// settlement that lost its request half.
func responseModel(body []byte, isSSE bool) string {
	payload := body
	if isSSE {
		if completed := extractCompletedResponseFromSSE(body); completed != nil {
			payload = completed
		} else {
			return ""
		}
	}
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return ""
	}
	return m.Model
}

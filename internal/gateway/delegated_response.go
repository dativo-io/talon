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
// row (estimate, session reservation, the response policy in force) in the
// same transaction as the decision record; the response half observes the
// response, then commits — in ONE transaction — the row's status transition
// with its outcome and the signed settlement record.
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
// actual. This is deliberately conservative: when the late actual is BELOW
// the booked estimate the estimate stands and the reconciliation books 0 —
// the ledger and the records say so (late_reconciliation), and nothing
// presents it as exact actual spend. Repeated callbacks for one exchange
// replay the recorded outcome and write nothing. Pending estimates still
// count toward the daily/monthly budget check, and the ledger is bounded by
// refusing NEW delegated requests when it is full — never by discarding an
// obligation.
//
// Session budget. The session store is a separate database and cannot join
// the ledger transaction. Each committed transition records what it owes
// the session (session_state = owed, with the cost/tokens); the session
// update runs right after COMMIT under an application id derived from the
// transition (sessionApplicationID) and is recorded in the session store
// in the same transaction as the balance change; then the ledger row is
// marked settled. A failed update leaves the row owed and the sweeper
// retries; a crash after the session store applied the work but before the
// mark retries into a no-op (the application is already recorded). No
// cross-database transaction is claimed: the two stores converge through
// the owed mark and the idempotent application, and the signed records
// remain the spend of record.
//
// Prevention. A preventive response policy (block/redact) promises the
// sandbox never receives ungoverned bytes. Every path that cannot prove the
// body was fully inspected fails closed: a body beyond the capture bound, a
// compressed or partial body, an unsupported content type, a scanner
// failure, a body mode less restrictive than the trusted plan, and a
// settlement that cannot be committed all BLOCK delivery. Observational
// policies (warn) pass such responses and record the observation as
// incomplete, never as a clean scan.

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
	annotationRawTextScanned    = "response_text_body_scanned"

	// FailureReasonResponseUnobserved marks an unobserved settlement.
	FailureReasonResponseUnobserved = "response_unobserved"

	// Response plan modes (what the runtime is asked to deliver to Talon).
	ResponseModeSkip        = "skip"
	ResponseModeHeadersOnly = "headers_only"
	ResponseModeWholeBody   = "whole_body"
	ResponseModeStream      = "stream"

	// Codes specific to the response hop.
	// CodeResponseScanUnavailable: the body cannot be inspected (compressed,
	// partial, no body) and the policy is preventive.
	CodeResponseScanUnavailable = "output_scan_unavailable"
	// CodeResponseScanIncomplete: the body exceeded the capture bound; only
	// a prefix could be scanned and the policy is preventive.
	CodeResponseScanIncomplete = "output_scan_incomplete"
	// CodeResponseContentUnsupported: a body Talon has no inspector for
	// (binary, unknown media type) under a preventive policy.
	CodeResponseContentUnsupported = "output_content_unsupported"
	// CodeResponseModeMismatch: the body arrived in a less restrictive mode
	// than the trusted plan asked for, under a preventive policy.
	CodeResponseModeMismatch = "response_mode_mismatch"
	// CodeWorkloadIdentityConflict: the response callback's verified
	// principal is not the one the request half was decided for.
	CodeWorkloadIdentityConflict = "workload_identity_conflict"
	// CodeSettlementCapacityExhausted: the ledger holds max_pending
	// obligations; new delegated requests are refused until some settle.
	CodeSettlementCapacityExhausted = "settlement_capacity_exhausted"
	// CodeSettlementUnavailable: the ledger could not be read or written.
	CodeSettlementUnavailable = "settlement_unavailable"
	// CodeSettlementReplayed: a repeated callback for an exchange that was
	// already settled; the recorded verdict was returned, nothing written.
	CodeSettlementReplayed = "settlement_replayed"

	settlementSweepBatch  = 500
	settlementPruneBatch  = 1000
	settlementReplayBasis = "replay"
)

// settlementKind is which ledger transition a settlement performs.
type settlementKind int

const (
	settleFirst      settlementKind = iota // pending → settled
	settleLate                             // unobserved → reconciled
	settleUnmatched                        // no row: observed once under a fresh terminal row
	settleUnobserved                       // sweeper: pending → unobserved
)

func (k settlementKind) String() string {
	switch k {
	case settleFirst:
		return "settled"
	case settleLate:
		return "reconciled"
	case settleUnmatched:
		return "unmatched"
	case settleUnobserved:
		return "unobserved"
	}
	return "unknown"
}

// settlementHooks are fault-injection points for tests (nil in production):
// beforeCommit runs inside the ledger transaction, after the status
// transition and the record insert, immediately before COMMIT. Returning an
// error rolls the transaction back, which is exactly what a crash there
// does.
type settlementHooks struct {
	beforeCommit func(kind settlementKind, key settlementKey) error
	// afterSessionApply runs after the session store applied the owed work
	// and before the ledger is marked settled: the crash window in which a
	// non-idempotent design would charge the session twice on retry.
	afterSessionApply func(key settlementKey) error
}

// sessionApplicationID is the exactly-once key of one ledger transition's
// session work: the exchange plus the status the transition reached. The
// unobserved settlement (estimate) and a later reconciliation (excess) are
// two applications; a retry of either is the same application.
func sessionApplicationID(key settlementKey, status string) string {
	return "delegated:" + key.runtimeID + "|" + key.sandboxRef + "|" + key.requestID + "|" + status
}

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

func (g *Gateway) ledgerRetention() time.Duration {
	if g.config == nil || g.config.OpenShell == nil || g.config.OpenShell.ResponseGovernance == nil {
		return 0
	}
	return g.config.OpenShell.ResponseGovernance.LedgerRetentionDuration()
}

// RunDelegatedSettlementSweeper settles pending exchanges whose response
// never arrived within the settlement window, repairs owed session
// bookkeeping and prunes terminal rows past their retention, until ctx ends.
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
			g.RepairOwedSessionSettlements(ctx)
			g.PruneSettlementLedger(ctx, now)
		}
	}
}

// SweepDelegatedPending settles every expired pending exchange as
// unobserved: the estimate stands as the cost, the session reservation is
// settled with it, and the record says no response was seen. Each row's
// transition and record commit in one transaction, so a response arriving
// concurrently either commits first (and the sweeper's transition finds
// nothing to claim) or reads a complete unobserved settlement to reconcile
// against — never a half-written one.
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
		if g.settleUnobserved(ctx, r) {
			n++
		}
	}
	return n
}

func (g *Gateway) settleUnobserved(ctx context.Context, r *settlementRow) bool {
	ctx = g.delegatedContext(ctx, r.sessionID, r.sessionSource)
	agent := g.settlementAgent(r)
	cost := r.estimate
	if r.isCountTokens {
		cost = 0
	}
	params := g.evidenceParams(ctx, r.correlationID, agent, r.provider, r.model, r.startedAt, "", nil, nil, cost,
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
	owes := g.sessionWork(r.sessionID, r.sessionSource, r.reservation(), cost, settleUnobserved)
	out := settlementOutcome{cost: cost, code: FailureReasonResponseUnobserved, sessionState: sessionStateNone, sessionCost: cost}
	if owes {
		out.sessionState = sessionStateOwed
	}
	ev, committed, err := g.commitTransition(ctx, r.key, settleUnobserved, params, out, nil)
	if err != nil {
		g.handleEvidenceWriteFailure(ctx, err)
		return false
	}
	if !committed {
		return false // a response won the claim meanwhile
	}
	if owes {
		g.applySessionWork(ctx, r.key, settlementUnobserved, r.reservation(), r.sessionID, r.sessionSource, r.tenantID, r.agentName, cost, 0)
	}
	log.Warn().Str("correlation_id", r.correlationID).Str("agent", r.agentName).Str("evidence_id", ev.ID).Msg("delegated_response_unobserved")
	return true
}

// RepairOwedSessionSettlements retries the session update of committed
// settlements whose session work did not complete (see the package comment
// for the at-least-once guarantee this gives).
func (g *Gateway) RepairOwedSessionSettlements(ctx context.Context) int {
	if g.settlements == nil || g.sessionStore == nil {
		return 0
	}
	rows, err := g.settlements.owedSessions(ctx, settlementSweepBatch)
	if err != nil {
		log.Warn().Err(err).Msg("delegated_settlement_session_repair_failed")
		return 0
	}
	n := 0
	for _, r := range rows {
		var res *sessionReservation
		if r.status != settlementReconciled {
			res = r.reservation()
		}
		if g.applySessionWork(ctx, r.key, r.status, res, r.sessionID, r.sessionSource, r.tenantID, r.agentName, r.sessionCost, r.sessionTokens) {
			n++
		}
	}
	return n
}

// PruneSettlementLedger removes terminal rows older than the ledger
// retention (bounded per call). Pending obligations and rows whose session
// work is still owed are never pruned. A response callback for a pruned
// exchange — impossible in the OpenShell protocol, whose response exchange
// lives for one in-flight HTTP response — would be observed once as
// decision_unmatched under a fresh row; the retention is the horizon after
// which that is the documented behavior.
func (g *Gateway) PruneSettlementLedger(ctx context.Context, now time.Time) int64 {
	retention := g.ledgerRetention()
	if g.settlements == nil || retention <= 0 {
		return 0
	}
	n, err := g.settlements.pruneTerminal(ctx, now.Add(-retention), settlementPruneBatch)
	if err != nil {
		log.Warn().Err(err).Msg("delegated_settlement_prune_failed")
		return 0
	}
	if n > 0 {
		log.Info().Int64("pruned", n).Dur("retention", retention).Msg("delegated_settlement_ledger_pruned")
	}
	return n
}

// sessionWork reports whether a transition owes the session store an update.
func (g *Gateway) sessionWork(sessionID, sessionSource string, res *sessionReservation, cost float64, kind settlementKind) bool {
	if g.sessionStore == nil || sessionID == "" || !isAssertedSessionSource(sessionSource) {
		return false
	}
	if kind == settleLate {
		return cost > 0
	}
	return res != nil || cost > 0
}

// applySessionWork performs the session update a committed settlement owes
// — exactly once per ledger transition, keyed by sessionApplicationID — and
// marks the ledger row; false when the update failed (the row stays owed
// for the repair pass). A crash after the session store applied the work
// and before the mark is harmless: the retry finds the application already
// recorded and only marks.
func (g *Gateway) applySessionWork(ctx context.Context, key settlementKey, status string, res *sessionReservation, sessionID, sessionSource, tenantID, agentName string, cost float64, tokens int) bool {
	if err := g.applySessionUsageOnce(ctx, sessionApplicationID(key, status), res, sessionID, sessionSource, tenantID, agentName, cost, tokens); err != nil {
		log.Warn().Err(err).Str("session_id", sessionID).Msg("delegated_settlement_session_owed")
		return false
	}
	if g.settlementHooks != nil && g.settlementHooks.afterSessionApply != nil {
		if err := g.settlementHooks.afterSessionApply(key); err != nil {
			return false
		}
	}
	if err := g.settlements.markSession(ctx, key, sessionStateSettled); err != nil {
		log.Warn().Err(err).Msg("delegated_settlement_session_mark_failed")
		return false
	}
	return true
}

// applySessionUsageOnce resolves the session row (the reservation's, or the
// asserted external session's) and applies the usage under applicationID.
func (g *Gateway) applySessionUsageOnce(ctx context.Context, applicationID string, res *sessionReservation, sessionID, sessionSource, tenantID, agentName string, cost float64, tokens int) error {
	if g.sessionStore == nil || sessionID == "" || !isAssertedSessionSource(sessionSource) {
		return nil
	}
	rowID, estimate := "", 0.0
	if res != nil {
		rowID, estimate = res.rowID, res.estimate
	} else {
		sess, err := g.sessionStore.GetOrCreateExternal(ctx, tenantID, agentName, sessionID, sessionSource)
		if err != nil {
			return err
		}
		rowID = sess.ID
	}
	applied, err := g.sessionStore.ApplyUsageOnce(ctx, applicationID, rowID, estimate, cost, tokens)
	if err != nil {
		return err
	}
	if res != nil {
		res.done = true
	}
	if applied {
		if stage := stageFromContext(ctx); stage != "" {
			if err := g.sessionStore.IncrementStageCount(ctx, rowID, stage); err != nil {
				log.Warn().Err(err).Str("session_id", rowID).Str("stage", stage).Msg("stage count increment failed")
			}
		}
	}
	return nil
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

// commitTransition is the one durable write of a settlement: the row's
// status transition with its outcome and the signed record, in a single
// write transaction. For settleUnmatched the row is inserted terminal. It
// returns (record, true, nil) on commit; (nil, false, nil) when another
// writer moved the row first (the caller replays from the committed row);
// and an error when nothing was written.
func (g *Gateway) commitTransition(ctx context.Context, key settlementKey, kind settlementKind, params RecordGatewayEvidenceParams, out settlementOutcome, unmatched *settlementRow) (*evidence.Evidence, bool, error) {
	tx, err := g.settlements.begin(ctx)
	if err != nil {
		return nil, false, err
	}
	w := g.evidenceStore.NewTxWriter()
	defer func() {
		_ = tx.Rollback()
		w.Discard()
	}()
	ev, err := storeGatewayEvidenceTx(ctx, w, tx, params)
	if err != nil {
		return nil, false, err
	}
	out.evidenceID = ev.ID
	now := time.Now()
	switch kind {
	case settleUnmatched:
		if err := g.settlements.insertTerminal(ctx, tx, unmatched, settlementSettled, out, now); err != nil {
			if errors.Is(err, errSettlementExists) {
				return nil, false, nil
			}
			return nil, false, err
		}
	default:
		from, to := settlementPending, settlementSettled
		switch kind {
		case settleLate:
			from, to = settlementUnobserved, settlementReconciled
		case settleUnobserved:
			from, to = settlementPending, settlementUnobserved
		}
		ok, err := g.settlements.transition(ctx, tx, key, from, to, out, now)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
	}
	if g.settlementHooks != nil && g.settlementHooks.beforeCommit != nil {
		if err := g.settlementHooks.beforeCommit(kind, key); err != nil {
			return nil, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	w.Committed(ctx)
	return ev, true, nil
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
// With a row, the callback's verified principal must be the one the
// request was decided for.
func (g *Gateway) resolveResponseContext(ctx context.Context, pf DelegatedResponsePreflight) (*responseContext, *DelegatedResponsePlan) {
	key := settlementKey{pf.RuntimeID, pf.SandboxRef, pf.RequestID}
	var row *settlementRow
	if g.settlements != nil {
		r, err := g.settlements.get(ctx, g.settlements.db, key)
		if err != nil {
			log.Error().Err(err).Msg("delegated_settlement_read_failed")
			return nil, &DelegatedResponsePlan{Block: true, Code: CodeSettlementUnavailable, Message: CodeSettlementUnavailable + ": Talon could not read the settlement ledger (fail-closed)"}
		}
		row = r
	}
	if row != nil {
		if row.principal.Subject != "" && pf.Principal != nil && (row.principal.Subject != pf.Principal.Subject || row.principal.Issuer != pf.Principal.Issuer) {
			RecordGatewayError(ctx, CodeWorkloadIdentityConflict)
			return nil, &DelegatedResponsePlan{Block: true, Code: CodeWorkloadIdentityConflict, Message: CodeWorkloadIdentityConflict + ": the response callback's verified principal is not the one this request was decided for"}
		}
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

// responseShape classifies the response from its headers.
type responseShape struct {
	isSSE, isJSON, isText bool
	uninspectable         bool
}

func shapeOf(pf DelegatedResponsePreflight) responseShape {
	mt := strings.ToLower(strings.TrimSpace(pf.ContentType))
	if i := strings.Index(mt, ";"); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	return responseShape{
		isSSE:         mt == "text/event-stream",
		isJSON:        mt == "application/json" || strings.HasSuffix(mt, "+json"),
		isText:        strings.HasPrefix(mt, "text/") && mt != "text/event-stream",
		uninspectable: !pf.BodyInspectable || (pf.ContentEncoding != "" && !strings.EqualFold(pf.ContentEncoding, "identity")),
	}
}

// planResponseMode maps the response policy and the response shape to an
// inspection mode (or a block). The contract is conservative: JSON and SSE
// are model bodies Talon can inspect field by field; text/* is inspected as
// raw text (observed under warn, blocked rather than rewritten on PII under
// redact); anything else — binary, unknown media types — has no inspector,
// so a preventive policy blocks it and an observational one records it as
// uninspectable. Provider error bodies are NOT assumed harmless.
func planResponseMode(action string, pf DelegatedResponsePreflight) DelegatedResponsePlan {
	prevent := preventive(action)
	observing := action != "" && action != "allow"
	sh := shapeOf(pf)
	if pf.Status >= http.StatusBadRequest {
		return planErrorResponseMode(observing, prevent, sh.uninspectable, sh.isJSON || sh.isText)
	}
	return planSuccessResponseMode(observing, prevent, pf.StreamPermitted, sh)
}

// planSuccessResponseMode is the plan for a 2xx/3xx response.
func planSuccessResponseMode(observing, prevent, streamPermitted bool, sh responseShape) DelegatedResponsePlan {
	switch {
	case sh.uninspectable && prevent:
		// The policy promises prevention and the body cannot be seen: fail
		// closed, never deliver unscanned bytes.
		return DelegatedResponsePlan{Block: true, Code: CodeResponseScanUnavailable, Message: "response body cannot be inspected and the response PII policy is preventive"}
	case sh.uninspectable:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly, Code: annotationBodyUninspectable}
	case sh.isSSE && !prevent && streamPermitted:
		// Observation: the sandbox streams while Talon watches; the record
		// says post-delivery.
		return DelegatedResponsePlan{Mode: ResponseModeStream}
	case sh.isSSE || sh.isJSON:
		// Preventive (block/redact) or non-streaming: the runtime holds the
		// whole body until Talon answers.
		return DelegatedResponsePlan{Mode: ResponseModeWholeBody}
	case sh.isText && observing:
		return DelegatedResponsePlan{Mode: ResponseModeWholeBody}
	case sh.isText:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly}
	case prevent:
		return DelegatedResponsePlan{Block: true, Code: CodeResponseContentUnsupported, Message: "response media type has no inspector and the response PII policy is preventive"}
	case observing:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly, Code: annotationBodyUninspectable}
	default:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly}
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
	case !textual && prevent:
		return DelegatedResponsePlan{Block: true, Code: CodeResponseContentUnsupported, Message: "provider error body has no inspector and the response PII policy is preventive"}
	case uninspectable || !textual:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly, Code: annotationBodyUninspectable}
	default:
		return DelegatedResponsePlan{Mode: ResponseModeWholeBody}
	}
}

// modeRank orders body modes by how much of the body Talon sees.
func modeRank(mode string) int {
	switch mode {
	case ResponseModeWholeBody:
		return 3
	case ResponseModeStream:
		return 2
	case ResponseModeHeadersOnly:
		return 1
	}
	return 0
}

// ---- settlement ------------------------------------------------------

// DelegatedResponseBody is the observed response: the whole body (whole_body
// mode), the bounded capture (stream mode) or nothing (headers_only).
type DelegatedResponseBody struct {
	Preflight DelegatedResponsePreflight
	Mode      string
	Body      []byte
	// Truncated: the capture hit its bound; usage/scan are partial.
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

// SettleDelegatedResponse observes one response: usage, cost, response PII
// policy, signed record, then session budget. It is idempotent per runtime
// exchange: the transition and the record commit together or not at all, a
// repeated callback replays the committed verdict, and a response that
// arrives after the sweeper booked the estimate reconciles against it.
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
	kind, replay := settlementKindFor(rc.row)
	if replay {
		return g.replaySettlement(ctx, key, in, rc)
	}
	if g.settlements == nil {
		// Response governance without a ledger does not exist (NewGateway
		// refuses it); kept so the type system is honest about nil.
		return g.failClosed(rc.action, CodeSettlementUnavailable)
	}
	obs := g.observe(ctx, in, rc, kind)
	var unmatched *settlementRow
	if kind == settleUnmatched {
		unmatched = g.newUnmatchedRow(key, pf, rc)
		obs.params.CorrelationID = unmatched.correlationID
		obs.params.SessionID = unmatched.sessionID
	}
	ev, committed, err := g.commitTransition(obs.ctx, key, kind, obs.params, obs.outcome, unmatched)
	if err != nil {
		g.handleEvidenceWriteFailure(ctx, err)
		// Nothing was written: the obligation is still pending for the
		// sweeper. A preventive policy cannot release bytes whose verdict
		// has no record.
		if preventive(rc.action) {
			return DelegatedSettlement{Block: true, Code: "evidence_unavailable", Message: "Talon could not commit the signed record (fail-closed)"}
		}
		return DelegatedSettlement{Code: "evidence_unavailable", Body: obs.result.Body}
	}
	if !committed && kind == settleFirst {
		// The sweeper committed the unobserved settlement while this
		// response was being observed: this response is late now, and it
		// reconciles against the booked estimate instead of replaying.
		var late *observation
		late, ev, committed, err = g.reconcileAfterLostClaim(ctx, key, in, rc)
		if err != nil {
			g.handleEvidenceWriteFailure(ctx, err)
			return g.failClosed(rc.action, "evidence_unavailable")
		}
		if late != nil {
			obs, kind = late, settleLate
		}
	}
	if !committed {
		// A concurrent callback or the sweeper committed first.
		return g.replaySettlement(ctx, key, in, rc)
	}
	out := obs.result
	out.EvidenceID = ev.ID
	g.settleOwedSession(obs, kind, key, rc.agent)
	return out
}

// settlementKindFor maps the committed row to the transition a response
// performs; replay is true when the row is already terminal.
func settlementKindFor(row *settlementRow) (kind settlementKind, replay bool) {
	switch {
	case row == nil:
		return settleUnmatched, false
	case row.status == settlementSettled, row.status == settlementReconciled:
		return settleFirst, true
	case row.status == settlementUnobserved:
		return settleLate, false
	}
	return settleFirst, false
}

// settleOwedSession applies the session work a committed transition owes.
func (g *Gateway) settleOwedSession(obs *observation, kind settlementKind, key settlementKey, agent *ResolvedIdentity) {
	if obs.outcome.sessionState != sessionStateOwed {
		return
	}
	res := obs.reservation
	status := settlementSettled
	if kind == settleLate {
		res, status = nil, settlementReconciled
	}
	g.applySessionWork(obs.ctx, key, status, res, obs.sessionID, obs.sessionSource, agent.TenantID, agent.Name, obs.outcome.sessionCost, obs.outcome.sessionTokens)
}

// reconcileAfterLostClaim re-reads the row after a pending→settled claim
// found nothing to claim; when the sweeper moved it to unobserved, the
// response is observed again as a late reconciliation and committed.
// (nil, nil, false, nil) means the row is not unobserved (replay instead).
func (g *Gateway) reconcileAfterLostClaim(ctx context.Context, key settlementKey, in DelegatedResponseBody, rc *responseContext) (*observation, *evidence.Evidence, bool, error) {
	row, err := g.settlements.get(ctx, g.settlements.db, key)
	if err != nil || row == nil || row.status != settlementUnobserved {
		return nil, nil, false, nil
	}
	rc.row = row
	obs := g.observe(ctx, in, rc, settleLate)
	ev, committed, err := g.commitTransition(obs.ctx, key, settleLate, obs.params, obs.outcome, nil)
	if err != nil {
		return nil, nil, false, err
	}
	return obs, ev, committed, nil
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
// unknown (decided before the ledger existed, or pruned past retention): a
// fresh correlation id, the current policy, no reservation.
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

// replaySettlement answers a repeated callback from the committed row: the
// recorded verdict, the recorded evidence id, no new record, no cost. An
// allowed response under a preventive policy is re-inspected so the
// replacement body is reproduced; if that re-inspection cannot be completed
// the replay fails closed rather than release the original bytes.
func (g *Gateway) replaySettlement(ctx context.Context, key settlementKey, in DelegatedResponseBody, rc *responseContext) DelegatedSettlement {
	row, err := g.settlements.get(ctx, g.settlements.db, key)
	if err != nil || row == nil || row.status == settlementPending {
		return g.failClosed(rc.action, CodeSettlementUnavailable)
	}
	out := DelegatedSettlement{Replayed: true, Basis: settlementReplayBasis, Code: CodeSettlementReplayed, EvidenceID: row.settledEvidenceID}
	if row.settledBlock {
		out.Block, out.Code, out.Message = true, row.settledCode, "replay of a blocked response"
		return out
	}
	if preventive(rc.action) && in.Mode == ResponseModeWholeBody && len(in.Body) > 0 && in.Preflight.Status < http.StatusBadRequest {
		g.replayPreventiveBody(ctx, in, rc, &out)
	}
	return out
}

// replayPreventiveBody reproduces the delivered body of a replayed,
// allowed response under a preventive policy, failing closed when the
// re-inspection cannot be completed.
func (g *Gateway) replayPreventiveBody(ctx context.Context, in DelegatedResponseBody, rc *responseContext, out *DelegatedSettlement) {
	if in.Truncated {
		out.Block, out.Code = true, CodeResponseScanIncomplete
		return
	}
	body, scan := g.applyResponsePolicy(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), in, rc.action, g.config.providerAPIFamily(rc.provider))
	incomplete := scan != nil && scan.Status == evidence.ResponseScanStatusIncomplete && scan.IncompleteReason != evidence.ResponseScanIncompleteNoTextContent
	if scan == nil || scan.Blocked || incomplete {
		out.Block, out.Code = true, CodeResponseScanUnavailable
		if scan != nil && scan.BlockReason != "" {
			out.Code = scan.BlockReason
		}
		return
	}
	out.Body, out.BodyChanged = body, !bytes.Equal(body, in.Body)
}

// observation is everything a settlement computed before touching the
// ledger: the record parameters, the ledger outcome and the hook's answer.
type observation struct {
	ctx           context.Context
	params        RecordGatewayEvidenceParams
	outcome       settlementOutcome
	result        DelegatedSettlement
	reservation   *sessionReservation
	sessionID     string
	sessionSource string
}

// observe runs the observation proper — usage, cost, response policy — with
// no database writes. kind decides the cost semantics and the annotations.
//
//nolint:gocyclo // one ordered observation; the branches are its facts
func (g *Gateway) observe(ctx context.Context, in DelegatedResponseBody, rc *responseContext, kind settlementKind) *observation {
	pf := in.Preflight
	row := rc.row
	agent := rc.agent
	provider, model, correlationID := rc.provider, "", ""
	var estimate float64
	sessionID, sessionSo := "", "synthetic"
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
	prevent := preventive(action)
	observing := action != "" && action != "allow"
	providerError := pf.Status >= http.StatusBadRequest
	sh := shapeOf(pf)

	// The trusted plan, recomputed: the body may not arrive in a less
	// restrictive mode than the plan asked for, and a plan that blocks at
	// preflight blocks here too (a restart between the two, say).
	plan := planResponseMode(action, pf)
	forced := ""
	switch {
	case plan.Block:
		forced = plan.Code
	case prevent && in.Mode != "" && modeRank(in.Mode) < modeRank(plan.Mode):
		forced = CodeResponseModeMismatch
	case prevent && in.Truncated && in.Mode == ResponseModeWholeBody:
		// Only a prefix could be scanned: the unscanned remainder may carry
		// what the policy forbids.
		forced = CodeResponseScanIncomplete
	}

	// Usage and cost.
	var usage TokenUsage
	if len(in.Body) > 0 && !providerError && (sh.isJSON || sh.isSSE) {
		if sh.isSSE {
			for _, block := range bytes.Split(in.Body, []byte("\n\n")) {
				extractUsageFromSSELine(block, &usage)
			}
		} else {
			parseUsageFromJSON(in.Body, wire, &usage)
		}
		if model == "" {
			model = responseModel(in.Body, sh.isSSE)
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
		// The provider refused: no generation is billed. (Providers do not
		// bill refused requests on the supported chat APIs; a provider that
		// did would show it in a usage block, which an error body lacks.)
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
	scanCtx := classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse)
	switch {
	case forced != "" || !observing || len(in.Body) == 0:
	case in.Mode == ResponseModeWholeBody && (providerError || (!sh.isJSON && !sh.isSSE)):
		// Error envelopes and plain text: scan the whole text; a preventive
		// policy blocks on PII rather than rewrite an envelope it does not
		// understand.
		scan = g.scanRawTextBody(scanCtx, in.Body, action)
		if providerError {
			annotations = append(annotations, annotationErrorBodyScanned)
		} else {
			annotations = append(annotations, annotationRawTextScanned)
		}
	case in.Mode == ResponseModeWholeBody:
		body, scan = g.applyResponsePolicy(scanCtx, in, action, wire)
		bodyChanged = scan != nil && !scan.Blocked && !bytes.Equal(body, in.Body)
	case in.Mode == ResponseModeStream:
		scan = g.observeDelegatedStream(scanCtx, in, action)
	}
	if scan != nil && in.Mode == ResponseModeWholeBody {
		// For a held body the capture bound or an abnormal end is the ROOT
		// cause of any gap (an unparsable prefix is its consequence), so it
		// overrides whatever the scan of the prefix concluded.
		switch {
		case in.Incomplete != "":
			scan.Status, scan.IncompleteReason = evidence.ResponseScanStatusIncomplete, in.Incomplete
		case in.Truncated:
			scan.Status, scan.IncompleteReason = evidence.ResponseScanStatusIncomplete, evidence.ResponseScanIncompleteCaptureLimitExceeded
		}
	} else if scan != nil && in.Incomplete != "" && scan.Status == evidence.ResponseScanStatusComplete {
		scan.markIncomplete(in.Incomplete)
	}
	blocked := scan != nil && scan.Blocked
	var reasons []string
	switch {
	case forced != "":
		blocked = true
		reasons = []string{forced}
		if scan == nil {
			scan = newResponseScanResult(action, false)
		}
		switch forced {
		case CodeResponseScanIncomplete:
			scan.markIncomplete(evidence.ResponseScanIncompleteCaptureLimitExceeded)
		case CodeResponseScanUnavailable, CodeResponseContentUnsupported, CodeResponseModeMismatch:
			scan.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		}
		scan.Blocked, scan.BlockReason = true, forced
		RecordGatewayError(ctx, forced)
	case blocked:
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

	params := g.evidenceParams(ctx, correlationID, agent, provider, model, start, "", nil, &usage, cost,
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
	result := DelegatedSettlement{Block: blocked, Body: body, BodyChanged: bodyChanged && !blocked, Cost: cost, Tokens: usage, Basis: basis}
	if blocked {
		result.Body, result.BodyChanged = nil, false
		result.Code, result.Message = reasons[0], "response blocked by Talon response policy"
	}
	if scan != nil {
		result.PIITypes, result.Redacted = scan.PIITypes, scan.Redacted && !blocked
	}
	tokens := usage.Input + usage.Output
	out := settlementOutcome{cost: cost, block: blocked, sessionState: sessionStateNone, sessionCost: cost, sessionTokens: tokens}
	if blocked {
		out.code = reasons[0]
	}
	if g.sessionWork(sessionID, sessionSo, reservation, cost, kind) {
		out.sessionState = sessionStateOwed
	}
	return &observation{ctx: ctx, params: params, outcome: out, result: result, reservation: reservation, sessionID: sessionID, sessionSource: sessionSo}
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

// scanRawTextBody inspects a body Talon cannot parse field by field — a
// provider error envelope, a text/* response — as one text. Under a
// preventive policy any PII blocks delivery (the envelope is not
// reconstructible without understanding it, so it is not rewritten); under
// warn it is observed. A scanner failure fails closed under prevention.
func (g *Gateway) scanRawTextBody(ctx context.Context, body []byte, action string) *ResponsePIIScanResult {
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
		log.Warn().Strs("pii_types", result.PIITypes).Msg("delegated_text_body_blocked")
	} else {
		log.Warn().Strs("pii_types", result.PIITypes).Msg("delegated_text_body_pii_detected")
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

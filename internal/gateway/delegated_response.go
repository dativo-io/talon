package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
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
// halves are joined by the runtime's own request id: the request half parks
// a pending settlement (estimate, session reservation, response policy);
// the response half observes actual usage, prices it, settles the session
// budget, applies the agent's response PII policy, and commits a second
// signed record under the SAME correlation id.
//
// Cost truth: while a settlement is pending the decision record carries
// cost 0 with PricingBasisAwaitingSettlement, so spend sums never count an
// estimate and an actual for one request. Exactly one later record carries
// the request's cost: the settlement (actual usage priced from the table, or
// the estimate when the provider sent no usage) or, when no response was
// observed within the settlement window, an unobserved settlement with the
// estimate. Pending estimates still count toward the daily/monthly budget
// check so an in-flight burst cannot slip under a cap.

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

	annotationSettlementPending = "response_settlement_pending"
	annotationResponseObserved  = "response_observed"
	annotationResponseUnseen    = "response_unobserved"
	annotationDecisionUnmatched = "decision_unmatched"
	annotationBodyUninspectable = "response_body_uninspectable"

	// FailureReasonResponseUnobserved marks an unobserved settlement.
	FailureReasonResponseUnobserved = "response_unobserved"

	// Response plan modes (what the runtime is asked to deliver to Talon).
	ResponseModeSkip        = "skip"
	ResponseModeHeadersOnly = "headers_only"
	ResponseModeWholeBody   = "whole_body"
	ResponseModeStream      = "stream"

	// Codes specific to the response hop.
	CodeResponseScanUnavailable = "output_scan_unavailable"

	maxPendingSettlements = 10000
)

type pendingKey struct{ runtimeID, sandboxRef, requestID string }

// delegatedPending is the request half of one delegated exchange.
type delegatedPending struct {
	key                pendingKey
	correlationID      string
	agent              *ResolvedIdentity
	provider, model    string
	wire               string
	estimate           float64
	sessionID          string
	sessionSource      string
	reservation        *sessionReservation
	startedAt          time.Time
	responsePIIAction  string
	decisionEvidenceID string
	isCountTokens      bool
	provenance         func(*RecordGatewayEvidenceParams)
	sessionHeader      string
}

// delegatedPendingSet is the bounded, TTL-swept registry of pending
// settlements. It is in-memory: a Talon restart forgets in-flight requests,
// whose responses then settle as decision_unmatched (usage still observed)
// and whose absence of response goes unrecorded — the documented window.
type delegatedPendingSet struct {
	mu      sync.Mutex
	entries map[pendingKey]*delegatedPending
	ttl     time.Duration
}

func newDelegatedPendingSet(ttl time.Duration) *delegatedPendingSet {
	return &delegatedPendingSet{entries: map[pendingKey]*delegatedPending{}, ttl: ttl}
}

func (p *delegatedPendingSet) add(e *delegatedPending) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) >= maxPendingSettlements {
		// Bounded: evict the oldest rather than grow without limit under a
		// runtime that never delivers responses.
		var oldestKey pendingKey
		var oldest time.Time
		for k, v := range p.entries {
			if oldest.IsZero() || v.startedAt.Before(oldest) {
				oldest, oldestKey = v.startedAt, k
			}
		}
		delete(p.entries, oldestKey)
	}
	p.entries[e.key] = e
}

func (p *delegatedPendingSet) take(k pendingKey) *delegatedPending {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[k]
	if ok {
		delete(p.entries, k)
	}
	return e
}

// expired removes and returns every entry older than the ttl.
func (p *delegatedPendingSet) expired(now time.Time) []*delegatedPending {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []*delegatedPending
	for k, v := range p.entries {
		if now.Sub(v.startedAt) >= p.ttl {
			out = append(out, v)
			delete(p.entries, k)
		}
	}
	return out
}

// estimateFor sums the pending estimates of one use case (budget input).
func (p *delegatedPendingSet) estimateFor(tenantID, agent string) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var sum float64
	for _, v := range p.entries {
		if v.agent != nil && v.agent.TenantID == tenantID && v.agent.Name == agent {
			sum += v.estimate
		}
	}
	return sum
}

func (p *delegatedPendingSet) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// responseGovernanceEnabled reports whether decisions park a settlement.
func (g *Gateway) responseGovernanceEnabled() bool {
	return g.config != nil && g.config.OpenShell.ResponseGovernanceEnabled() && g.delegatedPending != nil
}

// RunDelegatedSettlementSweeper settles pending exchanges whose response
// never arrived within the settlement window, until ctx ends.
func (g *Gateway) RunDelegatedSettlementSweeper(ctx context.Context) {
	if g.delegatedPending == nil {
		return
	}
	interval := g.delegatedPending.ttl / 4
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
// settled with it, and the record says no response was seen.
func (g *Gateway) SweepDelegatedPending(ctx context.Context, now time.Time) int {
	if g.delegatedPending == nil {
		return 0
	}
	n := 0
	for _, pe := range g.delegatedPending.expired(now) {
		g.settleUnobserved(ctx, pe)
		n++
	}
	return n
}

func (g *Gateway) settleUnobserved(ctx context.Context, pe *delegatedPending) {
	ctx = g.delegatedContext(ctx, pe.sessionID, pe.sessionSource)
	cost := pe.estimate
	if pe.isCountTokens {
		cost = 0
	}
	_, err := g.recordEvidence(ctx, pe.correlationID, pe.agent, pe.provider, pe.model, pe.startedAt, "", nil, nil, cost,
		time.Since(pe.startedAt).Milliseconds(), "", true, nil, false, nil, nil, nil, false, "", 0, 0, false, 0, 0, pe.estimate,
		pe.provenance, func(p *RecordGatewayEvidenceParams) {
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
		g.handleEvidenceWriteFailure(ctx, err)
	}
	g.trackSessionUsage(ctx, pe.reservation, pe.sessionID, pe.sessionSource, pe.agent.TenantID, pe.agent.Name, cost, 0)
	log.Warn().Str("correlation_id", pe.correlationID).Str("agent", pe.agent.Name).Msg("delegated_response_unobserved")
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
	// Matched is true when the request half was found.
	Matched bool
	Agent   string
}

// PlanDelegatedResponse chooses the inspection mode from the pending
// request's response policy and the response shape. It never consumes the
// pending entry: a plan that ends without a settlement (runtime abort) is
// settled by the sweeper as unobserved.
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
	pe := g.peekPending(pendingKey{pf.RuntimeID, pf.SandboxRef, pf.RequestID})
	action := ""
	agentName := ""
	if pe != nil {
		action = pe.responsePIIAction
		agentName = pe.agent.Name
	} else {
		// No request half (Talon restarted, or the window elapsed): the
		// response is still attributable through the binding, so usage can
		// be observed, but no response policy is known — observe only.
		if agent, ok := g.registry.Current().ResolveWorkload(pf.Runtime, pf.Principal.Subject); ok {
			agentName = agent.Name
		} else {
			return DelegatedResponsePlan{Mode: ResponseModeSkip, Code: CodeWorkloadIdentityUnbound}
		}
	}
	plan := planResponseMode(action, pf)
	plan.Matched, plan.Agent = pe != nil, agentName
	if plan.Block {
		RecordGatewayError(ctx, plan.Code)
	}
	return plan
}

// planResponseMode maps the response policy and the response shape to an
// inspection mode (or a block).
func planResponseMode(action string, pf DelegatedResponsePreflight) DelegatedResponsePlan {
	preventive := action == "block" || action == "redact"
	ct := strings.ToLower(pf.ContentType)
	isSSE := strings.Contains(ct, "text/event-stream")
	isJSON := strings.Contains(ct, "application/json")
	uninspectable := !pf.BodyInspectable || (pf.ContentEncoding != "" && !strings.EqualFold(pf.ContentEncoding, "identity"))
	switch {
	case pf.Status >= http.StatusBadRequest || (!isSSE && !isJSON):
		// Provider errors and non-model bodies carry nothing to scan or
		// price; settle from the headers.
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly}
	case uninspectable && preventive:
		// The policy promises prevention and the body cannot be seen: fail
		// closed, never deliver unscanned bytes.
		return DelegatedResponsePlan{Block: true, Code: CodeResponseScanUnavailable, Message: "response body cannot be inspected and the response PII policy is preventive"}
	case uninspectable:
		return DelegatedResponsePlan{Mode: ResponseModeHeadersOnly, Code: annotationBodyUninspectable}
	case isSSE && !preventive && pf.StreamPermitted:
		// Observation: the sandbox streams while Talon watches; the record
		// says post-delivery.
		return DelegatedResponsePlan{Mode: ResponseModeStream}
	default:
		// Preventive (block/redact) or non-streaming: the runtime holds the
		// whole body until Talon answers.
		return DelegatedResponsePlan{Mode: ResponseModeWholeBody}
	}
}

func (g *Gateway) peekPending(k pendingKey) *delegatedPending {
	if g.delegatedPending == nil {
		return nil
	}
	g.delegatedPending.mu.Lock()
	defer g.delegatedPending.mu.Unlock()
	return g.delegatedPending.entries[k]
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
}

// SettleDelegatedResponse observes one response: usage, cost, response PII
// policy, session budget, signed record. It consumes the pending entry.
//
//nolint:gocyclo // the settlement is one ordered sequence of observations; splitting it would hide the order
func (g *Gateway) SettleDelegatedResponse(ctx context.Context, in DelegatedResponseBody) DelegatedSettlement {
	pf := in.Preflight
	if pf.Principal == nil {
		return DelegatedSettlement{Block: true, Code: CodeWorkloadIdentityRequired}
	}
	var pe *delegatedPending
	if g.delegatedPending != nil {
		pe = g.delegatedPending.take(pendingKey{pf.RuntimeID, pf.SandboxRef, pf.RequestID})
	}
	start := time.Now()
	var (
		agent                *ResolvedIdentity
		provider, model      string
		correlationID        string
		estimate             float64
		action               string
		sessionID, sessionSo string
		reservation          *sessionReservation
		annotations          = []string{annotationResponseObserved}
		provenanceOpt        func(*RecordGatewayEvidenceParams)
	)
	if pe != nil {
		agent, provider, model, correlationID = pe.agent, pe.provider, pe.model, pe.correlationID
		estimate, action, sessionID, sessionSo, reservation = pe.estimate, pe.responsePIIAction, pe.sessionID, pe.sessionSource, pe.reservation
		start = pe.startedAt
		provenanceOpt = pe.provenance
	} else {
		a, ok := g.registry.Current().ResolveWorkload(pf.Runtime, pf.Principal.Subject)
		if !ok {
			return DelegatedSettlement{Block: true, Code: CodeWorkloadIdentityUnbound}
		}
		agent = a
		provider, _ = g.config.providerForHost(pf.Host)
		correlationID = "gw_" + uuid.New().String()[:12]
		annotations = append(annotations, annotationDecisionUnmatched)
		sessionID, sessionSo = "sess_"+correlationID, "synthetic"
		provenanceOpt = delegatedProvenance(DelegatedRequest{
			Runtime: pf.Runtime, RuntimeID: pf.RuntimeID, Principal: pf.Principal, Reference: pf.SandboxRef, RequestID: pf.RequestID,
		})
	}
	ctx = g.delegatedContext(ctx, sessionID, sessionSo)
	wire := g.config.providerAPIFamily(provider)

	// Usage and cost.
	var usage TokenUsage
	isSSE := strings.Contains(strings.ToLower(pf.ContentType), "text/event-stream")
	if len(in.Body) > 0 {
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
	if pe != nil && pe.isCountTokens {
		cost = 0
	}
	if pf.Status >= http.StatusBadRequest {
		// The provider refused: nothing was generated and nothing is billed.
		cost, basis, known = 0, PricingBasisEstimateNoUsage, false
		annotations = append(annotations, "provider_error")
	}

	// Response PII policy.
	var scan *ResponsePIIScanResult
	body := in.Body
	bodyChanged := false
	switch {
	case in.Mode == ResponseModeWholeBody && len(in.Body) > 0 && action != "" && action != "allow":
		if isSSE {
			capture := &responseCapture{statusCode: pf.Status}
			capture.body.Write(in.Body)
			capture.Header().Set("Content-Type", pf.ContentType)
			sink := &bufferResponseWriter{header: http.Header{}}
			scan = handleStreamingPIIScan(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), sink, capture, wire, action, g.classifier)
			if scan != nil && !scan.Blocked {
				body = sink.body.Bytes()
			}
		} else {
			body, scan = scanResponseForPII(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), wire, in.Body, action, g.classifier)
		}
		bodyChanged = scan != nil && !scan.Blocked && !bytes.Equal(body, in.Body)
	case in.Mode == ResponseModeStream && len(in.Body) > 0 && action != "" && action != "allow":
		scan = g.observeDelegatedStream(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), in, action)
	}
	if scan != nil && in.Incomplete != "" && scan.Status == evidence.ResponseScanStatusComplete {
		scan.markIncomplete(in.Incomplete)
	}
	blocked := scan != nil && scan.Blocked
	allowed := !blocked
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
		time.Since(start).Milliseconds(), "", allowed, reasons, false, scan, nil, nil, false, "", 0, 0, false, 0, 0, estimate,
		provenanceOpt, func(p *RecordGatewayEvidenceParams) {
			p.InvocationType = InvocationTypeGatewayResponse
			p.PricingBasis = basis
			p.PricingKnown = known
			p.GatewayAnnotations = append(p.GatewayAnnotations, annotations...)
			if pf.Status >= http.StatusBadRequest {
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
		if action == "block" || action == "redact" {
			// A preventive policy whose verdict cannot be recorded does not
			// release the body: evidence-before-delivery (fail closed).
			out.Block, out.Code, out.Message = true, "evidence_unavailable", "Talon could not commit the signed record (fail-closed)"
		}
		return out
	}
	out.EvidenceID = persisted.ID
	tokens := usage.Input + usage.Output
	g.trackSessionUsage(ctx, reservation, sessionID, sessionSo, agent.TenantID, agent.Name, cost, tokens)
	return out
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

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

// Pre-dispatch model-governance decision (#432 shared governed-model-call
// seam; #482 delegated enforcement).
//
// Everything Talon decides about a model request BEFORE any provider is
// reached lives in decidePreDispatch: extraction, attachment scan, PII
// classification, provider/sovereignty eligibility, budget/session
// admission, the compiled gateway policy, tool governance and request
// redaction. The HTTP gateway (ServeHTTP) and the delegated path used by an
// external runtime's pre-execution hook (EvaluateDelegated) both call this
// ONE function, so a decision can never differ by transport. Transport
// concerns — writing the error envelope, dispatching, response handling,
// metrics — stay with the caller.

// decisionInput is the transport-neutral request the decision evaluates.
type decisionInput struct {
	Wire          string // provider wire format: openai | anthropic
	Provider      string // configured provider name
	Agent         *ResolvedIdentity
	Eff           EffectivePolicy
	Body          []byte
	SessionID     string
	SessionSource string
	IsCountTokens bool
	CorrelationID string
}

// decisionDeny is one pre-dispatch denial, carrying exactly what the
// caller needs to answer the client and write the signed record.
type decisionDeny struct {
	Status  int
	Message string
	Reasons []string
	// ErrorCode, when set, is recorded through RecordGatewayError.
	ErrorCode string
	// MetricsError marks the denial as an internal error (policy engine,
	// filter failure) rather than a policy outcome, for metrics.
	MetricsError bool
	// MetricPIIAction is the pii_action label for metrics ("" before the
	// PII stage is reached, matching the historical label semantics).
	MetricPIIAction string
	// SkipEvidence: the request was unparseable — historically no record is
	// written and only the request/error metrics fire.
	SkipEvidence bool
	// CostEvent marks a budget hard-stop deny that notifies the org webhook
	// after the signed record committed.
	CostEvent bool

	Model          string
	InputText      string
	Classification *classifier.Classification
	AttSummary     *AttachmentsScanSummary
	ToolResult     *ToolGovernanceResult
	EstimatedCost  float64
	EvidenceOpts   []func(*RecordGatewayEvidenceParams)
}

// decisionAllow is the allowed, possibly transformed request plus every
// fact the caller needs for dispatch, evidence and accounting.
type decisionAllow struct {
	Extracted        ExtractedRequest
	Classification   *classifier.Classification
	Tier             int
	AttSummary       *AttachmentsScanSummary
	ToolContentScan  *evidence.ToolContentScan
	ToolResult       *ToolGovernanceResult
	ForwardBody      []byte
	InputPIIRedacted bool
	PIIAction        string
	EstimatedCost    float64
	EstTokensIn      int
	EstTokensOut     int
	DailyCost        float64
	MonthlyCost      float64
	DailyCap         float64
	MonthlyCap       float64
	// SessionBudgetUnavailable: the session-store read failed and the
	// session check failed open (#198) — visible in evidence annotations.
	SessionBudgetUnavailable bool
	SessView                 *sessionView
	PolicyInput              map[string]interface{}
	RetryS                   retrySettings
}

// decisionOutcome is exactly one of Deny/Allow, plus the request context
// enriched with the facts recordEvidence reads from it (scan duration,
// budget-unavailable annotation) and the session reservation the caller
// MUST release on every non-settling exit.
type decisionOutcome struct {
	Ctx             context.Context
	Deny            *decisionDeny
	Allow           *decisionAllow
	SessReservation *sessionReservation
}

//nolint:gocyclo // the ordered gate sequence is the contract; splitting it would hide the order
func (g *Gateway) decidePreDispatch(ctx context.Context, in decisionInput) decisionOutcome {
	agent, eff, wire := in.Agent, in.Eff, in.Wire
	out := decisionOutcome{Ctx: ctx}
	deny := func(d *decisionDeny) decisionOutcome {
		out.Ctx = ctx
		out.Deny = d
		return out
	}

	// Step 3: Extract
	extracted, err := ExtractForProvider(wire, in.Body)
	if err != nil {
		return deny(&decisionDeny{Status: http.StatusBadRequest, Message: "Invalid request body", ErrorCode: "extract_request", SkipEvidence: true})
	}
	body := in.Body

	// Step 3b: Scan attachments (base64-encoded file blocks)
	attPolicy := eff.Attachment
	var attSummary *AttachmentsScanSummary
	if attPolicy.Action != "allow" {
		attSummary = ScanRequestAttachments(ctx, body, wire,
			g.attExtractor, g.classifier, g.attInjScanner, attPolicy)
	}
	if attSummary != nil && attSummary.BlockRequest {
		// The request is blocked either way; the scan only enriches
		// evidence, so a scanner failure degrades to nil classification.
		attCls, _ := g.classifier.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), extracted.Text)
		return deny(&decisionDeny{
			Status: http.StatusBadRequest, Message: "Request blocked: attachment violates policy",
			Reasons: []string{"attachment policy block"}, Model: extracted.Model, InputText: extracted.Text,
			Classification: attCls, AttSummary: attSummary,
		})
	}
	if attSummary != nil && attSummary.ModifiedBody != nil {
		body = attSummary.ModifiedBody
	}

	// Step 4: Scan PII. A scanner failure is fail-closed: a request Talon
	// cannot classify must not reach the provider (#442).
	scanStart := time.Now()
	classification, scanErr := g.classifier.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), extracted.Text)
	ctx = withScanDuration(ctx, time.Since(scanStart))
	if scanErr != nil {
		return deny(&decisionDeny{
			Status: http.StatusBadGateway, Message: "scanner_unavailable: Request blocked: PII scanner unavailable (fail-closed)",
			ErrorCode: "scanner_unavailable", Reasons: []string{"scanner unavailable"}, Model: extracted.Model, InputText: extracted.Text,
			AttSummary: attSummary, EvidenceOpts: []func(*RecordGatewayEvidenceParams){func(p *RecordGatewayEvidenceParams) {
				if p.Scanner != nil {
					p.Scanner.Failure = scannerFailureKind(scanErr)
				}
			}},
		})
	}

	// Step 5: Classify (tier from PII)
	tier := classification.Tier
	if tier > 2 {
		tier = 2
	}

	// Observation-only tool-content scan (#212): evidence only, never
	// enforcement — tool blocks cannot be redacted yet.
	var toolContentScan *evidence.ToolContentScan
	if g.config.OrganizationPolicy.ScanToolContent != ScanToolContentOff && extracted.ToolText != "" {
		tc, tcErr := g.classifier.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), extracted.ToolText)
		if tcErr != nil {
			toolContentScan = &evidence.ToolContentScan{Scanned: false}
			log.Warn().Str("agent", agent.Name).Err(tcErr).Msg("tool_content_scan_failed")
		} else {
			toolContentScan = &evidence.ToolContentScan{
				Scanned:     true,
				HasPII:      tc.HasPII,
				EntityTypes: uniqueEntityTypes(tc.Entities),
				EntityCount: len(tc.Entities),
			}
		}
	}

	// Agent allowed for this provider? One resolver-backed check covers the
	// agent's own allowlist AND the organization hard constraint (#266). The
	// signed record names WHICH layer denied (#279 review).
	if denySrc := eff.ProviderDenySource(in.Provider); denySrc != "" {
		clientMsg := "provider_not_allowed: Provider not allowed for this agent (agent allowlist)"
		if denySrc == DenySourceOrgProviderAllowlist {
			clientMsg = "provider_not_allowed: Provider not allowed by organization policy"
		}
		return deny(&decisionDeny{
			Status: http.StatusForbidden, Message: clientMsg,
			Reasons: []string{"provider not allowed: " + denySrc}, Model: extracted.Model, InputText: extracted.Text,
			Classification: classification, AttSummary: attSummary,
		})
	}

	// Data-sovereignty eu_strict is a HARD PLATFORM BOUNDARY: forwarding
	// confidential EU data to a non-EU provider is never acceptable.
	if g.sovereigntyExcluded(in.Provider) {
		RecordSovereigntyProviderDenied(ctx, in.Provider)
		return deny(&decisionDeny{
			Status: http.StatusForbidden, Message: "provider blocked by sovereignty.mode=eu_strict (non-EU/LOCAL region)",
			Reasons: []string{sovereigntyDenyReason}, Model: extracted.Model, InputText: extracted.Text,
			Classification: classification, AttSummary: attSummary,
		})
	}

	// Step 6: Evaluate policy
	piiAction := eff.PIIAction
	if piiAction == "block" && classification.HasPII {
		return deny(&decisionDeny{
			Status: http.StatusBadRequest, Message: "pii_policy_violation: Request contains PII that is not allowed",
			Reasons: []string{"PII block"}, MetricPIIAction: piiAction, Model: extracted.Model, InputText: extracted.Text,
			Classification: classification, AttSummary: attSummary,
		})
	}

	// Estimated cost for policy (default token estimate; real tokens are not known yet)
	estTokensIn, estTokensOut := 500, 500
	estimatedCost := g.costEstimate(in.Provider, extracted.Model, Usage{Input: estTokensIn, Output: estTokensOut}).Amount
	if in.IsCountTokens {
		estimatedCost = 0 // free endpoint: a nonzero estimate would leak into budget input and deny evidence (#218)
	}
	dailyCost, monthlyCost, budgetUnavailable := g.agentCostTotals(ctx, agent)
	if budgetUnavailable {
		// Every evidence record for this request carries the governance-gap
		// annotation (read via ctx by recordEvidence).
		ctx = withBudgetUnavailable(ctx)
	}
	// Utilization is measured against the same effective caps enforcement
	// uses (#216, #287); skipped when the spend read failed — a "0%" reading
	// would be a lie.
	dailyCap, monthlyCap := eff.BindingDailyCap(), eff.BindingMonthlyCap()
	if dailyCap > 0 && !budgetUnavailable {
		RecordBudgetUtilization(ctx, agent.TenantID, "daily", (dailyCost/dailyCap)*100)
		g.noteBudgetThresholds(ctx, agent, in.Provider, in.CorrelationID, "daily", dailyCost, dailyCap)
	}
	if monthlyCap > 0 && !budgetUnavailable {
		RecordBudgetUtilization(ctx, agent.TenantID, "monthly", (monthlyCost/monthlyCap)*100)
		g.noteBudgetThresholds(ctx, agent, in.Provider, in.CorrelationID, "monthly", monthlyCost, monthlyCap)
	}
	destinationRegion := g.providerRegion(in.Provider)
	retryS := retrySettings{
		MaxAttempts:    eff.RetryMaxAttempts,
		InitialBackoff: eff.RetryInitialBackoff,
		MaxBackoff:     eff.RetryMaxBackoff,
	}
	// Session-cap admission (#144): reserve this request's estimate BEFORE
	// policy evaluation so concurrent requests serialize against reserved +
	// settled spend. The caller releases it on every non-settling exit.
	sessView, sessReservation := g.reserveSessionBudget(ctx, agent, in.SessionID, in.SessionSource, estimatedCost)
	out.SessReservation = sessReservation
	policyInput, sessionBudgetUnavailable := g.buildPolicyInputForRequest(ctx, agent, in.Provider, extracted.Model, tier, estimatedCost, dailyCost, monthlyCost, sessView)
	{
		allowed, reasons, policyErr := g.policy.EvaluateGateway(ctx, policyInput)
		if policyErr != nil {
			return deny(&decisionDeny{
				Status: http.StatusInternalServerError, Message: "Policy evaluation failed",
				Reasons: []string{"policy evaluation error"}, MetricsError: true, MetricPIIAction: piiAction,
				Model: extracted.Model, InputText: extracted.Text, Classification: classification, AttSummary: attSummary,
			})
		}
		if !allowed {
			if egressReason := firstEgressReason(reasons); egressReason != "" {
				log.Warn().
					Str("correlation_id", in.CorrelationID).
					Str("tenant_id", agent.TenantID).
					Str("agent_id", agent.Name).
					Int("data_tier", tier).
					Str("destination", in.Provider).
					Str("region", destinationRegion).
					Str("reason", egressReason).
					Msg("gateway_egress_denied")
			}
			return deny(&decisionDeny{
				Status: http.StatusForbidden, Message: preferredDenyReason(reasons),
				Reasons: reasons, MetricPIIAction: piiAction, CostEvent: costDenyReasonCode(reasons) != "",
				Model: extracted.Model, InputText: extracted.Text, Classification: classification, AttSummary: attSummary,
				EstimatedCost: estimatedCost,
				EvidenceOpts: []func(*RecordGatewayEvidenceParams){func(p *RecordGatewayEvidenceParams) {
					p.SessionBudget = sessionBudgetDetail(reasons, policyInput, estimatedCost)
					// Budget hard stop (#144): the deny record explicitly
					// carries the window/limit/spend it was decided on.
					p.CostBudget = costBudgetDetail(reasons, dailyCost, monthlyCost, dailyCap, monthlyCap, estimatedCost)
					if sessionBudgetUnavailable {
						p.GatewayAnnotations = append(p.GatewayAnnotations, "session_budget_unavailable")
					}
				}},
			})
		}
	}

	// Step 6b: Tool governance — filter or block forbidden tools before the LLM sees them.
	var toolResult *ToolGovernanceResult
	forwardBody := body
	if len(extracted.ToolNames) > 0 && hasToolGovernance(&eff) {
		tr := evaluateToolPolicyFor(extracted.ToolNames, &eff)
		toolResult = &tr
		if len(tr.Removed) > 0 {
			switch eff.ToolPolicyAction {
			case "block":
				log.Warn().
					Str("agent", agent.Name).
					Strs("forbidden", tr.Removed).
					Msg("gateway_tool_blocked")
				return deny(&decisionDeny{
					Status:  http.StatusForbidden,
					Message: fmt.Sprintf("tool_policy_violation: Request contains forbidden tools: %v", tr.Removed),
					Reasons: []string{"tool governance block"}, MetricPIIAction: piiAction,
					Model: extracted.Model, InputText: extracted.Text, Classification: classification, AttSummary: attSummary,
					ToolResult: toolResult, EstimatedCost: estimatedCost,
				})
			default:
				filtered, filterErr := FilterRequestBodyTools(wire, forwardBody, tr.Kept)
				if filterErr != nil {
					log.Error().Err(filterErr).
						Str("agent", agent.Name).
						Strs("forbidden", tr.Removed).
						Msg("gateway_tool_filter_failed")
					return deny(&decisionDeny{
						Status: http.StatusInternalServerError, Message: "Failed to filter forbidden tools from request",
						Reasons: []string{"tool filter error"}, MetricsError: true, MetricPIIAction: piiAction,
						Model: extracted.Model, InputText: extracted.Text, Classification: classification, AttSummary: attSummary,
						ToolResult: toolResult, EstimatedCost: estimatedCost,
					})
				}
				forwardBody = filtered
				log.Info().
					Str("agent", agent.Name).
					Strs("removed", tr.Removed).
					Strs("kept", tr.Kept).
					Msg("gateway_tools_filtered")
			}
		}
	}

	inputPIIRedacted := false
	// Step 7: Redact (if policy says redact and PII found). Redaction failure
	// is fail-closed: the request is known to contain PII, so forwarding it
	// unredacted is never acceptable.
	if piiAction == "redact" && classification.HasPII {
		redacted, redactErr := RedactRequestBody(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), wire, forwardBody, g.classifier)
		if redactErr != nil {
			return deny(&decisionDeny{
				Status: http.StatusBadGateway, Message: "scanner_unavailable: Request blocked: PII redaction failed (fail-closed)",
				ErrorCode: "scanner_unavailable", Reasons: []string{"request redaction failed"}, MetricPIIAction: piiAction,
				Model: extracted.Model, InputText: extracted.Text, Classification: classification, AttSummary: attSummary,
				ToolResult: toolResult, EstimatedCost: estimatedCost,
				EvidenceOpts: []func(*RecordGatewayEvidenceParams){func(p *RecordGatewayEvidenceParams) {
					if p.Scanner != nil {
						p.Scanner.Failure = scannerFailureKind(redactErr)
					}
				}},
			})
		}
		forwardBody = redacted
		inputPIIRedacted = true
	}
	// Fail closed if redacted request text still contains recognized PII.
	if inputPIIRedacted && g.classifier != nil {
		redactedExtracted, extractErr := ExtractForProvider(wire, forwardBody)
		if extractErr != nil {
			return deny(&decisionDeny{
				Status: http.StatusBadRequest, Message: "Request blocked: unable to verify redacted payload",
				Reasons: []string{"request redaction verification failed"}, MetricsError: true, MetricPIIAction: piiAction,
				Model: extracted.Model, InputText: extracted.Text, Classification: classification, AttSummary: attSummary,
				ToolResult: toolResult, EstimatedCost: estimatedCost,
			})
		}
		if verifyErr := g.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), redactedExtracted.Text); verifyErr != nil {
			// Residual PII (policy outcome) and an unverifiable scan (engine
			// failure) are different facts: status, message, evidence reason,
			// and scanner failure kind must each say which one happened.
			residual := errors.Is(verifyErr, classifier.ErrPIIDetected)
			types := strings.Join(classifier.ResidualTypes(verifyErr), ", ")
			// The machine-code prefix travels into the provider-native
			// error.type (#209): a residual block is a policy outcome (never
			// retriable as-is), a failed verification is infrastructure.
			msg := "pii_policy_violation: Request blocked: recognized PII remains after redaction"
			status := http.StatusBadRequest
			reason := "request residual pii after redaction"
			errorCode := ""
			if !residual {
				msg = "scanner_unavailable: Request blocked: redaction could not be verified (fail-closed)"
				status = http.StatusBadGateway
				reason = "request redaction verification failed: scanner unavailable"
				errorCode = "scanner_unavailable"
				log.Warn().Err(verifyErr).Str("agent", agent.Name).Msg("request_redaction_verification_scanner_unavailable")
			}
			if types != "" {
				msg += " (types: " + types + ")"
			}
			return deny(&decisionDeny{
				Status: status, Message: msg, ErrorCode: errorCode,
				Reasons: []string{reason}, MetricPIIAction: piiAction,
				Model: extracted.Model, InputText: extracted.Text, Classification: classification, AttSummary: attSummary,
				ToolResult: toolResult, EstimatedCost: estimatedCost,
				EvidenceOpts: []func(*RecordGatewayEvidenceParams){func(p *RecordGatewayEvidenceParams) {
					if !residual && p.Scanner != nil {
						p.Scanner.Failure = scannerFailureKind(verifyErr)
					}
				}},
			})
		}
	}

	out.Ctx = ctx
	out.Allow = &decisionAllow{
		Extracted:                extracted,
		Classification:           classification,
		Tier:                     tier,
		AttSummary:               attSummary,
		ToolContentScan:          toolContentScan,
		ToolResult:               toolResult,
		ForwardBody:              forwardBody,
		InputPIIRedacted:         inputPIIRedacted,
		PIIAction:                piiAction,
		EstimatedCost:            estimatedCost,
		EstTokensIn:              estTokensIn,
		EstTokensOut:             estTokensOut,
		DailyCost:                dailyCost,
		MonthlyCost:              monthlyCost,
		DailyCap:                 dailyCap,
		MonthlyCap:               monthlyCap,
		SessionBudgetUnavailable: sessionBudgetUnavailable,
		SessView:                 sessView,
		PolicyInput:              policyInput,
		RetryS:                   retryS,
	}
	return out
}

// sovereigntyExcluded reports whether eu_strict excludes the provider's
// region: a hard platform boundary evaluated before policy.
func (g *Gateway) sovereigntyExcluded(provider string) bool {
	if g.config.EffectiveSovereigntyMode != config.DataSovereigntyEUStrict {
		return false
	}
	region := strings.ToUpper(strings.TrimSpace(g.providerRegion(provider)))
	return region != "EU" && region != "LOCAL"
}

// writeDeny answers a pre-dispatch denial on the HTTP gateway: error
// envelope, signed record, cost webhook and metrics — ONE implementation
// for every deny branch.
func (g *Gateway) writeDeny(ctx context.Context, w http.ResponseWriter, wire string, route RouteResult, agent *ResolvedIdentity, start time.Time, correlationID string, d *decisionDeny) {
	durationMS := time.Since(start).Milliseconds()
	if d.ErrorCode != "" {
		RecordGatewayError(ctx, d.ErrorCode)
	}
	if d.SkipEvidence {
		RecordGatewayRequest(ctx, agent.Name, "", route.Provider, "error")
		WriteProviderError(w, wire, d.Status, d.Message)
		return
	}
	WriteProviderError(w, wire, d.Status, d.Message)
	persisted, err := g.recordDenyEvidence(ctx, correlationID, agent, route.Provider, start, durationMS, d)
	if err != nil {
		g.handleEvidenceWriteFailure(ctx, err)
		return
	}
	if d.CostEvent {
		// Cost hard stops notify the org webhook — strictly after the signed
		// deny record committed (#144). Non-cost denials are not cost events.
		if code := costDenyReasonCode(d.Reasons); code != "" {
			costEv := CostEvent{
				Event:         "budget_denied",
				TenantID:      agent.TenantID,
				Agent:         agent.Name,
				EstimatedCost: d.EstimatedCost,
				Currency:      g.pricingCurrency,
				ReasonCode:    code,
				EvidenceID:    persisted.ID,
				Timestamp:     persisted.Timestamp.UTC(),
			}
			if cb := persisted.CostBudget; cb != nil {
				costEv.Period, costEv.Limit, costEv.Spent = cb.Period, cb.Limit, cb.Spent
			}
			g.postCostEvent(costEv)
		}
	}
	g.emitMetrics(ctx, agent, route.Provider, d.Model, d.Classification, d.ToolResult, nil, 0, durationMS, d.MetricsError, true, d.MetricPIIAction, false, 0, 0, 0, persisted)
}

// recordDenyEvidence writes the signed record for one pre-dispatch denial.
// extra options (e.g. enforcement provenance on the delegated path) are
// applied after the denial's own options.
func (g *Gateway) recordDenyEvidence(ctx context.Context, correlationID string, agent *ResolvedIdentity, provider string, start time.Time, durationMS int64, d *decisionDeny, extra ...func(*RecordGatewayEvidenceParams)) (*evidence.Evidence, error) {
	opts := append(append([]func(*RecordGatewayEvidenceParams){}, d.EvidenceOpts...), extra...)
	return g.recordEvidence(ctx, correlationID, agent, provider, d.Model, start, d.InputText, d.Classification, nil, 0, durationMS, "", false, d.Reasons, false, nil, d.AttSummary, d.ToolResult, false, "", 0, 0, false, 0, 0, d.EstimatedCost, opts...)
}

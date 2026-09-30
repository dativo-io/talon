package gateway

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/workload"
)

// Delegated model governance (#482, #424 DELEGATE).
//
// An external execution runtime that owns the network boundary around an
// agent (reference: NVIDIA OpenShell's supervisor middleware) can ask Talon
// to decide a model request BEFORE the runtime injects the provider
// credential and forwards it. Talon evaluates exactly the pre-dispatch
// decision the HTTP gateway evaluates and returns allow/deny plus the
// transformed body. Talon does not dispatch, does not retry, does not
// fall back and never sees the provider credential on this path: the
// runtime owns the single provider attempt and its lifecycle.
//
// The transport-specific adapter (internal/openshell) owns wire parsing,
// caller authentication and result encoding; this file owns the
// runtime-neutral decision and its signed record.

// UpstreamAuthModeExternalRuntime marks evidence written on the delegated
// path: the provider credential was owned and injected by the runtime.
const UpstreamAuthModeExternalRuntime = "external_runtime"

// Stable delegated-path machine codes (in addition to the ordinary
// gateway codes such as pii_policy_violation, model_not_allowed).
const (
	CodeWorkloadIdentityRequired = "workload_identity_required"
	CodeWorkloadIdentityUnbound  = "workload_identity_unbound"
	CodeDestinationNotGoverned   = "destination_not_governed"
	CodeAgentDisabled            = "agent_disabled"
)

// DelegatedRequest is one model request a runtime hook asks Talon to decide.
type DelegatedRequest struct {
	// Runtime is the configured runtime type (e.g. "openshell"); RuntimeID
	// its stable configured identity (e.g. the token issuer).
	Runtime   string
	RuntimeID string
	// Principal is the VERIFIED workload identity, or nil when none was
	// presented or verification failed (IdentityFailure then carries the
	// stable failure code).
	Principal       *workload.Principal
	IdentityFailure string
	// Target facts from the runtime: the destination the agent asked for.
	Host   string
	Path   string
	Method string
	Body   []byte
	// SessionID is client-asserted session correlation forwarded by the
	// runtime (attribution only; empty = synthetic session).
	SessionID string
	// PolicyRef and Reference are SAFE runtime references recorded in
	// evidence (e.g. the runtime's policy/middleware name and sandbox id);
	// RequestID is the runtime's per-request correlation id.
	PolicyRef string
	Reference string
	RequestID string
}

// DelegatedDecision is Talon's verdict for the runtime to enforce.
type DelegatedDecision struct {
	Allowed bool
	// Code is the stable machine reason (e.g. pii_policy_violation); Status
	// and Message mirror what the HTTP gateway would have answered.
	Code    string
	Status  int
	Message string
	// Body is the request body the runtime must forward when allowed;
	// BodyChanged reports whether Talon transformed it (redaction, tool
	// filtering). Redacted is true when PII redaction was applied.
	Body        []byte
	BodyChanged bool
	Redacted    bool
	// PIITypes lists detected entity types (never values) for findings.
	PIITypes []string
	// EvidenceID is the committed signed record, "" when the denial could
	// not be attributed to a use case (identity failed before binding).
	EvidenceID string
	Agent      string
	Provider   string
	Model      string
}

// EvaluateDelegated decides one delegated request and commits its signed
// record. It never returns an error for a policy outcome: every path yields
// a decision, and a decision that could not be recorded is a DENY (a
// runtime must never forward on an unrecorded Talon allow).
func (g *Gateway) EvaluateDelegated(ctx context.Context, req DelegatedRequest) DelegatedDecision {
	start := time.Now()
	correlationID := "gw_" + uuid.New().String()[:12]
	registry := g.registry.Current()

	// Identity first: without a verified principal bound to a use case
	// there is no policy to evaluate and no tenant to attribute to. Like an
	// unknown agent key on the HTTP path, this denies with a metric and a
	// structured log but no tenant-scoped record.
	if req.Principal == nil {
		code := req.IdentityFailure
		if code == "" {
			code = workload.FailureMissing
		}
		RecordGatewayError(ctx, code)
		log.Warn().Str("runtime", req.Runtime).Str("host", req.Host).Str("failure", code).Msg("delegated_identity_rejected")
		return DelegatedDecision{
			Code: CodeWorkloadIdentityRequired, Status: http.StatusUnauthorized,
			Message: CodeWorkloadIdentityRequired + ": verified workload identity required (" + code + ")",
		}
	}
	agent, ok := registry.ResolveWorkload(req.Runtime, req.Principal.Subject)
	if !ok {
		RecordGatewayError(ctx, CodeWorkloadIdentityUnbound)
		log.Warn().Str("runtime", req.Runtime).Str("subject", req.Principal.Subject).Msg("delegated_identity_unbound")
		return DelegatedDecision{
			Code: CodeWorkloadIdentityUnbound, Status: http.StatusForbidden,
			Message: CodeWorkloadIdentityUnbound + ": verified workload principal is not bound to any Talon AI use case",
		}
	}

	sessionID := strings.TrimSpace(req.SessionID)
	sessionSource := "client_asserted"
	if sessionID == "" {
		sessionID = "sess_" + correlationID
		sessionSource = "synthetic"
	} else if _, err := evidence.ValidateOrchValue("session_id", sessionID); err != nil {
		sessionID = "sess_" + correlationID
		sessionSource = "synthetic"
	}
	ctx = context.WithValue(ctx, gatewaySessionIDKey, sessionID)
	ctx = context.WithValue(ctx, gatewaySessionSourceKey, sessionSource)
	ctx = context.WithValue(ctx, gatewayUpstreamAuthMode, UpstreamAuthModeExternalRuntime)

	identityFact := &evidence.WorkloadIdentity{
		Status:      evidence.WorkloadIdentityVerified,
		Runtime:     req.Runtime,
		AuthMethod:  req.Principal.AuthMethod,
		Issuer:      req.Principal.Issuer,
		Subject:     req.Principal.Subject,
		PrincipalID: req.Principal.PrincipalID,
		Audience:    req.Principal.Audience,
		Binding:     evidence.WorkloadIdentityBindingAgentConfig,
		VerifiedAt:  req.Principal.VerifiedAt.UTC().Format(time.RFC3339),
	}
	enforcement := &evidence.Enforcement{
		Mechanism:         evidence.MechanismDelegate,
		Boundary:          evidence.BoundaryExternalRuntime,
		DecisionAuthority: evidence.BoundaryTalon,
		Provenance:        evidence.ProvenanceExternalRuntimeEnforced,
		Observed:          false,
		Runtime: &evidence.ExternalRuntimeRef{
			Type: req.Runtime, ID: req.RuntimeID, PolicyRef: req.PolicyRef,
			Reference: req.Reference, RequestID: req.RequestID,
		},
	}
	provenanceOpt := func(p *RecordGatewayEvidenceParams) {
		p.WorkloadIdentity = identityFact
		p.Enforcement = enforcement
		p.GatewayAnnotations = append(p.GatewayAnnotations, "delegated_dispatch")
	}

	// Destination → configured provider. A host Talon has no provider for
	// is not governed here; the runtime bound Talon to it by mistake, so
	// fail closed rather than let ungoverned traffic through as "allowed".
	providerName, ok := g.config.providerForHost(req.Host)
	if !ok {
		d := &decisionDeny{
			Status: http.StatusForbidden, Message: CodeDestinationNotGoverned + ": no Talon provider is configured for destination " + req.Host,
			Reasons: []string{"delegated destination not governed: " + req.Host},
		}
		return g.delegatedDeny(ctx, correlationID, agent, req.Host, start, d, provenanceOpt)
	}
	wire := g.config.providerAPIFamily(providerName)

	// Operational kill switch (#268): attributed denial, zero dispatch.
	if !agent.Enabled {
		d := &decisionDeny{
			Status: http.StatusForbidden, Message: CodeAgentDisabled + ": agent \"" + agent.Name + "\" is disabled by its Talon agent config (enabled: false)",
			Reasons: []string{"agent disabled (enabled: false in agent config)"},
		}
		return g.delegatedDeny(ctx, correlationID, agent, providerName, start, d, provenanceOpt)
	}
	if req.Method != "" && !strings.EqualFold(req.Method, http.MethodPost) {
		d := &decisionDeny{Status: http.StatusMethodNotAllowed, Message: "method_not_allowed: Method not allowed", Reasons: []string{"delegated method not allowed"}}
		return g.delegatedDeny(ctx, correlationID, agent, providerName, start, d, provenanceOpt)
	}

	prov, _ := g.config.Provider(providerName)
	eff := ResolveEffectivePolicy(g.config.OrganizationPolicy, prov, agent.Override)
	isCountTokens := wire == "anthropic" && strings.HasSuffix(req.Path, "/count_tokens")

	outcome := g.decidePreDispatch(ctx, decisionInput{
		Wire: wire, Provider: providerName, Agent: agent, Eff: eff, Body: req.Body,
		SessionID: sessionID, SessionSource: sessionSource, IsCountTokens: isCountTokens, CorrelationID: correlationID,
	})
	ctx = outcome.Ctx
	if outcome.Deny != nil {
		if outcome.SessReservation != nil {
			g.releaseSessionReservation(outcome.SessReservation)
		}
		return g.delegatedDeny(ctx, correlationID, agent, providerName, start, outcome.Deny, provenanceOpt)
	}
	dec := outcome.Allow
	durationMS := time.Since(start).Milliseconds()

	// The provider is reached by the runtime, not by Talon: token usage is
	// unobserved on this path, so the record carries the pre-request
	// estimate exactly as a usage-less gateway record does.
	persisted, err := g.recordEvidence(ctx, correlationID, agent, providerName, dec.Extracted.Model, start, dec.Extracted.Text,
		dec.Classification, nil, dec.EstimatedCost, durationMS, "", true, nil, dec.InputPIIRedacted, nil, dec.AttSummary, dec.ToolResult,
		false, "", 0, 0, false, 0, 0, dec.EstimatedCost, provenanceOpt, func(p *RecordGatewayEvidenceParams) {
			p.ToolContent = dec.ToolContentScan
			if dec.SessionBudgetUnavailable {
				p.GatewayAnnotations = append(p.GatewayAnnotations, "session_budget_unavailable")
			}
			if isCountTokens {
				p.InvocationType = "gateway_count_tokens"
			}
		})
	if err != nil {
		// An allow that cannot be recorded is not an allow: the runtime must
		// not forward traffic Talon has no signed record of.
		if outcome.SessReservation != nil {
			g.releaseSessionReservation(outcome.SessReservation)
		}
		g.handleEvidenceWriteFailure(ctx, err)
		return DelegatedDecision{
			Code: "evidence_unavailable", Status: http.StatusServiceUnavailable,
			Message: "evidence_unavailable: Talon could not commit the signed record (fail-closed)", Agent: agent.Name, Provider: providerName,
		}
	}
	if !isCountTokens {
		g.trackSessionUsage(ctx, outcome.SessReservation, sessionID, sessionSource, agent.TenantID, agent.Name, dec.EstimatedCost, 0)
	} else if outcome.SessReservation != nil {
		g.releaseSessionReservation(outcome.SessReservation)
	}
	g.emitMetrics(ctx, agent, providerName, dec.Extracted.Model, dec.Classification, dec.ToolResult, nil, dec.EstimatedCost, durationMS, false, false, dec.PIIAction, false, 0, 0, 0, persisted)

	bodyChanged := string(dec.ForwardBody) != string(req.Body)
	return DelegatedDecision{
		Allowed: true, Status: http.StatusOK, Body: dec.ForwardBody, BodyChanged: bodyChanged, Redacted: dec.InputPIIRedacted,
		PIITypes: piiTypesOf(dec.Classification), EvidenceID: persisted.ID, Agent: agent.Name, Provider: providerName, Model: dec.Extracted.Model,
	}
}

func (g *Gateway) delegatedDeny(ctx context.Context, correlationID string, agent *ResolvedIdentity, provider string, start time.Time, d *decisionDeny, provenanceOpt func(*RecordGatewayEvidenceParams)) DelegatedDecision {
	durationMS := time.Since(start).Milliseconds()
	if d.ErrorCode != "" {
		RecordGatewayError(ctx, d.ErrorCode)
	}
	_, code := normalizeGatewayError(d.Message)
	dec := DelegatedDecision{Allowed: false, Code: code, Status: d.Status, Message: d.Message, Agent: agent.Name, Provider: provider, Model: d.Model, PIITypes: piiTypesOf(d.Classification)}
	if d.SkipEvidence {
		RecordGatewayRequest(ctx, agent.Name, "", provider, "error")
		return dec
	}
	persisted, err := g.recordDenyEvidence(ctx, correlationID, agent, provider, start, durationMS, d, provenanceOpt)
	if err != nil {
		g.handleEvidenceWriteFailure(ctx, err)
		return dec
	}
	dec.EvidenceID = persisted.ID
	if d.CostEvent {
		if c := costDenyReasonCode(d.Reasons); c != "" {
			costEv := CostEvent{
				Event: "budget_denied", TenantID: agent.TenantID, Agent: agent.Name, EstimatedCost: d.EstimatedCost,
				Currency: g.pricingCurrency, ReasonCode: c, EvidenceID: persisted.ID, Timestamp: persisted.Timestamp.UTC(),
			}
			if cb := persisted.CostBudget; cb != nil {
				costEv.Period, costEv.Limit, costEv.Spent = cb.Period, cb.Limit, cb.Spent
			}
			g.postCostEvent(costEv)
		}
	}
	g.emitMetrics(ctx, agent, provider, d.Model, d.Classification, d.ToolResult, nil, 0, durationMS, d.MetricsError, true, d.MetricPIIAction, false, 0, 0, 0, persisted)
	return dec
}

// providerForHost maps a destination host to the ONE enabled configured
// provider whose base_url has that host. Case-insensitive exact host match;
// a host shared by two providers is ambiguous and therefore not governed.
func (c *GatewayConfig) providerForHost(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", false
	}
	var found string
	for name, p := range c.Providers {
		if !p.Enabled || p.BaseURL == "" {
			continue
		}
		u, err := url.Parse(p.BaseURL)
		if err != nil || !strings.EqualFold(u.Hostname(), host) {
			continue
		}
		if found != "" {
			return "", false
		}
		found = name
	}
	return found, found != ""
}

func piiTypesOf(c *classifier.Classification) []string {
	if c == nil {
		return nil
	}
	return uniqueEntityTypes(c.Entities)
}

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
)

// RecordGatewayEvidenceParams holds all inputs for a gateway evidence record.
type RecordGatewayEvidenceParams struct {
	CorrelationID     string
	SessionID         string
	TenantID          string
	AgentName         string
	Team              string
	Provider          string
	Model             string
	PolicyAllowed     bool
	PolicyReasons     []string
	PolicyVersion     string
	PolicyDigests     *evidence.PolicyDigests
	InputTier         int
	OutputTier        int
	PIIDetected       []string
	PIIRedacted       bool
	InputPIIRedacted  bool
	OutputPIIDetected bool
	OutputPIITypes    []string
	Cost              float64
	EstimatedCost     float64
	Currency          string // ISO-4217 unit of Cost/EstimatedCost, from the pricing table (#216)
	InputTokens       int
	OutputTokens      int
	CacheReadTokens   int
	CacheWriteTokens  int
	PricingBasis      string // how Cost was derived (#196)
	PricingKnown      bool
	DurationMS        int64
	TTFTMS            int64   // time to first token (streaming); 0 when not streaming
	TPOTMS            float64 // time per output token (streaming); 0 when not applicable
	Error             string
	SecretsAccessed   []string // secret names only; never real keys
	AttachmentScan    *evidence.AttachmentScan
	ToolsRequested    []string
	ToolsFiltered     []string
	ToolsForwarded    []string
	// Semantic cache (set when response was served from cache)
	CacheHit     bool
	CacheEntryID string
	// CacheSourceCorrelationID names the evidence record of the request that
	// originally produced the cached response, so a cache hit's audit trail
	// points at the true source generation (#266 review round 5).
	CacheSourceCorrelationID string
	CacheSimilarity          float64
	CostSaved                float64
	UpstreamAuthMode         string
	UpstreamKeySource        string
	UpstreamKeyFingerprint   string
	GatewayAnnotations       []string
	AgentReasoning           string
	RetryAttempt             string // X-Talon-Retry-Attempt header value; empty when not a retry
	Stage                    string // "generation", "judge", or "commit"
	CandidateIndex           int
	ExplanationFacts         []explanation.Fact
	// DataFlow links classified data to its destination (digests only).
	DataFlow *evidence.DataFlow
	// EgressDecision records the egress allow/deny outcome (tier x destination).
	// Nil when egress is not configured or was not evaluated for this request.
	EgressDecision *evidence.EgressDecision
	// InvocationType overrides the default "gateway" (e.g.
	// "gateway_failover_attempt" for failed provider attempt records).
	InvocationType string
	// Status/FailureReason classify failed outcomes (evidence-by-default).
	Status        string
	FailureReason string
	// Failover carries fallback-chain context (failed attempt, fallback
	// decision, or fail-closed outcome).
	Failover *evidence.FailoverContext
	// Scanner identifies the PII scan engine used for this request's
	// classification (and its failure kind on scanner-driven blocks).
	Scanner *evidence.ScannerInfo
	// ToolContent carries the evidence-only PII observation over tool-related
	// request content (#212). Never used for enforcement in v1.
	ToolContent *evidence.ToolContentScan
	// ResponseScan states how the response PII control was applied and
	// whether the scan covered the whole response (#476). Nil when no
	// response scan ran.
	ResponseScan *evidence.ResponseScan
	// Orchestration carries client-asserted coding-orchestration identity
	// (#194). Evidence-only; never a policy input in v1.
	Orchestration *evidence.OrchestrationContext
	// SessionBudget carries the {limit, spent, estimate} a session-budget
	// deny was decided on (#198). Nil unless a session_budget_exceeded
	// deny fired.
	SessionBudget *evidence.SessionBudget
	// CostBudget carries the agent/org budget-window context of a
	// cost-control event (#144): threshold crossings and budget denies.
	CostBudget *evidence.CostBudget
	// WorkloadIdentity records verified workload-identity federation at
	// ingress (#457). Nil on the ordinary agent-key path.
	WorkloadIdentity *evidence.WorkloadIdentity
	// Enforcement records who owned the prevention boundary (#146). Nil =
	// Talon intercepted on its own gateway boundary (the legacy default).
	Enforcement *evidence.Enforcement
}

// RecordGatewayEvidence creates and stores a signed evidence record for a gateway request.
// Never logs or stores real provider API keys.
func RecordGatewayEvidence(ctx context.Context, store *evidence.Store, params RecordGatewayEvidenceParams) (*evidence.Evidence, error) {
	var toolGov *evidence.ToolGovernance
	if len(params.ToolsRequested) > 0 || len(params.ToolsFiltered) > 0 || len(params.ToolsForwarded) > 0 {
		toolGov = &evidence.ToolGovernance{
			ToolsRequested: params.ToolsRequested,
			ToolsFiltered:  params.ToolsFiltered,
			ToolsForwarded: params.ToolsForwarded,
		}
	}

	invocationType := params.InvocationType
	if invocationType == "" {
		invocationType = "gateway"
	}
	ev := &evidence.Evidence{
		ID:              "gw_" + uuid.New().String()[:12],
		CorrelationID:   params.CorrelationID,
		SessionID:       params.SessionID,
		Stage:           params.Stage,
		CandidateIndex:  params.CandidateIndex,
		Timestamp:       time.Now(),
		TenantID:        params.TenantID,
		AgentID:         params.AgentName,
		Team:            params.Team,
		InvocationType:  invocationType,
		RequestSourceID: params.AgentName,
		PolicyDecision: evidence.PolicyDecision{
			Allowed:       params.PolicyAllowed,
			Action:        "allow",
			Reasons:       params.PolicyReasons,
			PolicyVersion: params.PolicyVersion,
			PolicyDigests: params.PolicyDigests,
		},
		Classification: evidence.Classification{
			InputTier:         params.InputTier,
			OutputTier:        params.OutputTier,
			PIIDetected:       params.PIIDetected,
			PIIRedacted:       params.PIIRedacted,
			InputPIIRedacted:  params.InputPIIRedacted,
			OutputPIIDetected: params.OutputPIIDetected,
			OutputPIITypes:    params.OutputPIITypes,
			Scanner:           params.Scanner,
			ToolContent:       params.ToolContent,
			ResponseScan:      params.ResponseScan,
		},
		Execution: evidence.Execution{
			ModelUsed:     params.Model,
			Cost:          params.Cost,
			EstimatedCost: params.EstimatedCost,
			Currency:      params.Currency,
			Tokens:        evidence.TokenUsage{Input: params.InputTokens, Output: params.OutputTokens, CacheRead: params.CacheReadTokens, CacheWrite: params.CacheWriteTokens},
			PricingBasis:  params.PricingBasis,
			PricingKnown:  params.PricingKnown,
			DurationMS:    params.DurationMS,
			TTFTMS:        params.TTFTMS,
			TPOTMS:        params.TPOTMS,
			Error:         params.Error,
		},
		SecretsAccessed:          params.SecretsAccessed,
		AttachmentScan:           params.AttachmentScan,
		ToolGovernance:           toolGov,
		AuditTrail:               evidence.AuditTrail{},
		Compliance:               evidence.Compliance{},
		AgentReasoning:           params.AgentReasoning,
		CacheHit:                 params.CacheHit,
		CacheEntryID:             params.CacheEntryID,
		CacheSourceCorrelationID: params.CacheSourceCorrelationID,
		CacheSimilarity:          params.CacheSimilarity,
		CostSaved:                params.CostSaved,
		UpstreamAuthMode:         params.UpstreamAuthMode,
		UpstreamKeySource:        params.UpstreamKeySource,
		UpstreamKeyFingerprint:   params.UpstreamKeyFingerprint,
		GatewayAnnotations:       sanitizeGatewayAnnotations(params.GatewayAnnotations),
		RetryAttempt:             params.RetryAttempt,
		RoutingDecision: &evidence.RoutingDecision{
			SelectedProvider: params.Provider,
			SelectedModel:    params.Model,
		},
		DataFlow:         params.DataFlow,
		EgressDecision:   params.EgressDecision,
		Status:           params.Status,
		FailureReason:    params.FailureReason,
		Failover:         params.Failover,
		Orchestration:    params.Orchestration,
		SessionBudget:    params.SessionBudget,
		CostBudget:       params.CostBudget,
		WorkloadIdentity: params.WorkloadIdentity,
		Enforcement:      params.Enforcement,
	}
	if !params.PolicyAllowed {
		ev.PolicyDecision.Action = "deny"
	}
	facts := append([]explanation.Fact(nil), params.ExplanationFacts...)
	if len(facts) == 0 {
		facts = explanation.BuildLegacyFacts(
			params.PolicyAllowed,
			ev.PolicyDecision.Action,
			params.PolicyReasons,
			explanation.StagePolicyEvaluation,
			explanation.PolicyRef(params.PolicyVersion),
			params.PolicyVersion,
		)
		if params.OutputPIIDetected {
			disposition := outputPIIObserved
			switch {
			case !params.PolicyAllowed:
				disposition = outputPIIBlocked
			case params.ResponseScan != nil && params.ResponseScan.Action == "redact" &&
				params.ResponseScan.Enforcement == evidence.ResponseScanEnforcementPreventive:
				disposition = outputPIIRedacted
			}
			facts = append(facts, outputPIIFact(params.OutputPIITypes, disposition, explanation.PolicyRef(params.PolicyVersion), params.PolicyVersion))
		}
	}
	ev.Explanations = explanation.BuildFromFacts(facts)
	if err := store.Store(ctx, ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// What happened to a response in which PII was detected.
const (
	outputPIIBlocked  = "blocked"
	outputPIIRedacted = "redacted"
	outputPIIObserved = "observed"
)

// outputPIIFact is the single output-validation explanation fact for a
// response with detected PII, keyed on the disposition that actually
// happened: a withheld response is a denial, a redacted one a modification,
// and an observed one (warn) an allow — the response was delivered.
func outputPIIFact(piiTypes []string, disposition, policyRef, version string) explanation.Fact {
	trigger := "output_pii_detected"
	if len(piiTypes) > 0 {
		trigger = strings.Join(piiTypes, ",")
	}
	fact := explanation.Fact{
		Stage:           explanation.StageOutputValidation,
		Trigger:         trigger,
		PolicyRef:       policyRef,
		VersionIdentity: version,
	}
	switch disposition {
	case outputPIIBlocked:
		fact.Code, fact.Decision = explanation.CodePolicyDeniedPIIOutput, explanation.DecisionDeny
	case outputPIIRedacted:
		fact.Code, fact.Decision = explanation.CodePolicyRedactedPIIOutput, explanation.DecisionModify
	default:
		fact.Code, fact.Decision = explanation.CodePolicyObservedPIIOutput, explanation.DecisionAllow
	}
	return fact
}

func sanitizeGatewayAnnotations(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	allowed := map[string]struct{}{
		"quickstart_mode":                     {},
		"quickstart_model_allowlist_disabled": {},
		"quickstart_unsafe_listen":            {},
		"quickstart_shadow_mode":              {}, // LEGACY (#442): historical records only
		// force_true reversed an explicit client store:false on a Responses
		// API request (#213) — a retention decision that must be evidenced.
		"responses_store_overridden": {},
		// The session-store read failed and the session budget check failed
		// open (#198) — the enforcement gap must be visible in evidence.
		"session_budget_unavailable": {},
		"delegated_dispatch":         {}, // #482: the provider was reached by an external runtime after a Talon delegated decision
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := allowed[v]; ok {
			out = append(out, v)
			continue
		}
		log.Warn().Str("annotation", v).Msg("dropping_unsupported_gateway_annotation")
	}
	return out
}

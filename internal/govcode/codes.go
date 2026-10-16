// Package govcode is the ONE registry of Talon's stable governance codes
// (#372, #429, #424 D3/D9): the machine-readable outcome vocabulary that
// every adapter — the HTTP Action Gateway, the MCP 2026-07-28 adapter, the
// LLM gateway error contract, CLI and audit projections — carries without
// inventing a competing name. A code is the integration contract; prose
// and explanation text may change.
//
// The package is transport-neutral: it knows nothing about HTTP status,
// JSON-RPC error numbers or MCP result shapes. Adapters map a code to their
// envelope; the code, its retryability and its explanation code are fixed
// here.
package govcode

import "sort"

// Class groups codes by what the caller may do next. It is informational
// and never a substitute for the code itself.
type Class string

const (
	// ClassDenied: an authoritative governance denial; the request as sent
	// will never be allowed.
	ClassDenied Class = "denied"
	// ClassInvalid: the request is malformed or references nothing
	// trustworthy; fix the request.
	ClassInvalid Class = "invalid"
	// ClassPending: authorization is not usable yet; poll the canonical
	// resource. Polling creates no authorization.
	ClassPending Class = "pending"
	// ClassConflict: the request conflicts with committed state.
	ClassConflict Class = "conflict"
	// ClassFailed: Talon or a dependency failed before or without an effect.
	ClassFailed Class = "failed"
	// ClassUnknown: an effect may have happened; automatic retry is blocked.
	ClassUnknown Class = "unknown"
	// ClassUnsupported: the surface or posture cannot perform the request.
	ClassUnsupported Class = "unsupported"
)

// Producer states which shipped component emits a code, or which issue owns
// the first emitter when none ships yet. Target codes are part of the
// contract so adapters converge on one name; tests assert they stay tagged.
const (
	ProducerAction  = "action"  // internal/action (Action Gateway spine)
	ProducerGateway = "gateway" // internal/gateway (LLM gateway, delegated path)
	ProducerMCP     = "mcp"     // internal/mcp (/mcp, /mcp/proxy)
	ProducerTarget  = "target"  // not emitted yet; Issue names the owner
)

// Spec is one stable code with its fixed semantics.
type Spec struct {
	Code string
	Class
	// Retryable is conservative: true only when the same request may
	// legitimately be repeated later without a human or operator change.
	Retryable bool
	// Explanation is the DEFAULT explanation category reported for this
	// code when no signed record exists to quote. When an evidence
	// reference is present the extension's reasonCode is the record's
	// actual primary explanation code (Extension.WithEvidence), so the
	// in-band reason always agrees with what was signed.
	Explanation string
	// Producers lists the shipped emitters, or ProducerTarget.
	Producers []string
	// Issue names the owning issue for a target code ("" when shipped).
	Issue string
	// Summary is one sentence of prose (may change).
	Summary string
}

// Stable codes. Spelling is the contract: existing action-domain and
// gateway names are canonical; #372's target names that had no shipped
// equivalent are added with their owning issue.
const (
	// ---- action domain (internal/action) ---------------------------------
	OperationIDRequired       = "operation_id_required"
	OperationConflict         = "operation_conflict"
	ActionNotFound            = "action_not_found"
	ActionSchemaInvalid       = "action_schema_invalid"
	PolicyDenied              = "policy_denied"
	ApprovalRequired          = "approval_required"
	ApprovalPending           = "approval_pending"
	ApprovalRejected          = "approval_rejected"
	ApprovalExpired           = "approval_expired"
	ApprovalNotAuthorized     = "approval_not_authorized"
	ApprovalAlreadyDecided    = "approval_already_decided"
	ApprovalBindingStale      = "approval_binding_stale"
	OperationAlreadySucceeded = "operation_already_succeeded"
	OperationOutcomeUnknown   = "operation_outcome_unknown"
	AttemptAlreadyInProgress  = "attempt_already_in_progress"
	AttemptNotAuthorized      = "attempt_not_authorized"
	PayloadUnavailable        = "payload_unavailable"
	ExecutionUnsupported      = "execution_unsupported"
	NotFound                  = "not_found"
	InvalidRequest            = "invalid_request"
	StoreUnavailable          = "store_unavailable"
	GenerationChanged         = "generation_changed"
	AgentIdentityRequired     = "agent_identity_required"

	// ---- gateway (internal/gateway) ----------------------------------------
	ModelNotAllowed                  = "model_not_allowed"
	ProviderNotAllowed               = "provider_not_allowed"
	BudgetExceeded                   = "budget_exceeded"
	SessionBudgetExceeded            = "session_budget_exceeded"
	DataTierExceeded                 = "data_tier_exceeded"
	PIIPolicyViolation               = "pii_policy_violation"
	ScannerUnavailable               = "scanner_unavailable"
	ToolPolicyViolation              = "tool_policy_violation"
	EgressTierDestinationDisallowed  = "egress_tier_destination_disallowed"
	EgressDestinationDisallowed      = "egress_destination_disallowed"
	RateLimited                      = "rate_limited"
	WorkloadIdentityRequired         = "workload_identity_required"
	WorkloadIdentityUnbound          = "workload_identity_unbound"
	DestinationNotGoverned           = "destination_not_governed"
	AgentDisabled                    = "agent_disabled"
	ModelRequiredForPolicyEvaluation = "model_required_for_policy_evaluation"

	// ---- added by #372 -----------------------------------------------------
	// PolicyEvaluationFailed: the policy engine could not produce a verdict;
	// Talon fails closed. Nothing was dispatched.
	PolicyEvaluationFailed = "policy_evaluation_failed"
	// UpstreamAuthUnavailable: the credential Talon needs to reach the
	// upstream could not be obtained before dispatch (vault miss); zero
	// upstream call.
	UpstreamAuthUnavailable = "upstream_auth_unavailable"
	// UpstreamToolFailed: the upstream (or process-local) tool answered with
	// a failure, a contract violation, or the outbound request could not be
	// built. When the request was never written the effect did not happen.
	UpstreamToolFailed = "upstream_tool_failed"
	// UpstreamOutcomeUnknown: the request may have reached the upstream and
	// no trustworthy answer exists (connect/send/deadline failure after the
	// request was handed to the transport); automatic retry is blocked.
	UpstreamOutcomeUnknown = "upstream_outcome_unknown"
	// EvidenceCommitFailed: the mandatory signed record for a governed
	// outcome could not be committed; Talon returns no evidence id,
	// fabricates none, and performs zero dispatch.
	EvidenceCommitFailed = "evidence_commit_failed"
	// ApprovalRequiresTasks: an asynchronous human approval is required and
	// the current MCP request does not advertise the Tasks extension; honest
	// non-execution, zero dispatch, no hidden continuation.
	ApprovalRequiresTasks = "approval_requires_tasks"
	// ApprovalCancelled: a pending approval request was withdrawn.
	ApprovalCancelled = "approval_cancelled"
	// ApprovalInvalidated: a pending approval became obsolete because its
	// approval-relevant context changed. Today the action domain reports
	// this as approval_binding_stale; this name is reserved for the typed
	// kernel's decision lifecycle.
	ApprovalInvalidated = "approval_invalidated"
	// UnsupportedRuntimePosture: the adapter/runtime cannot honour the
	// request under the always-enforced posture (e.g. a client demanding a
	// non-enforcing mode).
	UnsupportedRuntimePosture = "unsupported_runtime_posture"
)

var registry = []Spec{
	{Code: OperationIDRequired, Class: ClassInvalid, Explanation: "ACTION_INVALID_REQUEST", Producers: []string{ProducerAction}, Summary: "operation_id is required; official adapters generate and persist one before the first call."},
	{Code: OperationConflict, Class: ClassConflict, Explanation: "ACTION_OPERATION_CONFLICT", Producers: []string{ProducerAction}, Summary: "The operation_id is bound to a different material payload; use a new operation_id."},
	{Code: ActionNotFound, Class: ClassInvalid, Explanation: "ACTION_NOT_FOUND", Producers: []string{ProducerAction}, Summary: "The action is not in this AI use case's trusted catalog."},
	{Code: ActionSchemaInvalid, Class: ClassInvalid, Explanation: "ACTION_SCHEMA_INVALID", Producers: []string{ProducerAction}, Summary: "The arguments violate the trusted action schema or are not canonicalizable."},
	{Code: PolicyDenied, Class: ClassDenied, Explanation: "ACTION_POLICY_DENIED", Producers: []string{ProducerAction, ProducerMCP}, Summary: "Policy denied this action; approval cannot override it."},
	{Code: ApprovalRequired, Class: ClassPending, Explanation: "ACTION_APPROVAL_REQUIRED", Producers: []string{ProducerAction}, Summary: "An authenticated reviewer must approve the exact operation before any attempt."},
	{Code: ApprovalPending, Class: ClassPending, Retryable: true, Explanation: "ACTION_APPROVAL_REQUESTED", Producers: []string{ProducerAction}, Summary: "The approval is pending; poll the operation or approval resource."},
	{Code: ApprovalRejected, Class: ClassDenied, Explanation: "ACTION_APPROVAL_REJECTED", Producers: []string{ProducerAction}, Summary: "A reviewer rejected the exact operation; a revised request needs a new operation."},
	{Code: ApprovalExpired, Class: ClassDenied, Explanation: "ACTION_APPROVAL_EXPIRED", Producers: []string{ProducerAction}, Summary: "The approval lifetime elapsed before first-attempt authorization."},
	{Code: ApprovalNotAuthorized, Class: ClassDenied, Explanation: "ACTION_APPROVAL_NOT_AUTHORIZED", Producers: []string{ProducerAction}, Summary: "The presented principal is not an approver authorized for this operation."},
	{Code: ApprovalAlreadyDecided, Class: ClassConflict, Explanation: "ACTION_APPROVAL_DECIDED", Producers: []string{ProducerAction}, Summary: "A decision is already committed; decisions are immutable."},
	{Code: ApprovalBindingStale, Class: ClassDenied, Explanation: "ACTION_APPROVAL_INVALIDATED", Producers: []string{ProducerAction}, Summary: "The trusted definition or policy changed since the subject was bound; establish a new operation."},
	{Code: OperationAlreadySucceeded, Class: ClassConflict, Explanation: "ACTION_ATTEMPT_SUCCEEDED", Producers: []string{ProducerAction}, Summary: "The operation already produced its effect; no further attempt is permitted."},
	{Code: OperationOutcomeUnknown, Class: ClassUnknown, Explanation: "ACTION_ATTEMPT_UNKNOWN", Producers: []string{ProducerAction}, Summary: "A previous attempt has no trustworthy outcome; automatic retry is blocked until reconciliation."},
	{Code: AttemptAlreadyInProgress, Class: ClassPending, Retryable: true, Explanation: "ACTION_ATTEMPT_CLAIMED", Producers: []string{ProducerAction}, Summary: "Another claimer holds the attempt; poll the operation."},
	{Code: AttemptNotAuthorized, Class: ClassDenied, Explanation: "ACTION_AUTHORIZATION_REFUSED", Producers: []string{ProducerAction}, Summary: "No usable authorization permits an attempt."},
	{Code: PayloadUnavailable, Class: ClassFailed, Explanation: "ACTION_AUTHORIZATION_REFUSED", Producers: []string{ProducerAction}, Summary: "The sealed payload cannot be opened (key rotated or purged); establish a new operation."},
	{Code: ExecutionUnsupported, Class: ClassUnsupported, Explanation: "ACTION_EXECUTION_UNSUPPORTED", Producers: []string{ProducerAction}, Summary: "This adapter has no executor for the action's destination type."},
	{Code: NotFound, Class: ClassInvalid, Explanation: "ACTION_NOT_FOUND", Producers: []string{ProducerAction}, Summary: "No such operation or approval in this scope."},
	{Code: InvalidRequest, Class: ClassInvalid, Explanation: "ACTION_INVALID_REQUEST", Producers: []string{ProducerAction}, Summary: "The request is malformed."},
	{Code: StoreUnavailable, Class: ClassFailed, Retryable: true, Explanation: "ACTION_STORE_UNAVAILABLE", Producers: []string{ProducerAction}, Summary: "Durable state could not be read or written; nothing changed."},
	{Code: GenerationChanged, Class: ClassConflict, Retryable: true, Explanation: "ACTION_GENERATION_CHANGED", Producers: []string{ProducerAction}, Summary: "The runtime generation changed between resolution and request; retry against the current generation."},
	{Code: AgentIdentityRequired, Class: ClassDenied, Explanation: "ACTION_AUTHORIZATION_REFUSED", Producers: []string{ProducerAction}, Summary: "The surface requires an authenticated AI use case identity."},

	{Code: ModelNotAllowed, Class: ClassDenied, Explanation: "POLICY_DENIED_ROUTING", Producers: []string{ProducerGateway}, Summary: "The model is outside the effective allow- or block-lists."},
	{Code: ProviderNotAllowed, Class: ClassDenied, Explanation: "POLICY_DENIED_ROUTING", Producers: []string{ProducerGateway}, Summary: "The provider is outside the effective allowlist."},
	{Code: BudgetExceeded, Class: ClassDenied, Explanation: "POLICY_DENIED_COST", Producers: []string{ProducerGateway}, Summary: "A daily or monthly cost cap would be exceeded."},
	{Code: SessionBudgetExceeded, Class: ClassDenied, Explanation: "POLICY_DENIED_COST", Producers: []string{ProducerGateway}, Summary: "The session cap would be exceeded."},
	{Code: DataTierExceeded, Class: ClassDenied, Explanation: "POLICY_DENIED_PII_INPUT", Producers: []string{ProducerGateway}, Summary: "The request data tier is above the effective maximum."},
	{Code: PIIPolicyViolation, Class: ClassDenied, Explanation: "POLICY_DENIED_PII_INPUT", Producers: []string{ProducerGateway, ProducerMCP}, Summary: "PII policy blocked the content, or recognized PII remained after redaction."},
	{Code: ScannerUnavailable, Class: ClassFailed, Retryable: true, Explanation: "EXECUTION_FAILED", Producers: []string{ProducerGateway, ProducerMCP}, Summary: "The PII scan engine is unavailable or its output unverifiable; fail closed."},
	{Code: ToolPolicyViolation, Class: ClassDenied, Explanation: "POLICY_DENIED_TOOL", Producers: []string{ProducerGateway}, Summary: "The request declares forbidden tools and the effective action is block."},
	{Code: EgressTierDestinationDisallowed, Class: ClassDenied, Explanation: "POLICY_DENIED_EGRESS", Producers: []string{ProducerGateway}, Summary: "Egress policy denies this data tier for this destination."},
	{Code: EgressDestinationDisallowed, Class: ClassDenied, Explanation: "POLICY_DENIED_EGRESS", Producers: []string{ProducerGateway}, Summary: "Egress policy denies this destination."},
	{Code: RateLimited, Class: ClassFailed, Retryable: true, Explanation: "RATE_LIMITED", Producers: []string{ProducerGateway}, Summary: "A gateway rate limit was exceeded; back off and retry."},
	{Code: WorkloadIdentityRequired, Class: ClassDenied, Explanation: "WORKLOAD_IDENTITY_REQUIRED", Producers: []string{ProducerGateway}, Summary: "No verified workload identity was presented on the delegated path."},
	{Code: WorkloadIdentityUnbound, Class: ClassDenied, Explanation: "WORKLOAD_IDENTITY_UNBOUND", Producers: []string{ProducerGateway}, Summary: "The verified subject is bound to no Talon AI use case."},
	{Code: DestinationNotGoverned, Class: ClassDenied, Explanation: "DESTINATION_NOT_GOVERNED", Producers: []string{ProducerGateway}, Summary: "No enabled provider matches the destination; fail closed."},
	{Code: AgentDisabled, Class: ClassDenied, Explanation: "AGENT_DISABLED", Producers: []string{ProducerGateway}, Summary: "The AI use case is disabled."},
	{Code: ModelRequiredForPolicyEvaluation, Class: ClassInvalid, Explanation: "POLICY_DENIED_ROUTING", Producers: []string{ProducerGateway}, Summary: "The request omits a model while a model policy is active."},

	{Code: PolicyEvaluationFailed, Class: ClassFailed, Retryable: true, Explanation: "EXECUTION_FAILED", Producers: []string{ProducerMCP}, Summary: "The policy engine could not produce a verdict; fail closed, nothing dispatched."},
	{Code: UpstreamAuthUnavailable, Class: ClassFailed, Retryable: true, Explanation: "EXECUTION_FAILED", Producers: []string{ProducerMCP}, Summary: "The upstream credential could not be obtained before dispatch; zero upstream call."},
	{Code: UpstreamToolFailed, Class: ClassFailed, Explanation: "EXECUTION_FAILED", Producers: []string{ProducerMCP}, Summary: "The tool failed, violated its contract, or the outbound request could not be built."},
	{Code: UpstreamOutcomeUnknown, Class: ClassUnknown, Explanation: "EXECUTION_OUTCOME_UNKNOWN", Producers: []string{ProducerMCP}, Summary: "The request may have reached the upstream and no trustworthy answer exists; automatic retry is blocked."},
	{Code: EvidenceCommitFailed, Class: ClassFailed, Retryable: true, Explanation: "EXECUTION_FAILED", Producers: []string{ProducerMCP}, Summary: "The mandatory signed record could not be committed; no evidence id, zero dispatch."},
	{Code: ApprovalRequiresTasks, Class: ClassUnsupported, Explanation: "ACTION_APPROVAL_REQUIRED", Producers: []string{ProducerTarget}, Issue: "#431/#448", Summary: "Asynchronous approval needs the MCP Tasks extension in the current request; honest non-execution, zero dispatch."},
	{Code: ApprovalCancelled, Class: ClassDenied, Explanation: "ACTION_APPROVAL_CANCELLED", Producers: []string{ProducerTarget}, Issue: "#426", Summary: "The pending approval request was withdrawn."},
	{Code: ApprovalInvalidated, Class: ClassDenied, Explanation: "ACTION_APPROVAL_INVALIDATED", Producers: []string{ProducerTarget}, Issue: "#426", Summary: "The pending approval became obsolete; today reported as approval_binding_stale."},
	{Code: UnsupportedRuntimePosture, Class: ClassUnsupported, Explanation: "POLICY_POSTURE", Producers: []string{ProducerTarget}, Issue: "#431", Summary: "The request demands a posture the always-enforced product does not offer."},
}

var byCode = func() map[string]Spec {
	m := make(map[string]Spec, len(registry))
	for _, s := range registry {
		m[s.Code] = s
	}
	return m
}()

// Lookup returns the spec of a registered code.
func Lookup(code string) (Spec, bool) {
	s, ok := byCode[code]
	return s, ok
}

// All returns every registered spec sorted by code (deterministic for
// documentation and parity tests).
func All() []Spec {
	out := make([]Spec, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Retryable reports the conservative retryability of a code; unknown codes
// are never retryable.
func Retryable(code string) bool {
	s, ok := byCode[code]
	return ok && s.Retryable
}

// IsTarget reports whether no shipped component emits the code yet.
func (s Spec) IsTarget() bool {
	return len(s.Producers) == 1 && s.Producers[0] == ProducerTarget
}

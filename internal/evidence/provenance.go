package evidence

// Enforcement provenance (#146 external-enforcement extension, spec 1.11).
//
// A Talon record has always described what Talon decided. When a
// complementary execution runtime (e.g. NVIDIA OpenShell) owns the actual
// prevention boundary, the record must also say WHO could prevent the
// effect and WHO enforced it. A valid Talon signature proves Talon recorded
// the claim below; it never proves an external runtime actually enforced it.
//
// Absence of the Enforcement object means the legacy default: Talon
// intercepted the traffic on its own gateway/MCP boundary (talon_enforced).

// Enforcement mechanisms (#424 doctrine).
const (
	MechanismIntercept = "intercept" // Talon owns the prevention boundary
	MechanismDelegate  = "delegate"  // Talon decides; a runtime's pre-execution hook enforces
	MechanismVerify    = "verify"    // a runtime enforced; Talon only consumed the fact
)

// Enforcement boundaries and decision authorities.
const (
	BoundaryTalon           = "talon"
	BoundaryExternalRuntime = "external_runtime"
)

// Provenance vocabulary (#146).
const (
	ProvenanceTalonEnforced           = "talon_enforced"
	ProvenanceExternalRuntimeEnforced = "external_runtime_enforced"
	ProvenanceExternalRuntimeVerified = "external_runtime_verified"
	ProvenanceClientAsserted          = "client_asserted"
)

// Workload identity verification statuses (#457).
const (
	WorkloadIdentityVerified = "verified"
	WorkloadIdentityFailed   = "failed"
	WorkloadIdentityAbsent   = "absent"
	// WorkloadIdentityAsserted marks identity facts that were imported or
	// asserted (e.g. a sandbox id read from a runtime's log export), never
	// verified by Talon. Attribution only.
	WorkloadIdentityAsserted = "asserted"
)

// WorkloadIdentityBindingAgentConfig marks a principal→use-case binding
// that came from the agent's own trusted configuration file.
const WorkloadIdentityBindingAgentConfig = "agent_config"

// Enforcement records who owned the prevention/observation boundary.
type Enforcement struct {
	Mechanism         string `json:"mechanism"`
	Boundary          string `json:"boundary"`
	DecisionAuthority string `json:"decision_authority"`
	Provenance        string `json:"provenance"`
	// Observed is true only when Talon itself observed the enforcement
	// outcome (its own interception, or a verified runtime receipt). On a
	// delegated pre-execution decision Talon returns a verdict and relies
	// on the runtime's hook contract; it did not see the block or the
	// forward, so Observed is false.
	Observed bool                `json:"observed"`
	Runtime  *ExternalRuntimeRef `json:"runtime,omitempty"`
	Receipt  *ExternalReceipt    `json:"receipt,omitempty"`
}

// ExternalRuntimeRef is a SAFE reference to the external runtime involved:
// configured type/identity and opaque runtime-side identifiers. Never
// tokens, never credential placeholders.
type ExternalRuntimeRef struct {
	Type string `json:"type"`         // e.g. "openshell"
	ID   string `json:"id,omitempty"` // configured stable runtime identity (e.g. gateway id)
	// PolicyRef is the runtime's own policy/config identity when safe and
	// available (e.g. the OpenShell policy name that selected Talon).
	PolicyRef string `json:"policy_ref,omitempty"`
	// Reference is the runtime's workload reference (e.g. sandbox id).
	Reference string `json:"reference,omitempty"`
	// RequestID is the runtime's per-request correlation id.
	RequestID string `json:"request_id,omitempty"`
}

// ExternalReceipt describes an externally produced fact Talon consumed.
// Verified is true only when Talon cryptographically verified the receipt
// itself; an operator-imported unsigned export is recorded with
// Verified=false so it can never be read as externally verified.
type ExternalReceipt struct {
	Kind     string `json:"kind"`             // e.g. "openshell_ocsf"
	Digest   string `json:"digest,omitempty"` // sha256 of the raw receipt bytes
	Verified bool   `json:"verified"`
	// Detail is a bounded, sanitized summary (e.g. an OCSF status_detail).
	Detail string `json:"detail,omitempty"`
}

// WorkloadIdentity records the outcome of verified workload-identity
// federation at ingress (#457). Safe facts only: never the raw credential.
type WorkloadIdentity struct {
	Status      string `json:"status"` // verified | failed | absent
	Runtime     string `json:"runtime,omitempty"`
	AuthMethod  string `json:"auth_method,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Subject     string `json:"subject,omitempty"`
	PrincipalID string `json:"principal_id,omitempty"`
	Audience    string `json:"audience,omitempty"`
	// Binding names where the principal → use-case binding came from
	// (agent_config). Empty when no binding was established.
	Binding     string `json:"binding,omitempty"`
	FailureCode string `json:"failure_code,omitempty"`
	VerifiedAt  string `json:"verified_at,omitempty"` // RFC 3339 UTC
}

// InvocationTypeExternalRuntimeEvent marks a signed record of a containment
// fact an external runtime produced and Talon imported (e.g. an OpenShell
// network denial). Never request-class: Talon made no decision.
const InvocationTypeExternalRuntimeEvent = "external_runtime_event"

// Action lifecycle evidence (#458/#146, spec 1.12).
//
// One signed record per lifecycle transition of a governed action
// operation, all sharing the operation's resource id as correlation_id, so
// the chain can be listed and independently verified (VerifyLifecycle in
// internal/action). Each record answers the separate questions the #482
// work made explicit: who decided (Talon policy), whether a human decided,
// whether Talon owned the dispatch boundary, whether Talon observed the
// dispatch, and how the result is known. These are distinct fields; none
// of them is the enforcement-boundary `Enforcement.Observed` flag.

// Lifecycle event names.
const (
	ActionEventOperationEstablished = "operation_established"
	ActionEventOperationConflict    = "operation_conflict"
	ActionEventApprovalRequested    = "approval_requested"
	ActionEventApprovalDecided      = "approval_decided"
	ActionEventAttemptClaimed       = "attempt_claimed"
	ActionEventAttemptDispatched    = "attempt_dispatched"
	ActionEventAttemptCompleted     = "attempt_completed"
	ActionEventAuthorizationRefused = "authorization_refused"
)

// Result provenance for an attempt outcome.
const (
	ResultProvenanceObserved       = "observed"       // Talon observed the downstream response
	ResultProvenanceUnknown        = "unknown"        // dispatch may have happened; no reliable outcome
	ResultProvenanceNotDispatched  = "not_dispatched" // the attempt failed before any request left Talon
	ResultProvenanceClientAsserted = "client_asserted"
	ResultProvenanceReconciled     = "reconciled"
)

// InvocationTypeActionLifecycle marks every action lifecycle record.
const InvocationTypeActionLifecycle = "action_lifecycle"

// ActionLifecycle is the per-transition fact set of one governed operation.
type ActionLifecycle struct {
	Event string `json:"event"`
	// Sequence is the operation-local monotonic transition number (1 = the
	// establishing record). The verifier requires a gap-free sequence.
	Sequence int `json:"sequence"`
	// Identity of the exact intended effect.
	OperationID      string `json:"operation_id"`  // caller-provided external id
	OperationRef     string `json:"operation_ref"` // Talon resource id (= correlation_id)
	Action           string `json:"action"`
	Digest           string `json:"digest"` // exact operation digest
	SchemaDigest     string `json:"schema_digest"`
	PolicyDigest     string `json:"policy_digest"` // approval-relevant policy digest
	BindingProfile   string `json:"binding_profile"`
	ExecutionProfile string `json:"execution_profile"` // talon_forwarded
	DestinationID    string `json:"destination_id"`
	IdentitySource   string `json:"identity_source,omitempty"` // caller_provided | adapter_generated
	// Verdict and states (separate axes, never one boolean).
	Verdict         string   `json:"verdict,omitempty"` // ALLOW | DENY | REQUIRE_APPROVAL
	MatchedRuleID   string   `json:"matched_rule_id,omitempty"`
	OperationStatus string   `json:"operation_status"`
	ApprovalID      string   `json:"approval_id,omitempty"`
	ApprovalStatus  string   `json:"approval_status,omitempty"`
	ApproverGroups  []string `json:"approver_groups,omitempty"`
	ApprovalExpires string   `json:"approval_expires_at,omitempty"`
	// Reviewer identity is the authenticated approver principal, never a
	// display name from the request body.
	ReviewerPrincipal string `json:"reviewer_principal,omitempty"`
	ReviewerGroup     string `json:"reviewer_group,omitempty"`
	DecisionReason    string `json:"decision_reason,omitempty"`
	// Attempt facts.
	AttemptID        string `json:"attempt_id,omitempty"`
	AttemptOrdinal   int    `json:"attempt_ordinal,omitempty"`
	AttemptStatus    string `json:"attempt_status,omitempty"`
	IdempotencyKey   string `json:"idempotency_key,omitempty"`
	DispatchBoundary string `json:"dispatch_boundary,omitempty"` // talon_forwarded
	// DispatchObserved is true once Talon itself wrote the downstream
	// request (the dispatch marker); it says nothing about the result.
	DispatchObserved bool `json:"dispatch_observed,omitempty"`
	// ResultProvenance says how the outcome is known: observed by Talon,
	// unknown (request may have left, no reliable answer), or not
	// dispatched at all.
	ResultProvenance string `json:"result_provenance,omitempty"`
	OutcomeCode      string `json:"outcome_code,omitempty"`
	OutcomeRef       string `json:"outcome_ref,omitempty"` // safe reference (e.g. response digest)
	RefusalCode      string `json:"refusal_code,omitempty"`
}

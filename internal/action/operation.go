package action

import (
	"encoding/json"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// Operation statuses (#426). `denied` is the persisted outcome of a DENY
// verdict so an identical replay returns the same denial and a changed
// payload under the same id is still a conflict.
const (
	OpAwaitingApproval = "awaiting_approval"
	OpAuthorized       = "authorized"
	OpExecuting        = "executing"
	OpSucceeded        = "succeeded"
	OpFailed           = "failed"
	OpUnknown          = "unknown"
	OpCancelled        = "cancelled"
	OpDenied           = "denied"
)

// Approval statuses.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalExpired  = "expired"
	// ApprovalInvalidated: the exact subject became obsolete (trusted
	// definition changed) before a decision. System outcome, not a human one.
	ApprovalInvalidated = "invalidated"
)

// Attempt statuses.
const (
	AttemptStarted   = "started"
	AttemptSucceeded = "succeeded"
	AttemptFailed    = "failed"
	AttemptUnknown   = "unknown"
)

// Identity sources.
const (
	IdentityCallerProvided   = "caller_provided"
	IdentityAdapterGenerated = "adapter_generated"
)

// Result provenance aliases (canonical values live in the evidence package
// so the verifier and the domain agree by construction).
const (
	ResultProvenanceObserved      = evidence.ResultProvenanceObserved
	ResultProvenanceUnknown       = evidence.ResultProvenanceUnknown
	ResultProvenanceNotDispatched = evidence.ResultProvenanceNotDispatched
)

// Operation is one immutable intended business effect.
type Operation struct {
	Ref              string // Talon resource id; evidence correlation id
	TenantID         string
	AgentID          string
	OperationID      string
	Action           string
	Digest           string
	SchemaDigest     string
	DefinitionDigest string // trusted definition identity bound at establish (schema, projection, destination, success, binding)
	ProjectionDigest string
	PolicyDigest     string
	CatalogDigest    string
	ExecutionProfile string
	BindingProfile   string
	DestinationID    string
	IdentitySource   string
	Verdict          string
	RuleID           string
	Status           string
	Version          int
	Sequence         int
	ApprovalID       string
	IdempotencyKey   string
	// ReviewJSON is the stored reviewer projection (never the raw payload;
	// the payload lives sealed in action_payloads).
	ReviewJSON        []byte
	CreatedAt         time.Time
	UpdatedAt         time.Time
	TerminalAt        *time.Time
	OutcomeProvenance string
	OutcomeCode       string
	AttemptCount      int
}

// Approval is the immutable exact approval subject and its decision.
type Approval struct {
	ID            string
	OperationRef  string
	SubjectDigest string
	RuleID        string
	Groups        []string
	Status        string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	DecidedAt     *time.Time
	DecidedBy     string // principal_id, or "system"
	DecidedGroup  string
	Reason        string
	Version       int
}

// Attempt is one execution try of an operation.
type Attempt struct {
	ID               string
	OperationRef     string
	Ordinal          int
	Status           string
	IdempotencyKey   string
	StartedAt        time.Time
	ArmedAt          *time.Time // durable pre-effect marker (intent, not observation)
	CompletedAt      *time.Time
	RequestWritten   bool // dispatcher observation
	ResponseObserved bool // dispatcher observation
	HTTPStatus       int
	ResultProvenance string
	OutcomeCode      string
	OutcomeRef       string
}

// Projection is the safe, adapter-facing view of an operation. It never
// contains the raw payload, only the reviewer projection.
type Projection struct {
	OperationID       string                     `json:"operation_id"`
	OperationRef      string                     `json:"operation_ref"`
	Action            string                     `json:"action"`
	Status            string                     `json:"operation_status"`
	Verdict           string                     `json:"verdict"`
	MatchedRuleID     string                     `json:"matched_rule_id,omitempty"`
	Digest            string                     `json:"digest"`
	DefinitionDigest  string                     `json:"definition_digest"`
	ExecutionProfile  string                     `json:"execution_profile"`
	DestinationID     string                     `json:"destination_id"`
	Version           int                        `json:"version"`
	AttemptCount      int                        `json:"attempt_count"`
	OutcomeCode       string                     `json:"outcome_code,omitempty"`
	OutcomeProvenance string                     `json:"outcome_provenance,omitempty"`
	Approval          *ApprovalProjection        `json:"approval,omitempty"`
	LatestAttempt     *AttemptProjection         `json:"latest_attempt,omitempty"`
	Review            map[string]json.RawMessage `json:"review,omitempty"`
	Payload           PayloadState               `json:"payload"`
	CreatedAt         time.Time                  `json:"created_at"`
	UpdatedAt         time.Time                  `json:"updated_at"`
}

// ApprovalProjection is the safe view of an approval.
type ApprovalProjection struct {
	ID           string     `json:"id"`
	Status       string     `json:"status"`
	RuleID       string     `json:"rule_id"`
	Groups       []string   `json:"approver_groups"`
	ExpiresAt    time.Time  `json:"expires_at"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	DecidedGroup string     `json:"decided_group,omitempty"`
	Reason       string     `json:"reason,omitempty"`
}

// AttemptProjection is the safe view of an attempt.
type AttemptProjection struct {
	ID               string     `json:"id"`
	Ordinal          int        `json:"ordinal"`
	Status           string     `json:"status"`
	IdempotencyKey   string     `json:"idempotency_key"`
	StartedAt        time.Time  `json:"started_at"`
	ArmedAt          *time.Time `json:"armed_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	DispatchArmed    bool       `json:"dispatch_armed"`
	RequestWritten   bool       `json:"request_written"`
	ResponseObserved bool       `json:"response_observed"`
	HTTPStatus       int        `json:"http_status,omitempty"`
	ResultProvenance string     `json:"result_provenance,omitempty"`
	OutcomeCode      string     `json:"outcome_code,omitempty"`
	OutcomeRef       string     `json:"outcome_ref,omitempty"`
}

func projectionOf(op *Operation, ap *Approval, at *Attempt, payload PayloadState) *Projection {
	p := &Projection{
		OperationID: op.OperationID, OperationRef: op.Ref, Action: op.Action, Status: op.Status, Verdict: op.Verdict,
		MatchedRuleID: op.RuleID, Digest: op.Digest, DefinitionDigest: op.DefinitionDigest, ExecutionProfile: op.ExecutionProfile, DestinationID: op.DestinationID,
		Version: op.Version, AttemptCount: op.AttemptCount, OutcomeCode: op.OutcomeCode, OutcomeProvenance: op.OutcomeProvenance,
		Payload: payload, CreatedAt: op.CreatedAt, UpdatedAt: op.UpdatedAt,
	}
	if ap != nil {
		p.Approval = &ApprovalProjection{
			ID: ap.ID, Status: ap.Status, RuleID: ap.RuleID, Groups: append([]string(nil), ap.Groups...),
			ExpiresAt: ap.ExpiresAt, DecidedAt: ap.DecidedAt, DecidedBy: ap.DecidedBy, DecidedGroup: ap.DecidedGroup, Reason: ap.Reason,
		}
	}
	if at != nil {
		p.LatestAttempt = &AttemptProjection{
			ID: at.ID, Ordinal: at.Ordinal, Status: at.Status, IdempotencyKey: at.IdempotencyKey,
			StartedAt: at.StartedAt, ArmedAt: at.ArmedAt, CompletedAt: at.CompletedAt, DispatchArmed: at.ArmedAt != nil,
			RequestWritten: at.RequestWritten, ResponseObserved: at.ResponseObserved, HTTPStatus: at.HTTPStatus,
			ResultProvenance: at.ResultProvenance, OutcomeCode: at.OutcomeCode, OutcomeRef: at.OutcomeRef,
		}
	}
	if len(op.ReviewJSON) > 0 {
		_ = json.Unmarshal(op.ReviewJSON, &p.Review)
	}
	return p
}

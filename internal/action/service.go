package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
)

// Service is ActionGovernance for one agent generation: catalog + approval
// policy are captured at construction (immutable), state lives in the
// repository, evidence in the evidence store, effects in the dispatcher.
type Service struct {
	TenantID string
	AgentID  string
	Catalog  *Catalog
	Policy   *ApprovalPolicy

	repo       *Repository
	evidence   *evidence.Store
	dispatcher Dispatcher
	now        func() time.Time
	newID      func(prefix string) string
}

// NewService wires the domain for one agent. The repository must live in
// the evidence store's database (NewRepository(evStore.DB())).
func NewService(tenantID, agentID string, catalog *Catalog, policy *ApprovalPolicy, repo *Repository, evStore *evidence.Store, dispatcher Dispatcher) (*Service, error) {
	if catalog == nil || policy == nil || repo == nil || evStore == nil || dispatcher == nil {
		return nil, errors.New("action service: catalog, policy, repository, evidence store and dispatcher are required")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	return &Service{
		TenantID: tenantID, AgentID: agentID, Catalog: catalog, Policy: policy,
		repo: repo, evidence: evStore, dispatcher: dispatcher,
		now: func() time.Time { return time.Now().UTC() },
		newID: func(prefix string) string {
			return prefix + "_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:20]
		},
	}, nil
}

var operationIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ReviewerPrincipal is the AUTHENTICATED human approver (never a display
// name from a request body).
type ReviewerPrincipal struct {
	Name  string
	Group string
}

// EstablishRequest is the adapter-neutral first call.
type EstablishRequest struct {
	OperationID    string
	Action         string
	Arguments      json.RawMessage
	IdentitySource string // caller_provided (default) | adapter_generated
}

// EstablishResult reports whether the operation was created now.
type EstablishResult struct {
	Operation *Projection
	Created   bool
}

// ---- evidence helpers -------------------------------------------------

func (s *Service) lifecycleRecord(op *Operation, ev *evidence.ActionLifecycle, allowed bool, reasons []string, code string) *evidence.Evidence {
	ev.OperationID, ev.OperationRef, ev.Action = op.OperationID, op.Ref, op.Action
	ev.Digest, ev.SchemaDigest, ev.PolicyDigest = op.Digest, op.SchemaDigest, op.PolicyDigest
	ev.BindingProfile, ev.ExecutionProfile, ev.DestinationID = op.BindingProfile, op.ExecutionProfile, op.DestinationID
	ev.IdentitySource, ev.Verdict, ev.MatchedRuleID, ev.OperationStatus = op.IdentitySource, op.Verdict, op.RuleID, op.Status
	decision := explanation.DecisionAllow
	if !allowed {
		decision = explanation.DecisionDeny
	}
	stage := explanation.StagePreExecution
	switch ev.Event {
	case evidence.ActionEventAttemptDispatched, evidence.ActionEventAttemptCompleted:
		stage = explanation.StageExecution
	}
	return &evidence.Evidence{
		ID:              s.newID("act"),
		CorrelationID:   op.Ref,
		Timestamp:       s.now(),
		TenantID:        op.TenantID,
		AgentID:         op.AgentID,
		InvocationType:  evidence.InvocationTypeActionLifecycle,
		RequestSourceID: "action_gateway",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: allowed, Action: ev.Event, Reasons: reasons, PolicyVersion: "action-policy:" + op.PolicyDigest,
		},
		Explanations: []explanation.Item{{
			Code:            code,
			Decision:        decision,
			Stage:           stage,
			Reason:          strings.Join(reasons, "; "),
			PolicyRef:       "action:" + op.Action,
			VersionIdentity: op.PolicyDigest,
		}},
		Status:          statusForEvent(op),
		ActionLifecycle: ev,
	}
}

func statusForEvent(op *Operation) string {
	switch op.Status {
	case OpDenied:
		return "denied"
	case OpSucceeded:
		return "completed"
	case OpFailed:
		return "failed"
	default:
		return ""
	}
}

// commit writes the record inside tx and bumps the operation sequence in
// memory (the caller persists the operation row in the same tx).
func (s *Service) commit(ctx context.Context, tx *sql.Tx, op *Operation, ev *evidence.ActionLifecycle, allowed bool, reasons []string, code string) error {
	op.Sequence++
	ev.Sequence = op.Sequence
	rec := s.lifecycleRecord(op, ev, allowed, reasons, code)
	if err := s.evidence.StoreTx(ctx, tx, rec); err != nil {
		return &Error{Code: CodeStoreUnavailable, Message: "committing lifecycle evidence", Err: err}
	}
	return nil
}

// ---- Establish -------------------------------------------------------

// Establish validates, binds and persists one exact operation, evaluating
// the authoritative verdict. It performs zero dispatch.
func (s *Service) Establish(ctx context.Context, req EstablishRequest) (*EstablishResult, error) {
	opID := strings.TrimSpace(req.OperationID)
	if opID == "" {
		return nil, newErr(CodeOperationIDRequired, "operation_id is required: official adapters generate and persist one before the first call")
	}
	if !operationIDRe.MatchString(opID) {
		return nil, newErr(CodeInvalidRequest, "operation_id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
	}
	def, ok := s.Catalog.Lookup(strings.TrimSpace(req.Action))
	if !ok {
		return nil, newErr(CodeActionNotFound, "action is not in this AI use case's trusted catalog")
	}
	if len(req.Arguments) == 0 {
		req.Arguments = json.RawMessage("{}")
	}
	canonical, err := Canonicalize(req.Arguments)
	if err != nil {
		return nil, &Error{Code: CodeActionSchemaInvalid, Message: "arguments are not canonicalizable JSON", Err: err}
	}
	if err := def.ValidateArguments(canonical); err != nil {
		return nil, &Error{Code: CodeActionSchemaInvalid, Message: "arguments violate the action schema", Err: err}
	}
	identitySource := req.IdentitySource
	if identitySource == "" {
		identitySource = IdentityCallerProvided
	}
	verdict := s.Policy.Evaluate(def.Name)
	digest := s.operationDigest(def, canonical)

	var result *EstablishResult
	err = s.repo.withTx(ctx, func(tx *sql.Tx) error {
		existing, err := getOperation(ctx, tx, s.TenantID, s.AgentID, opID)
		if err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "reading operation", Err: err}
		}
		if existing != nil {
			if existing.Digest == digest {
				proj, err := s.project(ctx, tx, existing)
				if err != nil {
					return err
				}
				result = &EstablishResult{Operation: proj, Created: false}
				return nil
			}
			// Same id, different intended effect: record the conflict on the
			// EXISTING operation and mutate nothing else.
			existing.Version++
			existing.UpdatedAt = s.now()
			if ok, err := updateOperation(ctx, tx, existing, existing.Version-1); err != nil || !ok {
				return &Error{Code: CodeStoreUnavailable, Message: "recording conflict", Err: err}
			}
			if err := s.commit(ctx, tx, existing, &evidence.ActionLifecycle{Event: evidence.ActionEventOperationConflict, RefusalCode: CodeOperationConflict},
				false, []string{"same operation_id presented with a different material payload; existing digest retained"}, "ACTION_OPERATION_CONFLICT"); err != nil {
				return err
			}
			if _, err := updateOperation(ctx, tx, existing, existing.Version); err != nil {
				return &Error{Code: CodeStoreUnavailable, Message: "recording conflict", Err: err}
			}
			proj, _ := s.project(ctx, tx, existing)
			return refusal(&Error{Code: CodeOperationConflict, Message: "operation_id already bound to a different material payload; use a new operation_id for a corrected action", State: proj})
		}
		now := s.now()
		op := &Operation{
			Ref: s.newID("op"), TenantID: s.TenantID, AgentID: s.AgentID, OperationID: opID, Action: def.Name,
			Digest: digest, SchemaDigest: def.SchemaDigest, PolicyDigest: s.Policy.Digest, CatalogDigest: s.Catalog.Digest,
			ExecutionProfile: def.ExecutionProfile, BindingProfile: def.BindingProfile, DestinationID: def.DestinationID,
			IdentitySource: identitySource, Verdict: verdict.Outcome, RuleID: verdict.RuleID, Version: 1, Payload: canonical,
			CreatedAt: now, UpdatedAt: now,
		}
		op.IdempotencyKey = "talon-" + op.Ref
		reasons := []string{verdict.Reason}
		code := "ACTION_AUTHORIZED"
		allowed := true
		switch verdict.Outcome {
		case VerdictDeny:
			op.Status, op.OutcomeCode, op.TerminalAt = OpDenied, CodePolicyDenied, utcPtr(now)
			code, allowed = "ACTION_POLICY_DENIED", false
		case VerdictRequireApproval:
			op.Status = OpAwaitingApproval
			code = "ACTION_APPROVAL_REQUIRED"
		default:
			op.Status = OpAuthorized
		}
		var ap *Approval
		if verdict.Outcome == VerdictRequireApproval {
			ap = &Approval{
				ID: s.newID("apr"), OperationRef: op.Ref, SubjectDigest: digest, RuleID: verdict.RuleID, Groups: verdict.ApproverGroups,
				Status: ApprovalPending, ExpiresAt: now.Add(s.Policy.ExpiresAfter), CreatedAt: now, Version: 1,
			}
			op.ApprovalID = ap.ID
		}
		if err := insertOperation(ctx, tx, op); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				// Lost a race with an identical establish; the winner's row is
				// authoritative. Retry the read path.
				return &Error{Code: CodeStoreUnavailable, Message: "concurrent establish; retry", Err: err}
			}
			return &Error{Code: CodeStoreUnavailable, Message: "inserting operation", Err: err}
		}
		if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{Event: evidence.ActionEventOperationEstablished}, allowed, reasons, code); err != nil {
			return err
		}
		if ap != nil {
			if err := insertApproval(ctx, tx, ap); err != nil {
				return &Error{Code: CodeStoreUnavailable, Message: "inserting approval", Err: err}
			}
			if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{
				Event: evidence.ActionEventApprovalRequested, ApprovalID: ap.ID, ApprovalStatus: ap.Status,
				ApproverGroups: ap.Groups, ApprovalExpires: ap.ExpiresAt.Format(time.RFC3339),
			}, true, []string{"exact approval subject persisted; zero dispatch until an authorized reviewer approves and the runtime claims an attempt"}, "ACTION_APPROVAL_REQUESTED"); err != nil {
				return err
			}
		}
		if ok, err := updateOperation(ctx, tx, op, 1); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "finalizing operation", Err: err}
		}
		result = &EstablishResult{Operation: projectionOf(op, ap, nil, def), Created: true}
		return nil
	})
	if err != nil {
		var de *Error
		if errors.As(err, &de) && de.Code == CodeStoreUnavailable && strings.Contains(de.Message, "concurrent establish") {
			// One retry resolves the identical-race case deterministically.
			return s.Establish(ctx, req)
		}
		return nil, err
	}
	return result, nil
}

// operationDigest binds tenant, agent, action identity, complete
// canonical arguments, schema, binding profile, approval-relevant policy,
// execution profile and material destination (#427).
func (s *Service) operationDigest(def *Definition, canonical []byte) string {
	parts := []string{
		"tenant=" + s.TenantID, "agent=" + s.AgentID, "action=" + def.Name,
		"args=" + Digest(canonical), "schema=" + def.SchemaDigest, "binding=" + def.BindingProfile,
		"policy=" + s.Policy.Digest, "profile=" + def.ExecutionProfile, "destination=" + def.DestinationID,
	}
	return Digest([]byte(strings.Join(parts, "\n")))
}

func (s *Service) project(ctx context.Context, q querier, op *Operation) (*Projection, error) {
	var ap *Approval
	if op.ApprovalID != "" {
		a, err := getApproval(ctx, q, op.ApprovalID)
		if err != nil {
			return nil, &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
		}
		ap = a
	}
	at, err := latestAttempt(ctx, q, op.Ref)
	if err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "reading attempt", Err: err}
	}
	def, _ := s.Catalog.Lookup(op.Action)
	return projectionOf(op, ap, at, def), nil
}

// Get returns the safe projection of a scoped operation.
func (s *Service) Get(ctx context.Context, operationID string) (*Projection, error) {
	op, err := getOperation(ctx, s.repo.db, s.TenantID, s.AgentID, operationID)
	if err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "reading operation", Err: err}
	}
	if op == nil {
		return nil, newErr(CodeNotFound, "operation not found in this AI use case")
	}
	return s.project(ctx, s.repo.db, op)
}

// GetApproval returns the safe projection of an approval owned by this
// agent, plus its operation.
func (s *Service) GetApproval(ctx context.Context, approvalID string) (*Projection, error) {
	ap, err := getApproval(ctx, s.repo.db, approvalID)
	if err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
	}
	if ap == nil {
		return nil, newErr(CodeNotFound, "approval not found")
	}
	op, err := getOperationByRef(ctx, s.repo.db, ap.OperationRef)
	if err != nil || op == nil || op.TenantID != s.TenantID || op.AgentID != s.AgentID {
		return nil, newErr(CodeNotFound, "approval not found")
	}
	return s.project(ctx, s.repo.db, op)
}

// ---- Decide ----------------------------------------------------------

// DecideRequest is an authenticated reviewer's decision.
type DecideRequest struct {
	ApprovalID string
	Approve    bool
	Reason     string
	Reviewer   ReviewerPrincipal
}

// Decide commits one immutable decision on a pending approval. It never
// dispatches, never resumes, and never changes the exact subject. Exactly
// one concurrent decision wins.
func (s *Service) Decide(ctx context.Context, req DecideRequest) (*Projection, error) {
	if strings.TrimSpace(req.Reviewer.Name) == "" || strings.TrimSpace(req.Reviewer.Group) == "" {
		return nil, newErr(CodeApprovalNotAuthorized, "an authenticated approver principal with a group is required")
	}
	if len(req.Reason) > 1024 {
		return nil, newErr(CodeInvalidRequest, "reason exceeds 1024 characters")
	}
	if !req.Approve && strings.TrimSpace(req.Reason) == "" {
		return nil, newErr(CodeInvalidRequest, "a rejection requires a reason")
	}
	var out *Projection
	err := s.repo.withTx(ctx, func(tx *sql.Tx) error {
		ap, err := getApproval(ctx, tx, req.ApprovalID)
		if err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
		}
		if ap == nil {
			return newErr(CodeNotFound, "approval not found")
		}
		op, err := getOperationByRef(ctx, tx, ap.OperationRef)
		if err != nil || op == nil || op.TenantID != s.TenantID || op.AgentID != s.AgentID {
			return newErr(CodeNotFound, "approval not found")
		}
		if !containsString(ap.Groups, req.Reviewer.Group) {
			// Evidenced refusal; state unchanged.
			op.Version++
			op.UpdatedAt = s.now()
			if ok, err := updateOperation(ctx, tx, op, op.Version-1); err != nil || !ok {
				return &Error{Code: CodeStoreUnavailable, Message: "recording refusal", Err: err}
			}
			if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{
				Event: evidence.ActionEventAuthorizationRefused, ApprovalID: ap.ID, ApprovalStatus: ap.Status,
				ApproverGroups: ap.Groups, ReviewerPrincipal: req.Reviewer.Name, ReviewerGroup: req.Reviewer.Group, RefusalCode: CodeApprovalNotAuthorized,
			},
				false, []string{"reviewer group is not an approver group of the matched rule"}, "ACTION_APPROVAL_NOT_AUTHORIZED"); err != nil {
				return err
			}
			if _, err := updateOperation(ctx, tx, op, op.Version); err != nil {
				return &Error{Code: CodeStoreUnavailable, Message: "recording refusal", Err: err}
			}
			return refusal(newErr(CodeApprovalNotAuthorized, "reviewer is not in an approver group for this rule"))
		}
		now := s.now()
		if ap.Status == ApprovalPending && !now.Before(ap.ExpiresAt) {
			return s.expireApproval(ctx, tx, op, ap, now)
		}
		if ap.Status != ApprovalPending {
			proj, _ := s.project(ctx, tx, op)
			return &Error{Code: CodeApprovalAlreadyDecided, Message: "approval is " + ap.Status, State: proj}
		}
		ap.Status = ApprovalRejected
		if req.Approve {
			ap.Status = ApprovalApproved
		}
		ap.DecidedAt, ap.DecidedBy, ap.DecidedGroup, ap.Reason = utcPtr(now), req.Reviewer.Name, req.Reviewer.Group, req.Reason
		ap.Version++
		won, err := decideApproval(ctx, tx, ap, ap.Version-1)
		if err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "committing decision", Err: err}
		}
		if !won {
			proj, _ := s.project(ctx, tx, op)
			return &Error{Code: CodeApprovalAlreadyDecided, Message: "a concurrent decision was committed first", State: proj}
		}
		prev := op.Version
		op.Version++
		op.UpdatedAt = now
		if req.Approve {
			op.Status = OpAuthorized
		} else {
			op.Status, op.OutcomeCode, op.TerminalAt = OpCancelled, CodeApprovalRejected, utcPtr(now)
		}
		if ok, err := updateOperation(ctx, tx, op, prev); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "updating operation after decision", Err: err}
		}
		code := "ACTION_APPROVAL_REJECTED"
		if req.Approve {
			code = "ACTION_APPROVAL_APPROVED"
		}
		if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{
			Event: evidence.ActionEventApprovalDecided, ApprovalID: ap.ID, ApprovalStatus: ap.Status,
			ApproverGroups: ap.Groups, ApprovalExpires: ap.ExpiresAt.Format(time.RFC3339), ReviewerPrincipal: ap.DecidedBy, ReviewerGroup: ap.DecidedGroup, DecisionReason: ap.Reason,
		},
			req.Approve, []string{"reviewer decision committed; decision performs no dispatch — the runtime must claim an attempt"}, code); err != nil {
			return err
		}
		if _, err := updateOperation(ctx, tx, op, op.Version); err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "finalizing decision", Err: err}
		}
		def, _ := s.Catalog.Lookup(op.Action)
		out = projectionOf(op, ap, nil, def)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) expireApproval(ctx context.Context, tx *sql.Tx, op *Operation, ap *Approval, now time.Time) error {
	ap.Status = ApprovalExpired
	ap.DecidedAt = utcPtr(now)
	ap.DecidedBy, ap.DecidedGroup = "system", "system"
	ap.Version++
	if won, err := decideApproval(ctx, tx, ap, ap.Version-1); err != nil || !won {
		return &Error{Code: CodeStoreUnavailable, Message: "expiring approval", Err: err}
	}
	prev := op.Version
	op.Version++
	op.UpdatedAt = now
	op.Status, op.OutcomeCode, op.TerminalAt = OpCancelled, CodeApprovalExpired, utcPtr(now)
	if ok, err := updateOperation(ctx, tx, op, prev); err != nil || !ok {
		return &Error{Code: CodeStoreUnavailable, Message: "expiring operation", Err: err}
	}
	if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{
		Event: evidence.ActionEventApprovalDecided, ApprovalID: ap.ID, ApprovalStatus: ap.Status,
		ApproverGroups: ap.Groups, ApprovalExpires: ap.ExpiresAt.Format(time.RFC3339), ReviewerPrincipal: "system", ReviewerGroup: "system",
	},
		false, []string{"approval lifetime elapsed before a decision; system expiry, not a human decision"}, "ACTION_APPROVAL_EXPIRED"); err != nil {
		return err
	}
	if _, err := updateOperation(ctx, tx, op, op.Version); err != nil {
		return &Error{Code: CodeStoreUnavailable, Message: "expiring operation", Err: err}
	}
	proj, _ := s.project(ctx, tx, op)
	return refusal(&Error{Code: CodeApprovalExpired, Message: "approval expired before a decision", State: proj})
}

// ---- Execute ---------------------------------------------------------

// ExecuteResult is the outcome of one claim + dispatch.
type ExecuteResult struct {
	Operation *Projection
	Attempt   *AttemptProjection
}

// Execute is the runtime/controller resumption: revalidate the exact
// operation against CURRENT catalog/policy, claim ONE attempt (committed
// before any effect), mark the dispatch boundary, dispatch once through
// the trusted dispatcher, and record the observed result or UNKNOWN.
// Nothing here is reachable from a reviewer decision.
func (s *Service) Execute(ctx context.Context, operationID string) (*ExecuteResult, error) {
	var op *Operation
	var at *Attempt
	var def *Definition
	// Phase 1: authorization usability + attempt claim, one transaction.
	err := s.repo.withTx(ctx, func(tx *sql.Tx) error {
		cur, err := getOperation(ctx, tx, s.TenantID, s.AgentID, operationID)
		if err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "reading operation", Err: err}
		}
		if cur == nil {
			return newErr(CodeNotFound, "operation not found in this AI use case")
		}
		op = cur
		if op.Status == OpAwaitingApproval && op.ApprovalID != "" {
			ap, err := getApproval(ctx, tx, op.ApprovalID)
			if err != nil || ap == nil {
				return &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
			}
			if ap.Status == ApprovalPending && !s.now().Before(ap.ExpiresAt) {
				return s.expireApproval(ctx, tx, op, ap, s.now())
			}
		}
		if code, msg := s.claimBlocker(op); code != "" {
			proj, _ := s.project(ctx, tx, op)
			return &Error{Code: code, Message: msg, State: proj}
		}
		d, ok := s.Catalog.Lookup(op.Action)
		if !ok || d.SchemaDigest != op.SchemaDigest || d.DestinationID != op.DestinationID || d.ExecutionProfile != op.ExecutionProfile {
			return s.refuse(ctx, tx, op, CodeApprovalBindingStale, "the trusted catalog definition changed since this operation was bound; establish a new operation")
		}
		def = d
		current := s.Policy.Evaluate(op.Action)
		if current.Outcome == VerdictDeny {
			return s.refuse(ctx, tx, op, CodePolicyDenied, "current policy denies this action; a prior authorization cannot be used")
		}
		var ap *Approval
		if op.ApprovalID != "" {
			ap, err = getApproval(ctx, tx, op.ApprovalID)
			if err != nil || ap == nil {
				return &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
			}
		}
		if current.Outcome == VerdictRequireApproval || op.Verdict == VerdictRequireApproval {
			if ap == nil || ap.Status != ApprovalApproved || ap.SubjectDigest != op.Digest {
				return s.refuse(ctx, tx, op, CodeApprovalRequired, "no usable approved decision binds this exact operation under current policy")
			}
			if s.Policy.Digest != op.PolicyDigest {
				return s.refuse(ctx, tx, op, CodeApprovalBindingStale, "approval-relevant policy changed since the approval was granted; a new approval cycle is required")
			}
			if op.AttemptCount == 0 && !s.now().Before(ap.ExpiresAt) {
				return s.refuse(ctx, tx, op, CodeApprovalExpired, "approved decision expired before the first attempt")
			}
		}
		now := s.now()
		prev := op.Version
		op.Version++
		op.Status = OpExecuting
		op.AttemptCount++
		op.UpdatedAt = now
		if ok, err := updateOperation(ctx, tx, op, prev); err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "claiming attempt", Err: err}
		} else if !ok {
			proj, _ := s.project(ctx, tx, op)
			return &Error{Code: CodeAttemptAlreadyInProgress, Message: "another claim won the race for this operation", State: proj}
		}
		at = &Attempt{ID: s.newID("att"), OperationRef: op.Ref, Ordinal: op.AttemptCount, Status: AttemptStarted, IdempotencyKey: op.IdempotencyKey, StartedAt: now}
		if err := insertAttempt(ctx, tx, at); err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "inserting attempt", Err: err}
		}
		if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{
			Event: evidence.ActionEventAttemptClaimed, AttemptID: at.ID, AttemptOrdinal: at.Ordinal, AttemptStatus: at.Status,
			IdempotencyKey: at.IdempotencyKey, DispatchBoundary: op.ExecutionProfile, ApprovalID: op.ApprovalID, ApprovalStatus: approvalStatus(ap),
		},
			true, []string{"current catalog/policy revalidated; exactly one attempt claimed before any effect"}, "ACTION_ATTEMPT_CLAIMED"); err != nil {
			return err
		}
		if _, err := updateOperation(ctx, tx, op, op.Version); err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "finalizing claim", Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Phase 2: dispatch marker, committed BEFORE the request leaves. A crash
	// after this point recovers as UNKNOWN, never as "not sent".
	err = s.repo.withTx(ctx, func(tx *sql.Tx) error {
		at.DispatchedAt, at.DispatchObserved = utcPtr(s.now()), true
		if ok, err := updateAttempt(ctx, tx, at); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "marking dispatch boundary", Err: err}
		}
		prev := op.Version
		op.Version++
		op.UpdatedAt = s.now()
		if ok, err := updateOperation(ctx, tx, op, prev); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "marking dispatch boundary", Err: err}
		}
		if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{
			Event: evidence.ActionEventAttemptDispatched, AttemptID: at.ID, AttemptOrdinal: at.Ordinal, AttemptStatus: at.Status,
			IdempotencyKey: at.IdempotencyKey, DispatchBoundary: op.ExecutionProfile, DispatchObserved: true,
		},
			true, []string{"dispatch boundary marked; the downstream request is about to leave Talon"}, "ACTION_ATTEMPT_DISPATCHED"); err != nil {
			return err
		}
		_, err := updateOperation(ctx, tx, op, op.Version)
		return err
	})
	if err != nil {
		// The marker did not commit: nothing was sent. Leave the attempt
		// `started` for recovery (→ failed/not_dispatched at next start).
		return nil, err
	}

	outcome := s.dispatcher.Dispatch(ctx, DispatchRequest{Definition: def, Payload: op.Payload, OperationRef: op.Ref, AttemptID: at.ID, IdempotencyKey: at.IdempotencyKey})
	return s.complete(ctx, op, at, outcome)
}

func (s *Service) complete(ctx context.Context, op *Operation, at *Attempt, outcome Outcome) (*ExecuteResult, error) {
	var out *ExecuteResult
	err := s.repo.withTx(ctx, func(tx *sql.Tx) error {
		now := s.now()
		at.Status, at.CompletedAt, at.ResultProvenance, at.OutcomeCode, at.OutcomeRef = outcome.Status, utcPtr(now), outcome.Provenance, outcome.Code, outcome.Ref
		if ok, err := updateAttempt(ctx, tx, at); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "completing attempt", Err: err}
		}
		prev := op.Version
		op.Version++
		op.UpdatedAt = now
		op.OutcomeProvenance, op.OutcomeCode = outcome.Provenance, outcome.Code
		allowed := true
		code := "ACTION_ATTEMPT_SUCCEEDED"
		reason := "downstream result observed by Talon"
		switch outcome.Status {
		case AttemptSucceeded:
			op.Status, op.TerminalAt = OpSucceeded, utcPtr(now)
		case AttemptUnknown:
			op.Status, op.TerminalAt = OpUnknown, utcPtr(now)
			code, allowed, reason = "ACTION_ATTEMPT_UNKNOWN", false, "the request may have reached the destination but no reliable outcome was observed; automatic retry is blocked"
		default:
			op.Status = OpFailed
			code, allowed, reason = "ACTION_ATTEMPT_FAILED", false, "known failure; the unchanged operation may be retried by an explicit new claim"
			if !outcome.Dispatched {
				reason = "the request never left Talon; the unchanged operation may be retried by an explicit new claim"
			}
		}
		if ok, err := updateOperation(ctx, tx, op, prev); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "completing operation", Err: err}
		}
		if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{
			Event: evidence.ActionEventAttemptCompleted, AttemptID: at.ID, AttemptOrdinal: at.Ordinal, AttemptStatus: at.Status,
			IdempotencyKey: at.IdempotencyKey, DispatchBoundary: op.ExecutionProfile, DispatchObserved: at.DispatchObserved, ResultProvenance: at.ResultProvenance,
			OutcomeCode: at.OutcomeCode, OutcomeRef: at.OutcomeRef,
		}, allowed, []string{reason}, code); err != nil {
			return err
		}
		if _, err := updateOperation(ctx, tx, op, op.Version); err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "finalizing completion", Err: err}
		}
		proj, err := s.project(ctx, tx, op)
		if err != nil {
			return err
		}
		out = &ExecuteResult{Operation: proj, Attempt: proj.LatestAttempt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// claimBlocker maps a non-claimable operation status to its stable code.
func (s *Service) claimBlocker(op *Operation) (string, string) {
	switch op.Status {
	case OpDenied:
		return CodePolicyDenied, "policy denied this operation; approval cannot override it"
	case OpAwaitingApproval:
		return CodeApprovalPending, "approval is pending; no attempt may be claimed"
	case OpSucceeded:
		return CodeOperationAlreadySucceeded, "the operation already succeeded; a successful logical operation is permanently closed"
	case OpUnknown:
		return CodeOperationOutcomeUnknown, "a prior attempt has an unknown outcome; automatic retry is blocked until an authorized reconciliation"
	case OpExecuting:
		return CodeAttemptAlreadyInProgress, "an attempt is already in progress"
	case OpCancelled:
		if op.OutcomeCode == CodeApprovalExpired {
			return CodeApprovalExpired, "approval expired"
		}
		return CodeApprovalRejected, "the reviewer rejected this operation"
	}
	return "", ""
}

// refuse records an authorization refusal (state otherwise unchanged) and
// returns the domain error.
func (s *Service) refuse(ctx context.Context, tx *sql.Tx, op *Operation, code, msg string) error {
	prev := op.Version
	op.Version++
	op.UpdatedAt = s.now()
	if ok, err := updateOperation(ctx, tx, op, prev); err != nil || !ok {
		return &Error{Code: CodeStoreUnavailable, Message: "recording refusal", Err: err}
	}
	if err := s.commit(ctx, tx, op, &evidence.ActionLifecycle{Event: evidence.ActionEventAuthorizationRefused, ApprovalID: op.ApprovalID, RefusalCode: code},
		false, []string{msg}, "ACTION_AUTHORIZATION_REFUSED"); err != nil {
		return err
	}
	if _, err := updateOperation(ctx, tx, op, op.Version); err != nil {
		return &Error{Code: CodeStoreUnavailable, Message: "recording refusal", Err: err}
	}
	proj, _ := s.project(ctx, tx, op)
	return refusal(&Error{Code: code, Message: msg, State: proj})
}

// RecoverInterrupted closes attempts left `started` by a crash: dispatched
// → UNKNOWN (the effect may exist), not dispatched → failed/not_dispatched
// (safe to retry). Called once at service construction; no attempt is in
// flight at process start, so every such row is orphaned.
func (s *Service) RecoverInterrupted(ctx context.Context) (int, error) {
	orphans, err := s.repo.orphanedAttempts(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, at := range orphans {
		op, err := getOperationByRef(ctx, s.repo.db, at.OperationRef)
		if err != nil || op == nil || op.TenantID != s.TenantID || op.AgentID != s.AgentID {
			continue
		}
		outcome := Outcome{Status: AttemptFailed, Provenance: ResultProvenanceNotDispatched, Code: "interrupted_before_dispatch"}
		if at.DispatchObserved {
			outcome = Outcome{Status: AttemptUnknown, Dispatched: true, Provenance: ResultProvenanceUnknown, Code: "interrupted_after_dispatch"}
		}
		if _, err := s.complete(ctx, op, at, outcome); err != nil {
			log.Warn().Err(err).Str("operation_ref", op.Ref).Msg("action_recovery_failed")
			continue
		}
		n++
	}
	return n, nil
}

func approvalStatus(ap *Approval) string {
	if ap == nil {
		return ""
	}
	return ap.Status
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ListLifecycle returns the operation's evidence chain in sequence order.
func (s *Service) ListLifecycle(ctx context.Context, operationID string) ([]*evidence.Evidence, error) {
	op, err := getOperation(ctx, s.repo.db, s.TenantID, s.AgentID, operationID)
	if err != nil {
		return nil, err
	}
	if op == nil {
		return nil, fmt.Errorf("operation not found")
	}
	return s.evidence.ListByCorrelationID(ctx, op.Ref)
}

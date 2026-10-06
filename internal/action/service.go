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
// repository, evidence in the evidence store, effects in the dispatcher,
// active payloads sealed by the cryptor.
type Service struct {
	TenantID string
	AgentID  string
	Catalog  *Catalog
	Policy   *ApprovalPolicy

	repo       *Repository
	evidence   *evidence.Store
	dispatcher Dispatcher
	cryptor    *PayloadCryptor
	now        func() time.Time
	newID      func(prefix string) string

	// crash-injection hooks (tests only): a hook that panics simulates a
	// process crash at that exact point after the preceding commit.
	hookAfterClaim     func()
	hookAfterArm       func()
	hookBeforeComplete func(Outcome)
}

// NewService wires the domain for one agent. The repository must live in
// the evidence store's database (NewRepository(evStore.DB())). A payload
// cryptor is mandatory: without it no operation can be established.
func NewService(tenantID, agentID string, catalog *Catalog, policy *ApprovalPolicy, repo *Repository, evStore *evidence.Store, dispatcher Dispatcher, cryptor *PayloadCryptor) (*Service, error) {
	if catalog == nil || policy == nil || repo == nil || evStore == nil || dispatcher == nil || cryptor == nil {
		return nil, errors.New("action service: catalog, policy, repository, evidence store, dispatcher and payload cryptor are required")
	}
	if tenantID == "" {
		tenantID = "default"
	}
	return &Service{
		TenantID: tenantID, AgentID: agentID, Catalog: catalog, Policy: policy,
		repo: repo, evidence: evStore, dispatcher: dispatcher, cryptor: cryptor,
		now: func() time.Time { return time.Now().UTC() },
		newID: func(prefix string) string {
			return prefix + "_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:20]
		},
	}, nil
}

var operationIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ReviewerPrincipal is the AUTHENTICATED, tenant-scoped human approver
// (#428). Everything here comes from trusted identity state, never from
// a request body or header.
type ReviewerPrincipal struct {
	PrincipalID       string
	TenantScope       string
	Subject           string
	Groups            []string
	CredentialID      string
	CredentialVersion int
	// Revalidate rechecks active/not-revoked state inside the decision
	// transaction. nil = no recheck possible (treated as inactive).
	Revalidate func(ctx context.Context) (bool, error)
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
	ev.DefinitionDigest, ev.ProjectionDigest = op.DefinitionDigest, op.ProjectionDigest
	ev.BindingProfile, ev.ExecutionProfile, ev.DestinationID = op.BindingProfile, op.ExecutionProfile, op.DestinationID
	ev.IdentitySource, ev.Verdict, ev.MatchedRuleID, ev.OperationStatus = op.IdentitySource, op.Verdict, op.RuleID, op.Status
	decision := explanation.DecisionAllow
	if !allowed {
		decision = explanation.DecisionDeny
	}
	stage := explanation.StagePreExecution
	switch ev.Event {
	case evidence.ActionEventAttemptArmed, evidence.ActionEventAttemptCompleted:
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

// statusForEvent maps the operation state to the generic evidence status.
// Every lifecycle record carries an explicit value: the generic vocabulary
// treats an EMPTY status as "completed" (backward-compatible default), so
// an in-flight, cancelled or — above all — unknown operation must never be
// serialized without one.
func statusForEvent(op *Operation) string {
	switch op.Status {
	case OpDenied:
		return evidence.StatusDenied
	case OpSucceeded:
		return evidence.StatusCompleted
	case OpFailed:
		return evidence.StatusFailed
	case OpUnknown:
		return evidence.StatusUnknown
	case OpCancelled:
		return evidence.StatusCancelled
	case OpExecuting:
		return evidence.StatusRunning
	default: // authorized, awaiting_approval: accepted, no effect yet
		return evidence.StatusQueued
	}
}

// commit writes the record through the transaction's evidence writer and
// bumps the operation sequence in memory (the caller persists the
// operation row in the same tx).
func (s *Service) commit(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, op *Operation, ev *evidence.ActionLifecycle, allowed bool, reasons []string, code string) error {
	op.Sequence++
	ev.Sequence = op.Sequence
	rec := s.lifecycleRecord(op, ev, allowed, reasons, code)
	if err := w.Store(ctx, tx, rec); err != nil {
		return &Error{Code: CodeStoreUnavailable, Message: "committing lifecycle evidence", Err: err}
	}
	return nil
}

// bump applies a version-guarded operation update; false means a
// concurrent writer won.
func bump(ctx context.Context, tx *sql.Tx, op *Operation, now time.Time) (bool, error) {
	prev := op.Version
	op.Version++
	op.UpdatedAt = now
	return updateOperation(ctx, tx, op, prev)
}

// finalize persists the sequence/status after evidence was written.
func finalize(ctx context.Context, tx *sql.Tx, op *Operation) error {
	if _, err := updateOperation(ctx, tx, op, op.Version); err != nil {
		return &Error{Code: CodeStoreUnavailable, Message: "finalizing operation", Err: err}
	}
	return nil
}

// ---- Establish -------------------------------------------------------

// Establish validates, binds and persists one exact operation, evaluating
// the authoritative verdict. It performs zero dispatch.
func (s *Service) Establish(ctx context.Context, req EstablishRequest) (*EstablishResult, error) {
	plan, err := s.prepareEstablish(req)
	if err != nil {
		return nil, err
	}
	var result *EstablishResult
	err = s.repo.withTx(ctx, s.evidence, func(tx *sql.Tx, w *evidence.TxWriter) error {
		existing, err := getOperation(ctx, tx, s.TenantID, s.AgentID, plan.opID)
		if err != nil {
			return &Error{Code: CodeStoreUnavailable, Message: "reading operation", Err: err}
		}
		if existing != nil {
			proj, err := s.reuseOrConflict(ctx, tx, w, existing, plan.digest)
			if err != nil {
				return err
			}
			result = &EstablishResult{Operation: proj, Created: false}
			return nil
		}
		proj, err := s.insertNewOperation(ctx, tx, w, plan)
		if err != nil {
			return err
		}
		result = &EstablishResult{Operation: proj, Created: true}
		return nil
	})
	if err != nil {
		var de *Error
		if errors.As(err, &de) && de.Code == CodeStoreUnavailable && strings.Contains(de.Message, "concurrent establish") {
			return s.Establish(ctx, req)
		}
		return nil, err
	}
	return result, nil
}

// establishPlan is everything decided BEFORE the transaction: validated
// input, canonical payload, exact digest, verdict and reviewer projection.
type establishPlan struct {
	opID           string
	def            *Definition
	canonical      []byte
	digest         string
	verdict        Verdict
	reviewJSON     []byte
	identitySource string
}

func (s *Service) prepareEstablish(req EstablishRequest) (*establishPlan, error) {
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
	if def.Destination.Type != DestinationTypeHTTP {
		// Fail closed before any binding: an mcp-sourced definition is
		// catalogued and inspectable, but no executor for it exists on
		// this adapter until #431 routes MCP tools/call through here.
		return nil, newErr(CodeExecutionUnsupported, "this adapter cannot execute an action sourced from an MCP source (destination type "+def.Destination.Type+"); MCP execution convergence is not shipped")
	}
	args := req.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	canonical, err := Canonicalize(args)
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
	reviewJSON, _ := json.Marshal(def.ReviewProjection(canonical))
	return &establishPlan{
		opID: opID, def: def, canonical: canonical, digest: s.operationDigest(def, canonical),
		verdict: s.Policy.Evaluate(def.Name), reviewJSON: reviewJSON, identitySource: identitySource,
	}, nil
}

// reuseOrConflict handles an operation id that already exists: same digest
// returns the canonical state; a different digest records a conflict on
// the EXISTING operation and mutates nothing else.
func (s *Service) reuseOrConflict(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, existing *Operation, digest string) (*Projection, error) {
	if existing.Digest == digest {
		return s.project(ctx, tx, existing)
	}
	if ok, err := bump(ctx, tx, existing, s.now()); err != nil || !ok {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "recording conflict", Err: err}
	}
	if err := s.commit(ctx, tx, w, existing, &evidence.ActionLifecycle{Event: evidence.ActionEventOperationConflict, RefusalCode: CodeOperationConflict},
		false, []string{"same operation_id presented with a different material payload; existing digest retained"}, "ACTION_OPERATION_CONFLICT"); err != nil {
		return nil, err
	}
	if err := finalize(ctx, tx, existing); err != nil {
		return nil, err
	}
	proj, _ := s.project(ctx, tx, existing)
	return nil, refusal(&Error{Code: CodeOperationConflict, Message: "operation_id already bound to a different material payload; use a new operation_id for a corrected action", State: proj})
}

// insertNewOperation persists a new operation under its verdict, seals the
// payload (never for a denied operation) and writes the establishing —
// and, when required, approval-requested — records.
func (s *Service) insertNewOperation(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, plan *establishPlan) (*Projection, error) {
	now := s.now()
	def, verdict := plan.def, plan.verdict
	op := &Operation{
		Ref: s.newID("op"), TenantID: s.TenantID, AgentID: s.AgentID, OperationID: plan.opID, Action: def.Name,
		Digest: plan.digest, SchemaDigest: def.SchemaDigest, DefinitionDigest: def.DefinitionDigest, ProjectionDigest: def.ProjectionDigest,
		PolicyDigest: s.Policy.Digest, CatalogDigest: s.Catalog.Digest,
		ExecutionProfile: def.ExecutionProfile, BindingProfile: def.BindingProfile, DestinationID: def.DestinationID,
		IdentitySource: plan.identitySource, Verdict: verdict.Outcome, RuleID: verdict.RuleID, Version: 1, ReviewJSON: plan.reviewJSON,
		CreatedAt: now, UpdatedAt: now,
	}
	op.IdempotencyKey = "talon-" + op.Ref
	code, allowed := "ACTION_AUTHORIZED", true
	switch verdict.Outcome {
	case VerdictDeny:
		op.Status, op.OutcomeCode, op.TerminalAt = OpDenied, CodePolicyDenied, utcPtr(now)
		code, allowed = "ACTION_POLICY_DENIED", false
	case VerdictRequireApproval:
		op.Status, code = OpAwaitingApproval, "ACTION_APPROVAL_REQUIRED"
	default:
		op.Status = OpAuthorized
	}
	var ap *Approval
	if verdict.Outcome == VerdictRequireApproval {
		ap = &Approval{
			ID: s.newID("apr"), OperationRef: op.Ref, SubjectDigest: plan.digest, RuleID: verdict.RuleID, Groups: verdict.ApproverGroups,
			Status: ApprovalPending, ExpiresAt: now.Add(s.Policy.ExpiresAfter), CreatedAt: now, Version: 1,
		}
		op.ApprovalID = ap.ID
	}
	if err := insertOperation(ctx, tx, op); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, &Error{Code: CodeStoreUnavailable, Message: "concurrent establish; retry", Err: err}
		}
		return nil, &Error{Code: CodeStoreUnavailable, Message: "inserting operation", Err: err}
	}
	if verdict.Outcome != VerdictDeny {
		if err := insertPayload(ctx, tx, s.cryptor, op.Ref, op.Digest, plan.canonical, now); err != nil {
			return nil, &Error{Code: CodeStoreUnavailable, Message: "sealing active payload", Err: err}
		}
	}
	if err := s.commit(ctx, tx, w, op, &evidence.ActionLifecycle{Event: evidence.ActionEventOperationEstablished}, allowed, []string{verdict.Reason}, code); err != nil {
		return nil, err
	}
	if ap != nil {
		if err := insertApproval(ctx, tx, ap); err != nil {
			return nil, &Error{Code: CodeStoreUnavailable, Message: "inserting approval", Err: err}
		}
		if err := s.commit(ctx, tx, w, op, &evidence.ActionLifecycle{
			Event: evidence.ActionEventApprovalRequested, ApprovalID: ap.ID, ApprovalStatus: ap.Status,
			ApproverGroups: ap.Groups, ApprovalExpires: ap.ExpiresAt.Format(time.RFC3339),
		}, true, []string{"exact approval subject persisted; zero dispatch until an authorized reviewer approves and the runtime claims an attempt"}, "ACTION_APPROVAL_REQUESTED"); err != nil {
			return nil, err
		}
	}
	if ok, err := updateOperation(ctx, tx, op, 1); err != nil || !ok {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "finalizing operation", Err: err}
	}
	return projectionOf(op, ap, nil, payloadState(ctx, tx, op.Ref)), nil
}

// operationDigest binds tenant, agent, complete canonical arguments and
// the COMPLETE trusted definition identity (schema, projection,
// destination + success contract, execution/binding profiles) plus the
// approval-relevant policy (#427).
func (s *Service) operationDigest(def *Definition, canonical []byte) string {
	parts := []string{
		"tenant=" + s.TenantID, "agent=" + s.AgentID, "action=" + def.Name,
		"args=" + Digest(canonical), "definition=" + def.DefinitionDigest, "policy=" + s.Policy.Digest,
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
	return projectionOf(op, ap, at, payloadState(ctx, q, op.Ref)), nil
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

// definitionCurrent reports whether the trusted definition bound at
// establish is still the active one.
func (s *Service) definitionCurrent(op *Operation) bool {
	d, ok := s.Catalog.Lookup(op.Action)
	return ok && d.DefinitionDigest == op.DefinitionDigest
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
// one concurrent decision wins. Authorization = tenant scope match AND a
// group of the matched rule AND an active principal/credential, rechecked
// inside the transaction.
func (s *Service) Decide(ctx context.Context, req DecideRequest) (*Projection, error) {
	if err := validateDecideRequest(req); err != nil {
		return nil, err
	}
	var out *Projection
	err := s.repo.withTx(ctx, s.evidence, func(tx *sql.Tx, w *evidence.TxWriter) error {
		ap, op, err := s.loadScopedApproval(ctx, tx, req.ApprovalID)
		if err != nil {
			return err
		}
		group, err := s.authorizeReviewer(ctx, tx, w, op, ap, req.Reviewer)
		if err != nil {
			return err
		}
		now := s.now()
		if ap.Status == ApprovalPending && !now.Before(ap.ExpiresAt) {
			return s.closeApproval(ctx, tx, w, op, ap, ApprovalExpired, CodeApprovalExpired, "approval lifetime elapsed before a decision; system expiry, not a human decision", "ACTION_APPROVAL_EXPIRED", now)
		}
		if ap.Status == ApprovalPending && !s.definitionCurrent(op) {
			return s.closeApproval(ctx, tx, w, op, ap, ApprovalInvalidated, CodeApprovalBindingStale, "the trusted action definition (schema/projection/destination/success contract) changed since the subject was bound; the pending approval is invalidated — establish a new operation", "ACTION_APPROVAL_INVALIDATED", now)
		}
		if ap.Status != ApprovalPending {
			proj, _ := s.project(ctx, tx, op)
			return &Error{Code: CodeApprovalAlreadyDecided, Message: "approval is " + ap.Status, State: proj}
		}
		proj, err := s.commitDecision(ctx, tx, w, op, ap, req, group, now)
		if err != nil {
			return err
		}
		out = proj
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func validateDecideRequest(req DecideRequest) error {
	rv := req.Reviewer
	if strings.TrimSpace(rv.PrincipalID) == "" || strings.TrimSpace(rv.TenantScope) == "" || len(rv.Groups) == 0 {
		return newErr(CodeApprovalNotAuthorized, "an authenticated, tenant-scoped approver principal with groups is required")
	}
	if len(req.Reason) > 1024 {
		return newErr(CodeInvalidRequest, "reason exceeds 1024 characters")
	}
	if !req.Approve && strings.TrimSpace(req.Reason) == "" {
		return newErr(CodeInvalidRequest, "a rejection requires a reason")
	}
	return nil
}

// loadScopedApproval loads an approval and its operation, scoped to this
// service's tenant/agent (anything else is not found).
func (s *Service) loadScopedApproval(ctx context.Context, tx *sql.Tx, approvalID string) (*Approval, *Operation, error) {
	ap, err := getApproval(ctx, tx, approvalID)
	if err != nil {
		return nil, nil, &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
	}
	if ap == nil {
		return nil, nil, newErr(CodeNotFound, "approval not found")
	}
	op, err := getOperationByRef(ctx, tx, ap.OperationRef)
	if err != nil || op == nil || op.TenantID != s.TenantID || op.AgentID != s.AgentID {
		return nil, nil, newErr(CodeNotFound, "approval not found")
	}
	return ap, op, nil
}

// reviewerFacts renders the reviewer identity for evidence (never a token).
func reviewerFacts(ap *Approval, rv ReviewerPrincipal, group string) *evidence.ActionLifecycle {
	return &evidence.ActionLifecycle{
		ApprovalID: ap.ID, ApprovalStatus: ap.Status, ApproverGroups: ap.Groups, ApprovalExpires: ap.ExpiresAt.Format(time.RFC3339),
		ReviewerPrincipal: rv.PrincipalID, ReviewerTenant: rv.TenantScope, ReviewerSubject: rv.Subject, ReviewerGroup: group,
		ReviewerCredentialID: rv.CredentialID, ReviewerCredentialVersion: rv.CredentialVersion,
	}
}

// authorizeReviewer applies the three authorization gates in order —
// tenant scope, rule group, active principal/credential (rechecked in the
// transaction) — and records an evidenced refusal for a failure.
func (s *Service) authorizeReviewer(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, op *Operation, ap *Approval, rv ReviewerPrincipal) (string, error) {
	refuse := func(msg string) (string, error) {
		if ok, err := bump(ctx, tx, op, s.now()); err != nil || !ok {
			return "", &Error{Code: CodeStoreUnavailable, Message: "recording refusal", Err: err}
		}
		ev := reviewerFacts(ap, rv, "")
		ev.Event, ev.RefusalCode = evidence.ActionEventAuthorizationRefused, CodeApprovalNotAuthorized
		if err := s.commit(ctx, tx, w, op, ev, false, []string{msg}, "ACTION_APPROVAL_NOT_AUTHORIZED"); err != nil {
			return "", err
		}
		if err := finalize(ctx, tx, op); err != nil {
			return "", err
		}
		return "", refusal(newErr(CodeApprovalNotAuthorized, msg))
	}
	if rv.TenantScope != op.TenantID {
		return refuse("reviewer tenant scope does not match the operation's tenant")
	}
	group := firstCommon(ap.Groups, rv.Groups)
	if group == "" {
		return refuse("reviewer is not in an approver group of the matched rule")
	}
	if rv.Revalidate == nil {
		return refuse("reviewer principal cannot be revalidated")
	}
	if active, err := rv.Revalidate(ctx); err != nil || !active {
		return refuse("reviewer principal or credential is inactive/revoked")
	}
	return group, nil
}

// commitDecision writes the one-winner decision and the operation
// transition (approved → authorized; rejected → cancelled + payload purge).
func (s *Service) commitDecision(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, op *Operation, ap *Approval, req DecideRequest, group string, now time.Time) (*Projection, error) {
	ap.Status = ApprovalRejected
	if req.Approve {
		ap.Status = ApprovalApproved
	}
	ap.DecidedAt, ap.DecidedBy, ap.DecidedGroup, ap.Reason = utcPtr(now), req.Reviewer.PrincipalID, group, req.Reason
	ap.Version++
	won, err := decideApproval(ctx, tx, ap, ap.Version-1)
	if err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "committing decision", Err: err}
	}
	if !won {
		proj, _ := s.project(ctx, tx, op)
		return nil, &Error{Code: CodeApprovalAlreadyDecided, Message: "a concurrent decision was committed first", State: proj}
	}
	if req.Approve {
		op.Status = OpAuthorized
	} else {
		op.Status, op.OutcomeCode, op.TerminalAt = OpCancelled, CodeApprovalRejected, utcPtr(now)
		if err := purgePayload(ctx, tx, op.Ref, now); err != nil {
			return nil, &Error{Code: CodeStoreUnavailable, Message: "purging payload", Err: err}
		}
	}
	if ok, err := bump(ctx, tx, op, now); err != nil || !ok {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "updating operation after decision", Err: err}
	}
	code := "ACTION_APPROVAL_REJECTED"
	if req.Approve {
		code = "ACTION_APPROVAL_APPROVED"
	}
	ev := reviewerFacts(ap, req.Reviewer, group)
	ev.Event, ev.DecisionReason = evidence.ActionEventApprovalDecided, ap.Reason
	if err := s.commit(ctx, tx, w, op, ev, req.Approve, []string{"reviewer decision committed; decision performs no dispatch — the runtime must claim an attempt"}, code); err != nil {
		return nil, err
	}
	if err := finalize(ctx, tx, op); err != nil {
		return nil, err
	}
	return projectionOf(op, ap, nil, payloadState(ctx, tx, op.Ref)), nil
}

// closeApproval terminates a pending approval by a SYSTEM event (expiry or
// invalidation): the approval and operation close, the payload is purged,
// and the caller receives the stable code as an evidenced refusal.
func (s *Service) closeApproval(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, op *Operation, ap *Approval, status, code, msg, evCode string, now time.Time) error {
	ap.Status = status
	ap.DecidedAt = utcPtr(now)
	ap.DecidedBy, ap.DecidedGroup = "system", "system"
	ap.Version++
	if won, err := decideApproval(ctx, tx, ap, ap.Version-1); err != nil || !won {
		return &Error{Code: CodeStoreUnavailable, Message: "closing approval", Err: err}
	}
	op.Status, op.OutcomeCode, op.TerminalAt = OpCancelled, code, utcPtr(now)
	if err := purgePayload(ctx, tx, op.Ref, now); err != nil {
		return &Error{Code: CodeStoreUnavailable, Message: "purging payload", Err: err}
	}
	if ok, err := bump(ctx, tx, op, now); err != nil || !ok {
		return &Error{Code: CodeStoreUnavailable, Message: "closing operation", Err: err}
	}
	if err := s.commit(ctx, tx, w, op, &evidence.ActionLifecycle{
		Event: evidence.ActionEventApprovalDecided, ApprovalID: ap.ID, ApprovalStatus: ap.Status,
		ApproverGroups: ap.Groups, ApprovalExpires: ap.ExpiresAt.Format(time.RFC3339), ReviewerPrincipal: "system", ReviewerGroup: "system", RefusalCode: code,
	},
		false, []string{msg}, evCode); err != nil {
		return err
	}
	if err := finalize(ctx, tx, op); err != nil {
		return err
	}
	proj, _ := s.project(ctx, tx, op)
	return refusal(&Error{Code: code, Message: msg, State: proj})
}

// ---- Execute ---------------------------------------------------------

// ExecuteResult is the outcome of one claim + dispatch.
type ExecuteResult struct {
	Operation *Projection
	Attempt   *AttemptProjection
}

// Execute is the runtime/controller resumption:
//
//  1. revalidate the exact operation against the CURRENT catalog/policy and
//     open the sealed payload (fail closed);
//  2. claim ONE attempt (committed);
//  3. ARM the attempt (durable pre-effect marker, committed) — after this a
//     crash recovers as UNKNOWN, never as "not sent";
//  4. dispatch exactly once through the trusted dispatcher;
//  5. record the observed facts and the conservative outcome.
//
// Nothing here is reachable from a reviewer decision.
func (s *Service) Execute(ctx context.Context, operationID string) (*ExecuteResult, error) {
	var op *Operation
	var at *Attempt
	var def *Definition
	var payload []byte
	err := s.repo.withTx(ctx, s.evidence, func(tx *sql.Tx, w *evidence.TxWriter) error {
		claim, err := s.authorizeClaim(ctx, tx, w, operationID)
		if err != nil {
			return err
		}
		op, def, payload = claim.op, claim.def, claim.payload
		at, err = s.claimAttempt(ctx, tx, w, op, claim.approval)
		return err
	})
	if err != nil {
		return nil, err
	}
	if s.hookAfterClaim != nil {
		s.hookAfterClaim()
	}
	if err := s.armAttempt(ctx, op, at); err != nil {
		// The marker did not commit: nothing was sent. The attempt stays
		// `started`/unarmed for recovery (→ failed/not_dispatched).
		return nil, err
	}
	if s.hookAfterArm != nil {
		s.hookAfterArm()
	}
	outcome := s.dispatcher.Dispatch(ctx, DispatchRequest{Definition: def, Payload: payload, OperationRef: op.Ref, AttemptID: at.ID, IdempotencyKey: at.IdempotencyKey})
	if s.hookBeforeComplete != nil {
		s.hookBeforeComplete(outcome)
	}
	return s.complete(ctx, op, at, outcome)
}

// claimAuthorization is what an authorized claim needs after revalidation.
type claimAuthorization struct {
	op       *Operation
	def      *Definition
	approval *Approval
	payload  []byte
}

// claimableOperation loads the operation and applies the state gate:
// a pending approval past its lifetime is expired by the system first,
// then the status must be one from which an attempt may be claimed.
func (s *Service) claimableOperation(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, operationID string) (*Operation, error) {
	op, err := getOperation(ctx, tx, s.TenantID, s.AgentID, operationID)
	if err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "reading operation", Err: err}
	}
	if op == nil {
		return nil, newErr(CodeNotFound, "operation not found in this AI use case")
	}
	if op.Status == OpAwaitingApproval && op.ApprovalID != "" {
		ap, err := getApproval(ctx, tx, op.ApprovalID)
		if err != nil || ap == nil {
			return nil, &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
		}
		if ap.Status == ApprovalPending && !s.now().Before(ap.ExpiresAt) {
			return nil, s.closeApproval(ctx, tx, w, op, ap, ApprovalExpired, CodeApprovalExpired, "approval lifetime elapsed before a decision; system expiry, not a human decision", "ACTION_APPROVAL_EXPIRED", s.now())
		}
	}
	if code, msg := s.claimBlocker(op); code != "" {
		proj, _ := s.project(ctx, tx, op)
		return nil, &Error{Code: code, Message: msg, State: proj}
	}
	return op, nil
}

// authorizeClaim revalidates authorization usability for one claim: state,
// current trusted definition, current policy, approval usability/expiry,
// and the sealed payload. Every refusal is evidenced; nothing is claimed.
func (s *Service) authorizeClaim(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, operationID string) (*claimAuthorization, error) {
	op, err := s.claimableOperation(ctx, tx, w, operationID)
	if err != nil {
		return nil, err
	}
	def, ok := s.Catalog.Lookup(op.Action)
	if !ok || def.DefinitionDigest != op.DefinitionDigest {
		return nil, s.refuse(ctx, tx, w, op, CodeApprovalBindingStale, "the trusted action definition (schema/projection/destination/success contract) changed since this operation was bound; establish a new operation")
	}
	current := s.Policy.Evaluate(op.Action)
	if current.Outcome == VerdictDeny {
		return nil, s.refuse(ctx, tx, w, op, CodePolicyDenied, "current policy denies this action; a prior authorization cannot be used")
	}
	var ap *Approval
	if op.ApprovalID != "" {
		ap, err = getApproval(ctx, tx, op.ApprovalID)
		if err != nil || ap == nil {
			return nil, &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
		}
	}
	if current.Outcome == VerdictRequireApproval || op.Verdict == VerdictRequireApproval {
		if refused := s.approvalUsable(ctx, tx, w, op, ap); refused != nil {
			return nil, refused
		}
	}
	// The sealed payload must open BEFORE anything is claimed: a missing
	// key, a rotated key or a tampered record is a fail-closed refusal,
	// never a partially claimed attempt.
	payload, err := loadPayload(ctx, tx, s.cryptor, op.Ref, op.Digest)
	if err != nil {
		return nil, s.refuse(ctx, tx, w, op, CodePayloadUnavailable, "active payload cannot be opened: "+err.Error())
	}
	return &claimAuthorization{op: op, def: def, approval: ap, payload: payload}, nil
}

// approvalUsable checks that an approved decision binds this exact
// operation under the current approval-relevant policy and is unexpired
// for a first attempt.
func (s *Service) approvalUsable(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, op *Operation, ap *Approval) error {
	if ap == nil || ap.Status != ApprovalApproved || ap.SubjectDigest != op.Digest {
		return s.refuse(ctx, tx, w, op, CodeApprovalRequired, "no usable approved decision binds this exact operation under current policy")
	}
	if s.Policy.Digest != op.PolicyDigest {
		return s.refuse(ctx, tx, w, op, CodeApprovalBindingStale, "approval-relevant policy changed since the approval was granted; a new approval cycle is required")
	}
	if op.AttemptCount == 0 && !s.now().Before(ap.ExpiresAt) {
		return s.refuse(ctx, tx, w, op, CodeApprovalExpired, "approved decision expired before the first attempt")
	}
	return nil
}

// claimAttempt allocates the next attempt ordinal under the version guard
// (exactly one concurrent claim wins) and records attempt_claimed.
func (s *Service) claimAttempt(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, op *Operation, ap *Approval) (*Attempt, error) {
	now := s.now()
	op.Status = OpExecuting
	op.AttemptCount++
	if ok, err := bump(ctx, tx, op, now); err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "claiming attempt", Err: err}
	} else if !ok {
		proj, _ := s.project(ctx, tx, op)
		return nil, &Error{Code: CodeAttemptAlreadyInProgress, Message: "another claim won the race for this operation", State: proj}
	}
	at := &Attempt{ID: s.newID("att"), OperationRef: op.Ref, Ordinal: op.AttemptCount, Status: AttemptStarted, IdempotencyKey: op.IdempotencyKey, StartedAt: now}
	if err := insertAttempt(ctx, tx, at); err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "inserting attempt", Err: err}
	}
	if err := s.commit(ctx, tx, w, op, &evidence.ActionLifecycle{
		Event: evidence.ActionEventAttemptClaimed, AttemptID: at.ID, AttemptOrdinal: at.Ordinal, AttemptStatus: at.Status,
		IdempotencyKey: at.IdempotencyKey, DispatchBoundary: op.ExecutionProfile, ApprovalID: op.ApprovalID, ApprovalStatus: approvalStatus(ap),
	},
		true, []string{"current catalog/policy revalidated; exactly one attempt claimed before any effect"}, "ACTION_ATTEMPT_CLAIMED"); err != nil {
		return nil, err
	}
	return at, finalize(ctx, tx, op)
}

// armAttempt commits the durable pre-effect marker. It states intent only
// — "a dispatch may now occur" — never that a request was written.
func (s *Service) armAttempt(ctx context.Context, op *Operation, at *Attempt) error {
	return s.repo.withTx(ctx, s.evidence, func(tx *sql.Tx, w *evidence.TxWriter) error {
		at.ArmedAt = utcPtr(s.now())
		if ok, err := updateAttempt(ctx, tx, at); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "arming dispatch", Err: err}
		}
		if ok, err := bump(ctx, tx, op, s.now()); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "arming dispatch", Err: err}
		}
		if err := s.commit(ctx, tx, w, op, &evidence.ActionLifecycle{
			Event: evidence.ActionEventAttemptArmed, AttemptID: at.ID, AttemptOrdinal: at.Ordinal, AttemptStatus: at.Status,
			IdempotencyKey: at.IdempotencyKey, DispatchBoundary: op.ExecutionProfile, DispatchArmed: true,
		},
			true, []string{"dispatch armed: from here a crash recovers as unknown; no request has been observed yet"}, "ACTION_ATTEMPT_ARMED"); err != nil {
			return err
		}
		return finalize(ctx, tx, op)
	})
}

func (s *Service) complete(ctx context.Context, op *Operation, at *Attempt, outcome Outcome) (*ExecuteResult, error) {
	var out *ExecuteResult
	err := s.repo.withTx(ctx, s.evidence, func(tx *sql.Tx, w *evidence.TxWriter) error {
		now := s.now()
		at.Status, at.CompletedAt = outcome.Status, utcPtr(now)
		at.RequestWritten, at.ResponseObserved, at.HTTPStatus = outcome.RequestWritten, outcome.ResponseObserved, outcome.HTTPStatus
		at.ResultProvenance, at.OutcomeCode, at.OutcomeRef = outcome.Provenance, outcome.Code, outcome.Ref
		if ok, err := updateAttempt(ctx, tx, at); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "completing attempt", Err: err}
		}
		op.OutcomeProvenance, op.OutcomeCode = outcome.Provenance, outcome.Code
		allowed := true
		code := "ACTION_ATTEMPT_SUCCEEDED"
		reason := "response matched the trusted success contract; outcome observed by Talon"
		terminal := false
		switch outcome.Status {
		case AttemptSucceeded:
			op.Status, op.TerminalAt, terminal = OpSucceeded, utcPtr(now), true
		case AttemptUnknown:
			op.Status, op.TerminalAt, terminal = OpUnknown, utcPtr(now), true
			code, allowed = "ACTION_ATTEMPT_UNKNOWN", false
			reason = "the request may or did reach the destination and no trustworthy outcome exists; automatic retry is blocked"
			if outcome.ResponseObserved {
				reason = fmt.Sprintf("the destination answered HTTP %d, which the trusted success contract does not declare as success; the business effect may have happened; automatic retry is blocked", outcome.HTTPStatus)
			}
		default:
			op.Status = OpFailed
			code, allowed = "ACTION_ATTEMPT_FAILED", false
			reason = "the request never left Talon; the unchanged operation may be retried by an explicit new claim"
		}
		if terminal {
			if err := purgePayload(ctx, tx, op.Ref, now); err != nil {
				return &Error{Code: CodeStoreUnavailable, Message: "purging payload", Err: err}
			}
		}
		if ok, err := bump(ctx, tx, op, now); err != nil || !ok {
			return &Error{Code: CodeStoreUnavailable, Message: "completing operation", Err: err}
		}
		if err := s.commit(ctx, tx, w, op, &evidence.ActionLifecycle{
			Event: evidence.ActionEventAttemptCompleted, AttemptID: at.ID, AttemptOrdinal: at.Ordinal, AttemptStatus: at.Status,
			IdempotencyKey: at.IdempotencyKey, DispatchBoundary: op.ExecutionProfile, DispatchArmed: at.ArmedAt != nil,
			RequestWritten: at.RequestWritten, ResponseObserved: at.ResponseObserved, HTTPStatus: at.HTTPStatus, ResultProvenance: at.ResultProvenance,
			OutcomeCode: at.OutcomeCode, OutcomeRef: at.OutcomeRef,
		}, allowed, []string{reason}, code); err != nil {
			return err
		}
		if err := finalize(ctx, tx, op); err != nil {
			return err
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
func (s *Service) claimBlocker(op *Operation) (code, msg string) {
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
		switch op.OutcomeCode {
		case CodeApprovalExpired:
			return CodeApprovalExpired, "approval expired"
		case CodeApprovalBindingStale:
			return CodeApprovalBindingStale, "the pending approval was invalidated by a trusted-definition change"
		}
		return CodeApprovalRejected, "the reviewer rejected this operation"
	}
	return "", ""
}

// refuse records an authorization refusal (state otherwise unchanged) and
// returns the domain error.
func (s *Service) refuse(ctx context.Context, tx *sql.Tx, w *evidence.TxWriter, op *Operation, code, msg string) error {
	if ok, err := bump(ctx, tx, op, s.now()); err != nil || !ok {
		return &Error{Code: CodeStoreUnavailable, Message: "recording refusal", Err: err}
	}
	if err := s.commit(ctx, tx, w, op, &evidence.ActionLifecycle{Event: evidence.ActionEventAuthorizationRefused, ApprovalID: op.ApprovalID, RefusalCode: code},
		false, []string{msg}, "ACTION_AUTHORIZATION_REFUSED"); err != nil {
		return err
	}
	if err := finalize(ctx, tx, op); err != nil {
		return err
	}
	proj, _ := s.project(ctx, tx, op)
	return refusal(&Error{Code: code, Message: msg, State: proj})
}

// RecoverInterrupted closes attempts left `started` by a crash: armed →
// UNKNOWN (the effect may exist; nothing was observed), not armed →
// failed/not_dispatched (safe to retry). Called once at service
// construction; no attempt is in flight at process start.
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
		outcome := Outcome{Status: AttemptFailed, Provenance: ResultProvenanceNotDispatched, Code: "interrupted_before_arm"}
		if at.ArmedAt != nil {
			outcome = Outcome{Status: AttemptUnknown, Provenance: ResultProvenanceUnknown, Code: "interrupted_after_arm"}
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

func firstCommon(a, b []string) string {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return x
			}
		}
	}
	return ""
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

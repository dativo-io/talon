package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/requestctx"
)

// Action Gateway HTTP adapter (#429/#458). A thin, framework-neutral
// projection over internal/action: it authenticates, decodes, calls the
// domain and maps stable domain codes to HTTP. It never evaluates policy,
// never touches state directly and never dispatches.
//
//	POST /v1/action-operations                          establish/evaluate   (agent key)
//	GET  /v1/action-operations/{operation_id}           projection           (agent key)
//	POST /v1/action-operations/{operation_id}/attempts  claim + dispatch     (agent key)
//	GET  /v1/approvals/{approval_id}                    approval projection  (agent key)
//	POST /v1/approvals/{approval_id}/decisions          reviewer decision    (approver credential ONLY)

// ActionServiceResolver returns the ActionGovernance service for one
// authenticated AI use case, bound to the runtime generation the identity
// authenticated against (#267 invariant, applied to the Action Gateway):
//
//	id.Generation != current generation → *ActionServiceError{generation_changed}
//	agent unknown / no catalog           → *ActionServiceError{action_not_found}
//
// A Service resolved against a matching immutable generation completes the
// current request even if a reload activates afterwards; the invariant is
// "authenticated generation == Service generation at resolution", not
// "no reload during the response". An identity without a generation (not
// generation-bound auth) resolves against the current generation.
type ActionServiceResolver func(id requestctx.AgentIdentity) (*action.Service, error)

// CodeGenerationChanged: the runtime generation changed between the agent
// key's authentication and the action's resolution. Nothing was evaluated,
// bound, persisted or dispatched; the caller re-authenticates and retries.
const CodeGenerationChanged = "generation_changed"

// ActionServiceError is why no Service was resolved (a stable code and a
// message; never a domain mutation).
type ActionServiceError struct {
	Code    string
	Message string
}

func (e *ActionServiceError) Error() string { return e.Code + ": " + e.Message }

// ApprovalOwnerResolver returns the service owning an approval id within
// the authenticated reviewer's trusted tenant scope. An approval outside
// that scope is "not found": approval ids are opaque across tenants, and
// a foreign tenant's operation must never be touched (no evidence, no
// version or sequence change) by a request it does not authorize.
type ApprovalOwnerResolver func(ctx context.Context, tenantScope, approvalID string) (*action.Service, bool)

// ApproverResolver authenticates a reviewer credential.
type ApproverResolver interface {
	ResolvePrincipal(ctx context.Context, token string) (*approver.Principal, error)
	IsActive(ctx context.Context, principalID, credentialID string) (bool, error)
}

// WithActionGateway mounts the Action Gateway routes.
func WithActionGateway(services ActionServiceResolver, owners ApprovalOwnerResolver, approvers ApproverResolver) Option {
	return func(s *Server) {
		s.actionServices = services
		s.approvalOwners = owners
		s.approvers = approvers
	}
}

const maxActionBody = 512 * 1024

type actionErrorEnvelope struct {
	Error actionErrorBody `json:"error"`
}

type actionErrorBody struct {
	Code      string             `json:"code"`
	Message   string             `json:"message"`
	Operation *action.Projection `json:"operation,omitempty"`
}

func writeActionJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeActionError(w http.ResponseWriter, status int, code, msg string, state *action.Projection) {
	writeActionJSON(w, status, actionErrorEnvelope{Error: actionErrorBody{Code: code, Message: msg, Operation: state}})
}

// statusForActionCode maps stable domain codes to HTTP (#429 recommended
// mapping). The body code is authoritative; HTTP alone is insufficient.
func statusForActionCode(code string) int {
	switch code {
	case action.CodeOperationIDRequired, action.CodeInvalidRequest, action.CodeActionSchemaInvalid:
		return http.StatusUnprocessableEntity
	case action.CodeActionNotFound, action.CodeNotFound:
		return http.StatusNotFound
	case action.CodePolicyDenied, action.CodeApprovalRequired, action.CodeApprovalRejected, action.CodeAttemptNotAuthorized:
		return http.StatusForbidden
	case action.CodeApprovalNotAuthorized:
		return http.StatusUnauthorized
	case action.CodeOperationConflict, action.CodeApprovalPending, action.CodeApprovalExpired, action.CodeApprovalAlreadyDecided,
		action.CodeApprovalBindingStale, action.CodeOperationAlreadySucceeded, action.CodeOperationOutcomeUnknown, action.CodeAttemptAlreadyInProgress:
		return http.StatusConflict
	case action.CodeStoreUnavailable:
		return http.StatusServiceUnavailable
	case action.CodeExecutionUnsupported:
		return http.StatusNotImplemented
	}
	return http.StatusInternalServerError
}

func writeDomainError(w http.ResponseWriter, err error) {
	var de *action.Error
	if errors.As(err, &de) {
		if de.Code == action.CodeApprovalPending {
			w.Header().Set("Retry-After", "5")
		}
		writeActionError(w, statusForActionCode(de.Code), de.Code, de.Message, de.State)
		return
	}
	log.Error().Err(err).Msg("action_gateway_internal_error")
	writeActionError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
}

// actionService resolves the authenticated agent's service. Admin keys
// and unauthenticated dev-mode requests are refused: runtime operations
// are agent-scoped, never operator-scoped (#429).
func (s *Server) actionService(w http.ResponseWriter, r *http.Request) (*action.Service, bool) {
	id, ok := requestctx.AgentIdentityFrom(r.Context())
	if !ok {
		writeActionError(w, http.StatusUnauthorized, "agent_identity_required", "runtime operations require the AI use case's agent key", nil)
		return nil, false
	}
	if s.actionServices == nil {
		writeActionError(w, http.StatusNotFound, action.CodeActionNotFound, "no action catalog is configured", nil)
		return nil, false
	}
	svc, err := s.actionServices(id)
	if err != nil {
		var se *ActionServiceError
		if errors.As(err, &se) {
			switch se.Code {
			case CodeGenerationChanged:
				w.Header().Set("Retry-After", "1")
				writeActionError(w, http.StatusConflict, CodeGenerationChanged, se.Message, nil)
			default:
				writeActionError(w, http.StatusNotFound, action.CodeActionNotFound, se.Message, nil)
			}
			return nil, false
		}
		log.Error().Err(err).Str("agent", id.AgentID).Msg("action_service_unavailable")
		writeActionError(w, http.StatusInternalServerError, "internal_error", "internal error", nil)
		return nil, false
	}
	return svc, true
}

type establishBody struct {
	OperationID string          `json:"operation_id"`
	Action      string          `json:"action"`
	Arguments   json.RawMessage `json:"arguments"`
}

func decodeActionBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxActionBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeActionError(w, http.StatusBadRequest, action.CodeInvalidRequest, "malformed request body: "+err.Error(), nil)
		return false
	}
	if dec.More() {
		writeActionError(w, http.StatusBadRequest, action.CodeInvalidRequest, "trailing data after JSON body", nil)
		return false
	}
	return true
}

func (s *Server) handleActionEstablish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.actionService(w, r)
	if !ok {
		return
	}
	var body establishBody
	if !decodeActionBody(w, r, &body) {
		return
	}
	res, err := svc.Establish(r.Context(), action.EstablishRequest{OperationID: body.OperationID, Action: body.Action, Arguments: body.Arguments})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	status := http.StatusOK
	switch {
	case res.Operation.Status == action.OpDenied:
		// A DENY is final and evidenced; the resource exists so the caller
		// can inspect it, but the answer is a denial.
		status = http.StatusForbidden
	case res.Created && res.Operation.Status == action.OpAwaitingApproval:
		status = http.StatusAccepted
	case res.Created:
		status = http.StatusCreated
	}
	writeActionJSON(w, status, map[string]any{"created": res.Created, "operation": res.Operation})
}

func (s *Server) handleActionGet(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.actionService(w, r)
	if !ok {
		return
	}
	proj, err := svc.Get(r.Context(), chi.URLParam(r, "operation_id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeActionJSON(w, http.StatusOK, map[string]any{"operation": proj})
}

func (s *Server) handleActionAttempt(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.actionService(w, r)
	if !ok {
		return
	}
	res, err := svc.Execute(r.Context(), chi.URLParam(r, "operation_id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeActionJSON(w, http.StatusOK, map[string]any{"operation": res.Operation, "attempt": res.Attempt})
}

func (s *Server) handleApprovalGet(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.actionService(w, r)
	if !ok {
		return
	}
	proj, err := svc.GetApproval(r.Context(), chi.URLParam(r, "approval_id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeActionJSON(w, http.StatusOK, map[string]any{"operation": proj, "approval": proj.Approval})
}

type decisionBody struct {
	Decision string `json:"decision"` // approve | reject
	Reason   string `json:"reason"`
}

// handleApprovalDecision authenticates the REVIEWER credential only. An
// admin key, an agent key, a body field or a header name never authorizes
// a decision (#428): approval authority is business authorization, not
// platform administration.
func (s *Server) handleApprovalDecision(w http.ResponseWriter, r *http.Request) {
	if s.approvers == nil || s.approvalOwners == nil {
		writeActionError(w, http.StatusNotFound, action.CodeNotFound, "approvals are not configured", nil)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer talon_appr_") {
		writeActionError(w, http.StatusUnauthorized, action.CodeApprovalNotAuthorized, "an approver credential (Authorization: Bearer talon_appr_…) is required; admin and agent keys carry no approval authority", nil)
		return
	}
	principal, err := s.approvers.ResolvePrincipal(r.Context(), strings.TrimPrefix(auth, "Bearer "))
	if err != nil || principal == nil {
		msg := "unknown, revoked or inactive approver credential"
		if errors.Is(err, approver.ErrLegacyCredential) {
			msg = err.Error()
		}
		writeActionError(w, http.StatusUnauthorized, action.CodeApprovalNotAuthorized, msg, nil)
		return
	}
	var body decisionBody
	if !decodeActionBody(w, r, &body) {
		return
	}
	approve := false
	switch strings.ToLower(strings.TrimSpace(body.Decision)) {
	case "approve":
		approve = true
	case "reject":
	default:
		writeActionError(w, http.StatusBadRequest, action.CodeInvalidRequest, "decision must be approve or reject", nil)
		return
	}
	approvalID := chi.URLParam(r, "approval_id")
	svc, ok := s.approvalOwners(r.Context(), principal.TenantScope, approvalID)
	if !ok {
		writeActionError(w, http.StatusNotFound, action.CodeNotFound, "approval not found", nil)
		return
	}
	resolver := s.approvers
	proj, err := svc.Decide(r.Context(), action.DecideRequest{
		ApprovalID: approvalID, Approve: approve, Reason: body.Reason,
		Reviewer: action.ReviewerPrincipal{
			PrincipalID: principal.PrincipalID, TenantScope: principal.TenantScope, Subject: principal.Subject, Groups: principal.Groups,
			CredentialID: principal.CredentialID, CredentialVersion: principal.CredentialVersion,
			Revalidate: func(ctx context.Context) (bool, error) {
				return resolver.IsActive(ctx, principal.PrincipalID, principal.CredentialID)
			},
		},
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeActionJSON(w, http.StatusOK, map[string]any{"operation": proj, "approval": proj.Approval})
}

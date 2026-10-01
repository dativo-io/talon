// Package action is Talon's ActionGovernance domain (#458, #424): the
// authorization and consumption state of one exact consequential action.
//
//	adapter (HTTP Action Gateway today; MCP/native later)
//	  → Service.Establish   validate against trusted catalog, bind exact digest,
//	                         evaluate verdict, persist operation (+ approval)
//	  → Service.Decide      authenticated approver commits an immutable decision
//	                         (performs ZERO dispatch)
//	  → Service.Execute     revalidate current controls, claim ONE attempt,
//	                         mark dispatch boundary, dispatch once, record
//	                         observed result or conservative UNKNOWN
//
// Every transition commits its state and its signed evidence in one SQLite
// transaction. The domain never imports HTTP, MCP or CLI types.
package action

import (
	"errors"
	"fmt"
)

// Stable machine codes (#429). Adapters map these to HTTP/MCP shapes; the
// code is the contract, the message is prose.
const (
	CodeOperationIDRequired       = "operation_id_required"
	CodeOperationConflict         = "operation_conflict"
	CodeActionNotFound            = "action_not_found"
	CodeActionSchemaInvalid       = "action_schema_invalid"
	CodePolicyDenied              = "policy_denied"
	CodeApprovalRequired          = "approval_required"
	CodeApprovalPending           = "approval_pending"
	CodeApprovalRejected          = "approval_rejected"
	CodeApprovalExpired           = "approval_expired"
	CodeApprovalNotAuthorized     = "approval_not_authorized"
	CodeApprovalAlreadyDecided    = "approval_already_decided"
	CodeApprovalBindingStale      = "approval_binding_stale"
	CodeOperationAlreadySucceeded = "operation_already_succeeded"
	CodeOperationOutcomeUnknown   = "operation_outcome_unknown"
	CodeAttemptAlreadyInProgress  = "attempt_already_in_progress"
	CodeAttemptNotAuthorized      = "attempt_not_authorized"
	CodePayloadUnavailable        = "payload_unavailable"
	CodeNotFound                  = "not_found"
	CodeInvalidRequest            = "invalid_request"
	CodeStoreUnavailable          = "store_unavailable"
)

// Error is a typed domain failure with a stable code.
type Error struct {
	Code    string
	Message string
	// State carries the current safe operation projection when useful.
	State *Projection
	Err   error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// CodeOf returns the stable code of a domain error, or "" for foreign errors.
func CodeOf(err error) string {
	var de *Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func newErr(code, msg string) *Error { return &Error{Code: code, Message: msg} }

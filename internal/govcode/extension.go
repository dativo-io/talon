package govcode

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ExtensionID is the versioned reverse-DNS identifier of Talon's MCP
// 2026-07-28 governance extension. It names the key under which the
// Extension object travels in JSON-RPC error.data and in result _meta, and
// the capabilities.extensions entry server/discover advertises.
const ExtensionID = "io.dativo.talon/governance"

// SchemaVersion is the extension's schema identity. Additive fields may
// appear within a version; a semantic change requires a new version.
const SchemaVersion = 1

// Decision is the governance outcome class the extension reports.
const (
	DecisionAllow   = "allow"
	DecisionDeny    = "deny"
	DecisionPending = "pending"
	DecisionFailed  = "failed"
	DecisionUnknown = "unknown"
)

// Bounds keep the in-band object small and safe: identifiers and codes are
// short tokens, remediation is one bounded sentence.
const (
	maxIDBytes          = 256
	maxRemediationBytes = 512
)

// EvidenceRef is the in-band reference to a signed record. It is a
// locator, not the record: the id appears only after the complete signed
// record committed, committed=true means Talon accepted the record (not a
// completeness or immutability claim), and cryptographic verification
// requires the full canonical record via `talon audit verify <id>`.
// Knowing an id grants no authority; retrieval stays scoped.
type EvidenceRef struct {
	ID        string `json:"id,omitempty"`
	Committed bool   `json:"committed"`
	// Sequence is the operation-lifecycle sequence of the record where one
	// exists (action lifecycle records); zero otherwise.
	Sequence int `json:"sequence,omitempty"`
}

// Committed builds a reference to a record that committed.
func Committed(id string) *EvidenceRef { return &EvidenceRef{ID: id, Committed: true} }

// NotCommitted builds a reference stating that the record did not commit.
// It carries no id: an id must never be fabricated.
func NotCommitted() *EvidenceRef { return &EvidenceRef{Committed: false} }

// Extension is the safe governance object. Field names follow MCP _meta
// conventions (camelCase). It never carries raw or protected payload,
// credentials, approver internals, caller-provided reviewer authority, raw
// upstream bodies, or any signature fragment.
type Extension struct {
	SchemaVersion int    `json:"schemaVersion"`
	Code          string `json:"code"`
	Decision      string `json:"decision"`
	ReasonCode    string `json:"reasonCode,omitempty"`
	Retryable     bool   `json:"retryable"`
	// RetryAfterMs is a poll or back-off hint; zero means none.
	RetryAfterMs int `json:"retryAfterMs,omitempty"`
	// Identifiers are scoped resource locators, never bearer authorization.
	OperationID  string       `json:"operationId,omitempty"`
	OperationRef string       `json:"operationRef,omitempty"`
	ApprovalID   string       `json:"approvalId,omitempty"`
	AttemptID    string       `json:"attemptId,omitempty"`
	TaskID       string       `json:"taskId,omitempty"`
	Evidence     *EvidenceRef `json:"evidence,omitempty"`
	// Generation is the short runtime-generation identity the decision was
	// made against.
	Generation string `json:"generation,omitempty"`
	// Provenance is the outcome provenance where meaningful
	// (observed | not_dispatched | unknown | client_asserted | reconciled).
	Provenance string `json:"provenance,omitempty"`
	// Remediation is one bounded sentence for the caller.
	Remediation string `json:"remediation,omitempty"`
}

// New builds an extension for a registered code with its fixed decision
// class, retryability and explanation code. An unregistered code is
// rejected: adapters must not invent names.
func New(code string) (Extension, error) {
	spec, ok := Lookup(code)
	if !ok {
		return Extension{}, fmt.Errorf("govcode: %q is not a registered governance code", code)
	}
	return Extension{SchemaVersion: SchemaVersion, Code: code, Decision: decisionFor(spec), ReasonCode: spec.Explanation, Retryable: spec.Retryable}, nil
}

// Must is New for callers whose code is a package constant; it panics on a
// programming error (an unregistered constant), never on input.
func Must(code string) Extension {
	e, err := New(code)
	if err != nil {
		panic(err)
	}
	return e
}

// CodeAllowed is the code of an allowed outcome; it is not a failure code
// and is not part of the registry of refusals.
const CodeAllowed = "allowed"

// Allowed builds the extension attached to an allowed outcome: decision
// allow, provenance observed (Talon saw the call complete), and the
// evidence reference of the terminal record. An allowed result says the
// call was authorized and answered; it does not by itself prove a business
// effect succeeded downstream.
func Allowed(ev *EvidenceRef) Extension {
	return Extension{SchemaVersion: SchemaVersion, Code: CodeAllowed, Decision: DecisionAllow, Evidence: ev, Provenance: "observed"}
}

// WithEvidence attaches the committed record and, when the record carries
// one, its actual primary explanation code as reasonCode: the in-band
// reason is what was signed, never a parallel vocabulary. Without a record
// the registry's default category stays.
func (e Extension) WithEvidence(ref *EvidenceRef, signedReason string) Extension {
	e.Evidence = ref
	if ref != nil && ref.Committed && signedReason != "" {
		e.ReasonCode = signedReason
	}
	return e
}

func decisionFor(s Spec) string {
	switch s.Class {
	case ClassDenied:
		return DecisionDeny
	case ClassPending:
		return DecisionPending
	case ClassUnknown:
		return DecisionUnknown
	case ClassInvalid, ClassConflict, ClassUnsupported, ClassFailed:
		return DecisionFailed
	}
	return DecisionFailed
}

// ErrExtensionInvalid reports an extension that violates its bounds.
var ErrExtensionInvalid = errors.New("governance extension invalid")

// Validate enforces the safe-data bounds: tokens are non-empty-or-absent,
// at most maxIDBytes, printable, and free of whitespace; remediation is
// bounded; the code is registered (or "allowed"); the decision is known;
// an evidence id implies committed=true.
func (e Extension) Validate() error {
	if err := e.validateHead(); err != nil {
		return err
	}
	for name, v := range map[string]string{
		"reasonCode": e.ReasonCode, "operationId": e.OperationID, "operationRef": e.OperationRef, "approvalId": e.ApprovalID,
		"attemptId": e.AttemptID, "taskId": e.TaskID, "generation": e.Generation, "provenance": e.Provenance,
	} {
		if err := validToken(name, v); err != nil {
			return err
		}
	}
	if err := e.Evidence.validate(); err != nil {
		return err
	}
	if e.RetryAfterMs < 0 {
		return fmt.Errorf("%w: retryAfterMs", ErrExtensionInvalid)
	}
	if len(e.Remediation) > maxRemediationBytes || !utf8.ValidString(e.Remediation) || strings.ContainsFunc(e.Remediation, unicode.IsControl) {
		return fmt.Errorf("%w: remediation", ErrExtensionInvalid)
	}
	return nil
}

// validateHead checks the schema version, the code registration and the
// coherence of decision and retryability with the registry: an adapter
// cannot present a denial as retryable or an unknown outcome as a failure.
func (e Extension) validateHead() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schemaVersion %d", ErrExtensionInvalid, e.SchemaVersion)
	}
	if e.Code == CodeAllowed {
		if e.Decision != DecisionAllow || e.Retryable {
			return fmt.Errorf("%w: allowed outcome must be decision allow and not retryable", ErrExtensionInvalid)
		}
		return nil
	}
	spec, ok := Lookup(e.Code)
	if !ok {
		return fmt.Errorf("%w: unregistered code %q", ErrExtensionInvalid, e.Code)
	}
	if e.Decision != decisionFor(spec) {
		return fmt.Errorf("%w: decision %q does not match code %q (%s)", ErrExtensionInvalid, e.Decision, e.Code, decisionFor(spec))
	}
	if e.Retryable != spec.Retryable {
		return fmt.Errorf("%w: retryable=%v contradicts the registry for %q", ErrExtensionInvalid, e.Retryable, e.Code)
	}
	return nil
}

// validate enforces the reference invariants: a bounded id, never an id
// without commit, a non-negative sequence. A nil reference is valid.
func (r *EvidenceRef) validate() error {
	if r == nil {
		return nil
	}
	if err := validToken("evidence.id", r.ID); err != nil {
		return err
	}
	if r.ID != "" && !r.Committed {
		return fmt.Errorf("%w: evidence id without commit", ErrExtensionInvalid)
	}
	if r.Sequence < 0 {
		return fmt.Errorf("%w: evidence sequence", ErrExtensionInvalid)
	}
	return nil
}

func validToken(name, v string) error {
	if v == "" {
		return nil
	}
	if len(v) > maxIDBytes || !utf8.ValidString(v) {
		return fmt.Errorf("%w: %s too long", ErrExtensionInvalid, name)
	}
	for _, r := range v {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains whitespace or control characters", ErrExtensionInvalid, name)
		}
	}
	return nil
}

// Bounded truncates free text to the remediation bound at a rune boundary
// and strips control characters, so adapters can pass prose safely.
func Bounded(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if len(s) <= maxRemediationBytes {
		return s
	}
	cut := maxRemediationBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// MarshalJSON validates before encoding so an adapter can never emit an
// out-of-contract object.
func (e Extension) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	type plain Extension
	return json.Marshal(plain(e))
}

// Advertisement is the server/discover capabilities.extensions entry: the
// extension id mapped to its settings object. It is advertised only
// because the implementation is real (#372).
func Advertisement() map[string]any {
	return map[string]any{ExtensionID: map[string]any{"schemaVersion": SchemaVersion}}
}

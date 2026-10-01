// Package workload verifies externally issued workload identity and
// normalizes it into one Talon principal (#457).
//
// Talon issues no identity of its own here. It consumes a standards-based
// credential (v1: an EdDSA-signed JWT) presented by a configured runtime,
// verifies it against operator-configured issuer, audience and key
// material, and produces an immutable Principal that policy, the identity
// registry and signed evidence can consume. Binding a principal to a Talon
// agent/use case is NOT done here: it comes from trusted Talon
// configuration, never from claims (see gateway.IdentityRegistry).
//
// Raw tokens never leave Verify: the Principal carries selected safe
// claims only, so nothing here can leak credential material into logs or
// evidence.
package workload

import (
	"fmt"
	"time"
)

// AuthMethodJWTEdDSA is the only verification method in v1: a compact JWS
// signed with Ed25519 (JOSE alg "EdDSA").
const AuthMethodJWTEdDSA = "jwt_eddsa"

// Principal is a verified workload identity normalized once at ingress.
type Principal struct {
	// PrincipalID is the stable normalized identity used for binding and
	// evidence. For JWT federation it is the verified subject.
	PrincipalID string
	Issuer      string
	Subject     string
	// Audience is the configured audience the token was verified against.
	Audience   string
	AuthMethod string
	// Claims holds the selected safe string claims the verifier was
	// configured to retain (e.g. a runtime's sandbox id). Never the raw
	// token, never signatures.
	Claims     map[string]string
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

// Claim returns a retained safe claim.
func (p *Principal) Claim(name string) string {
	if p == nil || p.Claims == nil {
		return ""
	}
	return p.Claims[name]
}

// Stable failure codes (machine-readable; part of the evidence contract).
const (
	FailureMissing              = "workload_identity_missing"
	FailureMalformed            = "workload_identity_malformed"
	FailureAlgUnsupported       = "workload_identity_alg_unsupported"
	FailureTypeMismatch         = "workload_identity_type_mismatch"
	FailureKeyUnknown           = "workload_identity_key_unknown"
	FailureSignatureInvalid     = "workload_identity_signature_invalid"
	FailureExpired              = "workload_identity_expired"
	FailureNotYetValid          = "workload_identity_not_yet_valid"
	FailureIssuerMismatch       = "workload_identity_issuer_mismatch"
	FailureAudienceMismatch     = "workload_identity_audience_mismatch"
	FailureClaimsInvalid        = "workload_identity_claims_invalid"
	FailureLifetimeExceeded     = "workload_identity_lifetime_exceeded"
	FailureKeySourceUnavailable = "workload_identity_key_source_unavailable"
)

// VerificationError is a typed verification failure. Code is stable and
// safe to persist; Err carries detail for logs and never token material.
type VerificationError struct {
	Code string
	Err  error
}

func (e *VerificationError) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *VerificationError) Unwrap() error { return e.Err }

// FailureCode extracts the stable code from a verification error, or ""
// for nil / foreign errors.
func FailureCode(err error) string {
	if err == nil {
		return ""
	}
	if ve, ok := err.(*VerificationError); ok {
		return ve.Code
	}
	return ""
}

func failf(code string, format string, args ...any) error {
	return &VerificationError{Code: code, Err: fmt.Errorf(format, args...)}
}

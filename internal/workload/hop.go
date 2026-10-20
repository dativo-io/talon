package workload

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Workload hop assertion (#457/#482).
//
// An external runtime such as OpenShell verifies a sandbox's identity at ITS
// egress hop and calls Talon's middleware with a gateway-signed token. The
// sandboxed application never holds that token, and the runtime does not let
// middleware write the Authorization header of the forwarded request. So
// when the destination of a sandbox request is Talon's own Action Gateway,
// Talon's middleware mints this assertion — a Talon-signed, request-bound,
// short-lived statement of what Talon verified at the hop — and asks the
// runtime to carry it in a Talon-owned header. Talon's HTTP ingress then
// verifies the assertion and binds the request to the agent the verified
// principal is configured for.
//
// This is not identity issuance: the assertion is consumed only by the same
// Talon deployment that minted it (one shared root key), names nothing a
// third party could redeem, and is bound to one method, path and body
// digest, so it can neither be redirected to another route nor replayed
// with another payload. Replay of the exact same request within the TTL is
// absorbed by the Action Gateway's idempotency contract.
const (
	// HopAssertionHeader carries the assertion from the runtime hop to Talon.
	HopAssertionHeader = "X-Talon-Workload-Assertion"
	// HopAssertionAudience is the only consumer of a hop assertion.
	HopAssertionAudience = "talon-action-gateway"
	// AuthMethodHopAssertion labels evidence for identities verified through
	// a hop assertion (the runtime credential was verified at the hop).
	AuthMethodHopAssertion = "workload_hop_assertion"

	hopVersion       = "v1"
	hopKeyInfo       = "talon-workload-hop-assertion-v1"
	maxHopTokenBytes = 8 * 1024

	DefaultHopAssertionTTL = 60 * time.Second
	MinHopAssertionTTL     = 5 * time.Second
	MaxHopAssertionTTL     = 5 * time.Minute
	// hopClockSkew tolerates small clock differences between the process
	// that minted and the process that verifies (one deployment, but
	// possibly several Talon instances).
	hopClockSkew = 30 * time.Second
)

// Hop assertion failure codes. They never reveal which part of the token
// failed beyond what a caller could learn by observation.
const (
	FailureHopMalformed        = "workload_assertion_malformed"
	FailureHopSignatureInvalid = "workload_assertion_signature_invalid"
	FailureHopExpired          = "workload_assertion_expired"
	FailureHopNotYetValid      = "workload_assertion_not_yet_valid"
	FailureHopAudienceMismatch = "workload_assertion_audience_mismatch"
	FailureHopBindingMismatch  = "workload_assertion_binding_mismatch"
	FailureHopLifetimeExceeded = "workload_assertion_lifetime_exceeded"
)

// HopClaims is what the hop verified and what the assertion binds.
type HopClaims struct {
	Version  string `json:"v"`
	Audience string `json:"aud"`
	// Runtime and RuntimeIssuer identify the external runtime that
	// authenticated the sandbox (e.g. "openshell", "openshell-gateway:<id>").
	Runtime       string `json:"runtime"`
	RuntimeIssuer string `json:"runtime_iss"`
	// Subject and PrincipalID are the verified workload principal.
	Subject     string `json:"sub"`
	PrincipalID string `json:"principal_id"`
	// SandboxRef and RequestID are the runtime's own references for the
	// workload and this request (correlation, never authority).
	SandboxRef string `json:"sandbox_ref,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	// Agent and Tenant are the use case the principal is BOUND to by trusted
	// Talon configuration at mint time; ingress re-checks the binding.
	Agent  string `json:"agent"`
	Tenant string `json:"tenant"`
	// Method, Path and BodySHA256 bind the assertion to one exact request.
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodySHA256 string `json:"body_sha256"`
	// SessionID is the client-asserted session header seen at the hop
	// (attribution only).
	SessionID string `json:"session_id,omitempty"`
	JTI       string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// HopSigner mints and verifies hop assertions under one deployment key.
type HopSigner struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

// NewHopSigner derives the assertion key from the deployment's root secret
// (the same root the Action Gateway seals payloads with) with a dedicated
// HKDF info string, so the root is never used directly and a hop key can
// never open a payload.
func NewHopSigner(rootKey string, ttl time.Duration) (*HopSigner, error) {
	root := strings.TrimSpace(rootKey)
	if len(root) < 32 {
		return nil, fmt.Errorf("hop assertion: root key must be at least 32 bytes")
	}
	if ttl == 0 {
		ttl = DefaultHopAssertionTTL
	}
	if ttl < MinHopAssertionTTL || ttl > MaxHopAssertionTTL {
		return nil, fmt.Errorf("hop assertion: ttl must be between %s and %s", MinHopAssertionTTL, MaxHopAssertionTTL)
	}
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(root), nil, []byte(hopKeyInfo)), derived); err != nil {
		return nil, fmt.Errorf("hop assertion: deriving key: %w", err)
	}
	return &HopSigner{key: derived, ttl: ttl, now: time.Now}, nil
}

// TTL is the assertion lifetime this signer mints with.
func (s *HopSigner) TTL() time.Duration { return s.ttl }

// Mint signs the claims. Version, audience, jti, iat and exp are set here;
// the caller supplies the verified facts and the request binding.
func (s *HopSigner) Mint(c HopClaims) (string, error) {
	if c.Subject == "" || c.Agent == "" || c.Tenant == "" || c.Method == "" || c.Path == "" || c.BodySHA256 == "" || c.Runtime == "" {
		return "", fmt.Errorf("hop assertion: subject, runtime, agent, tenant, method, path and body digest are required")
	}
	now := s.now()
	c.Version = hopVersion
	c.Audience = HopAssertionAudience
	c.Method = strings.ToUpper(c.Method)
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(s.ttl).Unix()
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", fmt.Errorf("hop assertion: jti: %w", err)
	}
	c.JTI = hex.EncodeToString(jti[:])
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := hopVersion + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signing + "." + base64.RawURLEncoding.EncodeToString(s.sign(signing)), nil
}

// Verify checks the signature, lifetime and the exact request binding and
// returns the claims. Every failure is a *VerificationError with a stable
// code; verification is constant-time on the signature and never trusts a
// field before the signature passed.
func (s *HopSigner) Verify(token, method, path, bodySHA256 string) (*HopClaims, error) {
	c, err := s.parseSigned(token)
	if err != nil {
		return nil, err
	}
	if err := s.checkLifetime(c); err != nil {
		return nil, err
	}
	if c.Subject == "" || c.Agent == "" || c.Tenant == "" || c.Runtime == "" || c.JTI == "" {
		return nil, failf(FailureHopMalformed, "required claims missing")
	}
	if !strings.EqualFold(c.Method, method) || c.Path != path || !hmac.Equal([]byte(c.BodySHA256), []byte(bodySHA256)) {
		return nil, failf(FailureHopBindingMismatch, "assertion is bound to a different request")
	}
	return c, nil
}

// parseSigned splits the token, verifies the signature FIRST and only then
// decodes the claims.
func (s *HopSigner) parseSigned(token string) (*HopClaims, error) {
	if token == "" || len(token) > maxHopTokenBytes {
		return nil, failf(FailureHopMalformed, "token length out of bounds")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != hopVersion {
		return nil, failf(FailureHopMalformed, "token is not a v1 hop assertion")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, failf(FailureHopMalformed, "signature encoding")
	}
	if !hmac.Equal(sig, s.sign(parts[0]+"."+parts[1])) {
		return nil, failf(FailureHopSignatureInvalid, "signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, failf(FailureHopMalformed, "claims encoding")
	}
	var c HopClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, failf(FailureHopMalformed, "claims are not valid JSON")
	}
	if c.Version != hopVersion {
		return nil, failf(FailureHopMalformed, "claims version")
	}
	if c.Audience != HopAssertionAudience {
		return nil, failf(FailureHopAudienceMismatch, "audience")
	}
	return &c, nil
}

func (s *HopSigner) checkLifetime(c *HopClaims) error {
	if c.IssuedAt == 0 || c.ExpiresAt == 0 {
		return failf(FailureHopMalformed, "iat/exp missing")
	}
	now := s.now()
	exp := time.Unix(c.ExpiresAt, 0)
	iat := time.Unix(c.IssuedAt, 0)
	switch {
	case !now.Before(exp.Add(hopClockSkew)):
		return failf(FailureHopExpired, "expired")
	case iat.After(now.Add(hopClockSkew)):
		return failf(FailureHopNotYetValid, "issued in the future")
	case exp.Sub(iat) > MaxHopAssertionTTL:
		return failf(FailureHopLifetimeExceeded, "lifetime exceeds the maximum")
	}
	return nil
}

func (s *HopSigner) sign(data string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// BodyDigest is the request-body binding used in hop assertions.
func BodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

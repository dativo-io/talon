package workload

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// KeySet resolves Ed25519 public keys by key id.
type KeySet interface {
	// Key returns the public key for kid. The second result is false when
	// the key id is unknown; an error means the key source itself failed
	// (e.g. remote JWKS unreachable), which callers treat as fail-closed.
	Key(kid string) (ed25519.PublicKey, bool, error)
}

// JWTVerifier verifies compact EdDSA JWTs against fixed issuer/audience
// expectations. It is safe for concurrent use.
type JWTVerifier struct {
	// Issuer is the exact expected "iss" claim.
	Issuer string
	// Audience is the exact expected audience; "aud" may be a string or a
	// list and must contain it.
	Audience string
	// Type, when non-empty, is the exact expected JOSE "typ" header
	// (e.g. "openshell-ext+jwt"). An unexpected type is rejected so a token
	// minted for another purpose by the same issuer cannot be replayed here.
	Type string
	// Keys resolves signing keys by kid.
	Keys KeySet
	// SafeClaims lists additional string claims to retain on the Principal.
	SafeClaims []string
	// MaxLifetime bounds exp-iat (0 = 24h). Tokens claiming a longer life
	// are rejected regardless of signature: a runtime that mints short-lived
	// credentials should never present a long-lived one.
	MaxLifetime time.Duration
	// Leeway tolerates clock skew on exp/nbf/iat (0 = 30s).
	Leeway time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

type joseHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Verify checks token and returns the normalized principal. The token is
// never retained. Every failure is a *VerificationError with a stable code.
func (v *JWTVerifier) Verify(token string) (*Principal, error) {
	if v == nil || v.Keys == nil {
		return nil, failf(FailureKeySourceUnavailable, "verifier not configured")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, failf(FailureMissing, "no token presented")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, failf(FailureMalformed, "compact JWS must have 3 segments")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, failf(FailureMalformed, "header: %v", err)
	}
	var hdr joseHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, failf(FailureMalformed, "header json: %v", err)
	}
	if hdr.Alg != "EdDSA" {
		return nil, failf(FailureAlgUnsupported, "alg %q (only EdDSA is accepted)", hdr.Alg)
	}
	if v.Type != "" && hdr.Typ != v.Type {
		return nil, failf(FailureTypeMismatch, "typ %q, expected %q", hdr.Typ, v.Type)
	}
	if hdr.Kid == "" {
		return nil, failf(FailureKeyUnknown, "header carries no kid")
	}
	pub, ok, err := v.Keys.Key(hdr.Kid)
	if err != nil {
		return nil, &VerificationError{Code: FailureKeySourceUnavailable, Err: err}
	}
	if !ok {
		return nil, failf(FailureKeyUnknown, "kid %q not in key set", hdr.Kid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, failf(FailureMalformed, "signature: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, failf(FailureSignatureInvalid, "signature does not verify under kid %q", hdr.Kid)
	}
	// Only after the signature is good do we look at claims: nothing below
	// is trusted until then.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, failf(FailureMalformed, "payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, failf(FailureMalformed, "payload json: %v", err)
	}
	return v.principalFromClaims(claims)
}

func (v *JWTVerifier) principalFromClaims(claims map[string]any) (*Principal, error) {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	leeway := v.Leeway
	if leeway == 0 {
		leeway = 30 * time.Second
	}
	maxLife := v.MaxLifetime
	if maxLife == 0 {
		maxLife = 24 * time.Hour
	}

	iss, _ := claims["iss"].(string)
	if iss == "" || iss != v.Issuer {
		return nil, failf(FailureIssuerMismatch, "iss %q, expected %q", iss, v.Issuer)
	}
	if !audienceContains(claims["aud"], v.Audience) {
		return nil, failf(FailureAudienceMismatch, "aud does not contain %q", v.Audience)
	}
	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return nil, failf(FailureClaimsInvalid, "sub is required")
	}
	exp, expOK := numericDate(claims["exp"])
	if !expOK {
		return nil, failf(FailureClaimsInvalid, "exp is required")
	}
	if !now.Before(exp.Add(leeway)) {
		return nil, failf(FailureExpired, "expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && now.Add(leeway).Before(nbf) {
		return nil, failf(FailureNotYetValid, "nbf %s", nbf.UTC().Format(time.RFC3339))
	}
	// The advertised maximum lifetime must hold without trusting an
	// optional claim: exp is bounded relative to trusted current time, and
	// iat is required so the token's own lifetime is auditable.
	if exp.Sub(now) > maxLife+leeway {
		return nil, failf(FailureLifetimeExceeded, "exp is %s ahead of now, exceeds %s", exp.Sub(now), maxLife)
	}
	iat, iatOK := numericDate(claims["iat"])
	if !iatOK {
		return nil, failf(FailureClaimsInvalid, "iat is required")
	}
	if now.Add(leeway).Before(iat) {
		return nil, failf(FailureNotYetValid, "iat %s is in the future", iat.UTC().Format(time.RFC3339))
	}
	if exp.Sub(iat) > maxLife {
		return nil, failf(FailureLifetimeExceeded, "exp-iat %s exceeds %s", exp.Sub(iat), maxLife)
	}

	p := &Principal{
		PrincipalID: sub,
		Issuer:      iss,
		Subject:     sub,
		Audience:    v.Audience,
		AuthMethod:  AuthMethodJWTEdDSA,
		VerifiedAt:  now.UTC(),
		ExpiresAt:   exp.UTC(),
	}
	if len(v.SafeClaims) > 0 {
		p.Claims = make(map[string]string, len(v.SafeClaims))
		for _, name := range v.SafeClaims {
			if s, ok := claims[name].(string); ok && s != "" {
				p.Claims[name] = s
			}
		}
	}
	return p, nil
}

func audienceContains(aud any, want string) bool {
	if want == "" {
		return false
	}
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		if n <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(n), 0), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i <= 0 {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	}
	return time.Time{}, false
}

var errNoKeys = errors.New("key set is empty")

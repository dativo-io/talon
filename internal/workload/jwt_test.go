package workload

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type testIssuer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

func newIssuer(t *testing.T, kid string) *testIssuer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testIssuer{priv: priv, pub: pub, kid: kid}
}

func (i *testIssuer) jwks() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{i.kid: i.pub}
}

func (i *testIssuer) mint(t *testing.T, header map[string]any, claims map[string]any) string {
	t.Helper()
	if header == nil {
		header = map[string]any{"alg": "EdDSA", "typ": "openshell-ext+jwt", "kid": i.kid}
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sig := ed25519.Sign(i.priv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

var fixedNow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func baseClaims() map[string]any {
	return map[string]any{
		"iss":         "openshell-gateway:gw-1",
		"aud":         "urn:openshell:extension:middleware:talon",
		"sub":         "spiffe://openshell/sandbox/sb-123",
		"caller_kind": "supervisor",
		"sandbox_id":  "sb-123",
		"jti":         "j1",
		"iat":         fixedNow.Add(-time.Minute).Unix(),
		"exp":         fixedNow.Add(14 * time.Minute).Unix(),
	}
}

func verifier(keys KeySet) *JWTVerifier {
	return &JWTVerifier{
		Issuer:     "openshell-gateway:gw-1",
		Audience:   "urn:openshell:extension:middleware:talon",
		Type:       "openshell-ext+jwt",
		Keys:       keys,
		SafeClaims: []string{"sandbox_id", "caller_kind"},
		Now:        func() time.Time { return fixedNow },
	}
}

func TestJWTVerifier_Valid(t *testing.T) {
	iss := newIssuer(t, "k1")
	v := verifier(NewStaticKeySet(iss.jwks()))
	p, err := v.Verify(iss.mint(t, nil, baseClaims()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Subject != "spiffe://openshell/sandbox/sb-123" || p.PrincipalID != p.Subject {
		t.Errorf("principal = %+v", p)
	}
	if p.Claim("sandbox_id") != "sb-123" || p.Claim("caller_kind") != "supervisor" {
		t.Errorf("safe claims not retained: %+v", p.Claims)
	}
	if p.Claim("jti") != "" {
		t.Errorf("unselected claim retained")
	}
	if p.AuthMethod != AuthMethodJWTEdDSA || p.Issuer != v.Issuer || p.Audience != v.Audience {
		t.Errorf("normalization wrong: %+v", p)
	}
	if !p.ExpiresAt.Equal(fixedNow.Add(14 * time.Minute)) {
		t.Errorf("exp = %v", p.ExpiresAt)
	}
}

func TestJWTVerifier_AudienceList(t *testing.T) {
	iss := newIssuer(t, "k1")
	v := verifier(NewStaticKeySet(iss.jwks()))
	c := baseClaims()
	c["aud"] = []string{"other", v.Audience}
	if _, err := v.Verify(iss.mint(t, nil, c)); err != nil {
		t.Fatalf("aud list should verify: %v", err)
	}
}

func TestJWTVerifier_Failures(t *testing.T) {
	iss := newIssuer(t, "k1")
	other := newIssuer(t, "k1") // same kid, different key: forged signature
	v := verifier(NewStaticKeySet(iss.jwks()))

	cases := []struct {
		name  string
		token func() string
		code  string
	}{
		{"missing", func() string { return "" }, FailureMissing},
		{"malformed", func() string { return "a.b" }, FailureMalformed},
		{"garbage segments", func() string { return "!!.!!.!!" }, FailureMalformed},
		{"alg none", func() string {
			return iss.mint(t, map[string]any{"alg": "none", "typ": "openshell-ext+jwt", "kid": "k1"}, baseClaims())
		}, FailureAlgUnsupported},
		{"alg hs256", func() string {
			return iss.mint(t, map[string]any{"alg": "HS256", "typ": "openshell-ext+jwt", "kid": "k1"}, baseClaims())
		}, FailureAlgUnsupported},
		{"wrong typ", func() string {
			return iss.mint(t, map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": "k1"}, baseClaims())
		}, FailureTypeMismatch},
		{"no kid", func() string {
			return iss.mint(t, map[string]any{"alg": "EdDSA", "typ": "openshell-ext+jwt"}, baseClaims())
		}, FailureKeyUnknown},
		{"unknown kid", func() string {
			return iss.mint(t, map[string]any{"alg": "EdDSA", "typ": "openshell-ext+jwt", "kid": "rotated"}, baseClaims())
		}, FailureKeyUnknown},
		{"forged signature", func() string { return other.mint(t, nil, baseClaims()) }, FailureSignatureInvalid},
		{"tampered payload", func() string {
			tok := iss.mint(t, nil, baseClaims())
			c := baseClaims()
			c["sub"] = "spiffe://openshell/sandbox/victim"
			forged := iss.mint(t, nil, c)
			// header+payload from the forged token, signature from the real one
			parts := splitToken(tok)
			fparts := splitToken(forged)
			return fparts[0] + "." + fparts[1] + "." + parts[2]
		}, FailureSignatureInvalid},
		{"wrong issuer", func() string { c := baseClaims(); c["iss"] = "openshell-gateway:evil"; return iss.mint(t, nil, c) }, FailureIssuerMismatch},
		{"wrong audience", func() string {
			c := baseClaims()
			c["aud"] = "urn:openshell:extension:middleware:other"
			return iss.mint(t, nil, c)
		}, FailureAudienceMismatch},
		{"missing sub", func() string { c := baseClaims(); delete(c, "sub"); return iss.mint(t, nil, c) }, FailureClaimsInvalid},
		{"missing exp", func() string { c := baseClaims(); delete(c, "exp"); return iss.mint(t, nil, c) }, FailureClaimsInvalid},
		{"expired", func() string {
			c := baseClaims()
			c["exp"] = fixedNow.Add(-time.Minute).Unix()
			return iss.mint(t, nil, c)
		}, FailureExpired},
		{"not yet valid", func() string {
			c := baseClaims()
			c["nbf"] = fixedNow.Add(5 * time.Minute).Unix()
			return iss.mint(t, nil, c)
		}, FailureNotYetValid},
		{"iat in future", func() string {
			c := baseClaims()
			c["iat"] = fixedNow.Add(5 * time.Minute).Unix()
			return iss.mint(t, nil, c)
		}, FailureNotYetValid},
		{"lifetime exceeded", func() string {
			c := baseClaims()
			c["iat"] = fixedNow.Add(-time.Minute).Unix()
			c["exp"] = fixedNow.Add(48 * time.Hour).Unix()
			return iss.mint(t, nil, c)
		}, FailureLifetimeExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := v.Verify(tc.token())
			if err == nil {
				t.Fatalf("expected failure %s, got principal %+v", tc.code, p)
			}
			if got := FailureCode(err); got != tc.code {
				t.Errorf("code = %s, want %s (%v)", got, tc.code, err)
			}
			var ve *VerificationError
			if !errors.As(err, &ve) {
				t.Errorf("error is not *VerificationError: %T", err)
			}
		})
	}
}

func TestJWTVerifier_Leeway(t *testing.T) {
	iss := newIssuer(t, "k1")
	v := verifier(NewStaticKeySet(iss.jwks()))
	c := baseClaims()
	c["exp"] = fixedNow.Add(-10 * time.Second).Unix() // within 30s leeway
	if _, err := v.Verify(iss.mint(t, nil, c)); err != nil {
		t.Fatalf("leeway should tolerate 10s skew: %v", err)
	}
}

func TestJWTVerifier_KeySourceUnavailableFailsClosed(t *testing.T) {
	iss := newIssuer(t, "k1")
	v := verifier(failingKeySet{})
	_, err := v.Verify(iss.mint(t, nil, baseClaims()))
	if FailureCode(err) != FailureKeySourceUnavailable {
		t.Fatalf("expected key source unavailable, got %v", err)
	}
}

type failingKeySet struct{}

func (failingKeySet) Key(string) (ed25519.PublicKey, bool, error) {
	return nil, false, errors.New("jwks endpoint down")
}

func TestParseJWKS(t *testing.T) {
	iss := newIssuer(t, "k1")
	doc := map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": base64.RawURLEncoding.EncodeToString(iss.pub)},
		{"kty": "RSA", "kid": "rsa", "n": "x", "e": "AQAB"},
	}}
	data, _ := json.Marshal(doc)
	keys, err := ParseJWKS(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys["k1"].Equal(iss.pub) {
		t.Errorf("keys = %v", keys)
	}
	if _, err := ParseJWKS([]byte(`{"keys":[]}`)); err == nil {
		t.Error("empty JWKS must error")
	}
	if _, err := ParseJWKS([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"bad","x":"AAAA"}]}`)); err == nil {
		t.Error("short key must error")
	}
}

func splitToken(tok string) []string {
	out := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			out = append(out, tok[start:i])
			start = i + 1
		}
	}
	return append(out, tok[start:])
}

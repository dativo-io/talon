package workload

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const hopTestRoot = "12345678901234567890123456789012"

func hopClaims() HopClaims {
	return HopClaims{
		Runtime: "openshell", RuntimeIssuer: "openshell-gateway:gw-1", Subject: "spiffe://openshell/sandbox/sb-1", PrincipalID: "p-1",
		SandboxRef: "sb-1", RequestID: "req-1", Agent: "support", Tenant: "acme", Method: "post", Path: "/v1/action-operations",
		BodySHA256: BodyDigest([]byte(`{"a":1}`)), SessionID: "sess-1",
	}
}

func TestHopSigner_MintVerifyRoundTrip(t *testing.T) {
	s, err := NewHopSigner(hopTestRoot, 0)
	require.NoError(t, err)
	tok, err := s.Mint(hopClaims())
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(tok, "v1."))
	assert.NotContains(t, tok, hopTestRoot)

	c, err := s.Verify(tok, "POST", "/v1/action-operations", BodyDigest([]byte(`{"a":1}`)))
	require.NoError(t, err)
	assert.Equal(t, "support", c.Agent)
	assert.Equal(t, "acme", c.Tenant)
	assert.Equal(t, "POST", c.Method, "method is normalized")
	assert.Equal(t, HopAssertionAudience, c.Audience)
	assert.Equal(t, "sess-1", c.SessionID)
	assert.Len(t, c.JTI, 32)
	assert.Equal(t, int64(60), c.ExpiresAt-c.IssuedAt)

	tok2, _ := s.Mint(hopClaims())
	assert.NotEqual(t, tok, tok2, "every assertion carries a fresh jti")
}

func TestHopSigner_RequestBinding(t *testing.T) {
	s, _ := NewHopSigner(hopTestRoot, 0)
	tok, _ := s.Mint(hopClaims())
	body := BodyDigest([]byte(`{"a":1}`))
	for name, tc := range map[string]struct{ method, path, body string }{
		"other method": {"GET", "/v1/action-operations", body},
		"other path":   {"POST", "/v1/action-operations/op-1/attempts", body},
		"other body":   {"POST", "/v1/action-operations", BodyDigest([]byte(`{"a":2}`))},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Verify(tok, tc.method, tc.path, tc.body)
			assert.Equal(t, FailureHopBindingMismatch, FailureCode(err))
		})
	}
}

func TestHopSigner_Tamper(t *testing.T) {
	s, _ := NewHopSigner(hopTestRoot, 0)
	tok, _ := s.Mint(hopClaims())
	body := BodyDigest([]byte(`{"a":1}`))
	parts := strings.Split(tok, ".")

	// Flip a byte of the claims: the signature no longer matches.
	claims := []byte(parts[1])
	claims[len(claims)/2] ^= 0x01
	_, err := s.Verify(parts[0]+"."+string(claims)+"."+parts[2], "POST", "/v1/action-operations", body)
	assert.Equal(t, FailureHopSignatureInvalid, FailureCode(err))

	// Signature from a different deployment key.
	other, _ := NewHopSigner("abcdefghijklmnopqrstuvwxyz0123456789", 0)
	otherTok, _ := other.Mint(hopClaims())
	_, err = s.Verify(otherTok, "POST", "/v1/action-operations", body)
	assert.Equal(t, FailureHopSignatureInvalid, FailureCode(err))

	for name, bad := range map[string]string{
		"empty":     "",
		"two parts": parts[0] + "." + parts[1],
		"version":   "v0." + parts[1] + "." + parts[2],
		"huge":      "v1." + strings.Repeat("A", maxHopTokenBytes) + ".x",
		"bad sig":   parts[0] + "." + parts[1] + ".!!!",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Verify(bad, "POST", "/v1/action-operations", body)
			assert.Equal(t, FailureHopMalformed, FailureCode(err), "%v", err)
		})
	}
}

func TestHopSigner_Lifetime(t *testing.T) {
	s, _ := NewHopSigner(hopTestRoot, 10*time.Second)
	base := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	tok, _ := s.Mint(hopClaims())
	body := BodyDigest([]byte(`{"a":1}`))

	s.now = func() time.Time { return base.Add(10*time.Second + hopClockSkew - time.Second) }
	_, err := s.Verify(tok, "POST", "/v1/action-operations", body)
	require.NoError(t, err, "within ttl plus skew")

	s.now = func() time.Time { return base.Add(10*time.Second + hopClockSkew + time.Second) }
	_, err = s.Verify(tok, "POST", "/v1/action-operations", body)
	assert.Equal(t, FailureHopExpired, FailureCode(err))

	s.now = func() time.Time { return base.Add(-hopClockSkew - time.Second) }
	_, err = s.Verify(tok, "POST", "/v1/action-operations", body)
	assert.Equal(t, FailureHopNotYetValid, FailureCode(err))
}

func TestNewHopSigner_Bounds(t *testing.T) {
	_, err := NewHopSigner("short", 0)
	assert.Error(t, err)
	_, err = NewHopSigner(hopTestRoot, time.Second)
	assert.Error(t, err)
	_, err = NewHopSigner(hopTestRoot, time.Hour)
	assert.Error(t, err)
	s, err := NewHopSigner(hopTestRoot, MaxHopAssertionTTL)
	require.NoError(t, err)
	assert.Equal(t, MaxHopAssertionTTL, s.TTL())

	_, err = s.Mint(HopClaims{Agent: "a"})
	assert.Error(t, err, "incomplete claims are refused")
}

package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Signer creates and verifies HMAC-SHA256 signatures for evidence integrity.
type Signer struct {
	key []byte
}

// NewSigner creates an HMAC-SHA256 signer. Key must be at least 32 raw bytes or 64+ hex characters (decoded ≥32 bytes).
func NewSigner(key string) (*Signer, error) {
	keyBytes, err := resolveSigningKey(key)
	if err != nil {
		return nil, err
	}
	return &Signer{key: keyBytes}, nil
}

// resolveSigningKey interprets the key as raw bytes or hex (64+ even hex chars → decoded bytes, requiring ≥32 bytes).
func resolveSigningKey(key string) ([]byte, error) {
	if len(key) >= 64 && len(key)%2 == 0 && isHexString(key) {
		decoded, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("signing key hex decode: %w", err)
		}
		if len(decoded) < 32 {
			return nil, fmt.Errorf("signing key hex must decode to at least 32 bytes (got %d)", len(decoded))
		}
		return decoded, nil
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("signing key must be at least 32 bytes (got %d)", len(key))
	}
	return []byte(key), nil
}

func isHexString(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Sign creates an HMAC-SHA256 signature for the given data.
func (s *Signer) Sign(data []byte) (string, error) {
	h := hmac.New(sha256.New, s.key)
	if _, err := h.Write(data); err != nil {
		return "", err
	}
	return "hmac-sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Verify checks if a signature is valid for the given data.
func (s *Signer) Verify(data []byte, signature string) bool {
	expected, err := s.Sign(data)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(signature))
}

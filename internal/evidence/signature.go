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

// NewSigner creates an HMAC-SHA256 signer. Key must be at least 32 bytes.
func NewSigner(key string) (*Signer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("signing key must be at least 32 bytes")
	}
	return &Signer{key: []byte(key)}, nil
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

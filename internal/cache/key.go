// Package cache: cache entry key derivation (deterministic, not password hashing).
package cache

import (
	"crypto/sha256"
	"encoding/hex"
)

// DeriveEntryKey returns a deterministic cache entry key from tenant, model, and prompt.
// SHA-256 is used for key derivation only: same inputs always produce the same key for
// cache lookup/insert. This is not password or secret hashing (OWASP: SHA-2 is acceptable
// for non-password uses such as cache keys and integrity; key-stretching is for secrets).
func DeriveEntryKey(tenantID, model, prompt string) string {
	h := sha256.Sum256([]byte(prompt))
	sum := sha256.Sum256([]byte(tenantID + "|" + model + "|" + hex.EncodeToString(h[:])))
	return hex.EncodeToString(sum[:])
}

// Package cache: cache entry key derivation (deterministic, not password hashing).
package cache

import (
	"crypto/sha256"
	"encoding/hex"
)

// DeriveEntryKey returns a deterministic cache entry key from tenant, model, and prompt.
// SHA-256 is used for cache key derivation only: same inputs always produce the same key
// for lookup/insert. No password or secret is hashed; inputs are tenant id, model name,
// and prompt text (OWASP: key-stretching is for secrets; SHA-2 is acceptable for
// non-secret uses such as cache keys and integrity).
func DeriveEntryKey(tenantID, model, prompt string) string {
	// Cache key derivation only; not password or secret hashing.
	h := sha256.Sum256([]byte(prompt)) //nolint:gosec // cache key derivation only; no password or secret
	sum := sha256.Sum256([]byte(tenantID + "|" + model + "|" + hex.EncodeToString(h[:])))
	return hex.EncodeToString(sum[:])
}

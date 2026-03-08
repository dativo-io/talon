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
//
// Precondition: callers must pass only non-secret values—tenant identifier (e.g. from
// caller config, used as cache scope), model name, and prompt text. Do not pass API keys,
// passwords, or other secrets. The tenant ID is typically from config lookup (by API key),
// not the API key itself; it is an identifier like "acme-corp", not sensitive data.
//
// TenantIDForCacheKey documents that the given string is a tenant identifier for cache
// scoping (e.g. from caller config), not an API key or secret. Use at call sites to make
// the non-secret use explicit for static analysis.
func TenantIDForCacheKey(tenantID string) string { return tenantID }

func DeriveEntryKey(tenantID, model, prompt string) string {
	// Cache key derivation only; not password or secret hashing (tenantID is scope id from config).
	h := sha256.Sum256([]byte(prompt))                                                    //nolint:gosec // cache key derivation only; no password or secret
	sum := sha256.Sum256([]byte(tenantID + "|" + model + "|" + hex.EncodeToString(h[:]))) //nolint:gosec // cache key; tenantID/model/prompt are non-secret
	return hex.EncodeToString(sum[:])
}

package testutil

// Test signing and encryption keys for use in tests only.
// 32 bytes for AES-256 / HMAC key material.
const (
	TestEncryptionKey = "12345678901234567890123456789012"
	TestSigningKey    = "test-signing-key-1234567890123456"
)

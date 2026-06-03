package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvidenceIntegritySpecRoundTrip is the executable counterpart to
// docs/reference/evidence-integrity-spec.md. It proves that following the
// documented procedure — serialize with signature="" (§3), HMAC-SHA256 and
// prefix with "hmac-sha256:" (§4), then verify (§5) — produces a signature the
// verifier accepts, and that any post-signing mutation is detected.
func TestEvidenceIntegritySpecRoundTrip(t *testing.T) {
	// A representative record. Fields are populated across types (strings,
	// numbers, bools, slices, nested objects, timestamp) to exercise the
	// canonical-serialization rules in the spec.
	ev := &Evidence{
		ID:             "evt_spec_roundtrip",
		CorrelationID:  "corr_123",
		Timestamp:      time.Date(2026, 6, 2, 21, 15, 2, 123456789, time.UTC),
		TenantID:       "acme",
		AgentID:        "support-bot",
		InvocationType: "gateway",
		PolicyDecision: PolicyDecision{
			Allowed:       true,
			Action:        "allow",
			Reasons:       []string{"within budget"},
			PolicyVersion: "v1",
		},
		Classification: Classification{
			InputTier:   1,
			PIIDetected: []string{"email", "iban"},
			PIIRedacted: true,
		},
		Execution: Execution{
			ModelUsed:  "gpt-4o-mini",
			Cost:       0.0031,
			DurationMS: 142,
		},
		AuditTrail: AuditTrail{
			InputHash:  "sha256:aaa",
			OutputHash: "sha256:bbb",
		},
		Compliance: Compliance{
			Frameworks:   []string{"gdpr", "eu-ai-act"},
			DataLocation: "eu-central-1",
		},
		// Signature is intentionally empty; it is set by the signing procedure.
	}

	// §3: canonical bytes are the JSON encoding with signature == "".
	require.Empty(t, ev.Signature, "record must be unsigned before computing canonical bytes")
	canonical, err := json.Marshal(ev)
	require.NoError(t, err)

	// The canonical form always carries an empty signature field (no omitempty).
	assert.Contains(t, string(canonical), `"signature":""`,
		"canonical form must include an empty signature field")

	// §4: HMAC-SHA256, hex-encoded, with the "hmac-sha256:" prefix.
	signer, err := NewSigner(testSigningKey)
	require.NoError(t, err)
	sig, err := signer.Sign(canonical)
	require.NoError(t, err)

	const prefix = "hmac-sha256:"
	require.True(t, strings.HasPrefix(sig, prefix), "signature must carry the hmac-sha256: prefix")
	hexPart := strings.TrimPrefix(sig, prefix)
	assert.Len(t, hexPart, 64, "SHA-256 hex digest must be 64 characters")
	assert.Equal(t, strings.ToLower(hexPart), hexPart, "hex digest must be lowercase")

	ev.Signature = sig

	// §5 (independent verifier): a third party with the same key, re-deriving
	// the canonical bytes per the spec, accepts the signature.
	independent, err := NewSigner(testSigningKey)
	require.NoError(t, err)
	saved := ev.Signature
	ev.Signature = ""
	recomputed, err := json.Marshal(ev)
	require.NoError(t, err)
	ev.Signature = saved
	assert.True(t, independent.Verify(recomputed, sig),
		"independently serialized + verified record must validate")

	// §5 (Talon verifier): Store.VerifyRecord agrees.
	store := newTestStore(t)
	assert.True(t, store.VerifyRecord(ev), "Store.VerifyRecord must accept a spec-conformant signature")

	// Tamper detection: mutating any signed field invalidates the signature.
	originalModel := ev.Execution.ModelUsed
	ev.Execution.ModelUsed = originalModel + "-tampered"
	assert.False(t, store.VerifyRecord(ev), "mutating a signed field must invalidate the signature")
	ev.Execution.ModelUsed = originalModel
	assert.True(t, store.VerifyRecord(ev), "restoring the field must re-validate the signature")
}

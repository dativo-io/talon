package evidence

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const provenanceTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef"

// Spec 1.11 append rule: records without the new objects keep identical
// canonical bytes (pre-1.11 signatures verify unchanged), records with them
// round-trip and sign, and a legacy verifier's view of a 1.11 record is
// exactly the record minus the two appended members.
func TestProvenanceFields_AppendRuleAndRoundTrip(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "e.db"), provenanceTestKey)
	require.NoError(t, err)
	defer store.Close()

	base := &Evidence{
		ID: "ev_legacy", CorrelationID: "c1", Timestamp: time.Now().UTC(), TenantID: "acme", AgentID: "a",
		InvocationType: "gateway", PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
	}
	require.NoError(t, store.Store(t.Context(), base))
	legacyJSON, _ := json.Marshal(base)
	require.NotContains(t, string(legacyJSON), `"enforcement"`)
	require.NotContains(t, string(legacyJSON), `"workload_identity"`)
	require.True(t, store.VerifyRecord(base))

	withProv := &Evidence{
		ID: "ev_delegated", CorrelationID: "c2", Timestamp: time.Now().UTC(), TenantID: "acme", AgentID: "a",
		InvocationType: "gateway", PolicyDecision: PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"model not allowed"}},
		WorkloadIdentity: &WorkloadIdentity{
			Status: WorkloadIdentityVerified, Runtime: "openshell", AuthMethod: "jwt_eddsa",
			Issuer: "openshell-gateway:gw", Subject: "spiffe://openshell/sandbox/sb", PrincipalID: "spiffe://openshell/sandbox/sb",
			Audience: "urn:x", Binding: WorkloadIdentityBindingAgentConfig, VerifiedAt: "2026-09-30T00:00:00Z",
		},
		Enforcement: &Enforcement{
			Mechanism: MechanismDelegate, Boundary: BoundaryExternalRuntime, DecisionAuthority: BoundaryTalon,
			Provenance: ProvenanceDelegatedExpected, DecisionReturnedVia: "openshell_middleware",
			Runtime: &ExternalRuntimeRef{Type: "openshell", ID: "openshell-gateway:gw", Reference: "sb", RequestID: "r1"},
		},
	}
	require.NoError(t, store.Store(t.Context(), withProv))
	require.True(t, store.VerifyRecord(withProv))
	got, err := store.Get(t.Context(), "ev_delegated")
	require.NoError(t, err)
	require.True(t, store.VerifyRecord(got))
	require.Equal(t, withProv.Enforcement, got.Enforcement)
	require.Equal(t, withProv.WorkloadIdentity, got.WorkloadIdentity)

	// Field order: the two objects are the last members of the record.
	raw, _ := json.Marshal(got)
	wi := bytes.Index(raw, []byte(`"workload_identity"`))
	en := bytes.Index(raw, []byte(`"enforcement"`))
	cb := bytes.Index(raw, []byte(`"cost_budget"`))
	require.Greater(t, wi, 0)
	require.Greater(t, en, wi)
	require.Equal(t, -1, cb, "omitted when nil")
	require.True(t, strings.HasSuffix(strings.TrimSpace(string(raw)), `}}`), "enforcement is the final member: %s", raw)

	// A tampered provenance claim must not verify: upgrading
	// delegated_expected → external_verified is detectable.
	tampered := *got
	e := *got.Enforcement
	e.Provenance = ProvenanceExternalVerified
	tampered.Enforcement = &e
	require.False(t, store.VerifyRecord(&tampered))
}

func TestExternalRuntimeEventIsNotRequestClass(t *testing.T) {
	require.Equal(t, ClassExternalEvent, RecordClassOf(InvocationTypeExternalRuntimeEvent))
	require.NotEqual(t, ClassRequest, RecordClassOf(InvocationTypeExternalRuntimeEvent))
}

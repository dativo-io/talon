package action

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/govcode"
)

// Every stable code the action domain can emit is registered in the one
// governance registry under the SAME spelling (#372 parity: HTTP, MCP, CLI
// and audit share domain codes; adapters never invent a competing name).
func TestDomainCodes_RegisteredInGovcode(t *testing.T) {
	for _, code := range []string{
		CodeOperationIDRequired, CodeOperationConflict, CodeActionNotFound, CodeActionSchemaInvalid, CodePolicyDenied,
		CodeApprovalRequired, CodeApprovalPending, CodeApprovalRejected, CodeApprovalExpired, CodeApprovalNotAuthorized,
		CodeApprovalAlreadyDecided, CodeApprovalBindingStale, CodeOperationAlreadySucceeded, CodeOperationOutcomeUnknown,
		CodeAttemptAlreadyInProgress, CodeAttemptNotAuthorized, CodePayloadUnavailable, CodeExecutionUnsupported,
		CodeNotFound, CodeInvalidRequest, CodeStoreUnavailable,
	} {
		spec, ok := govcode.Lookup(code)
		require.True(t, ok, "action code %q is not registered in govcode", code)
		require.False(t, spec.IsTarget(), "action code %q is emitted by the shipped domain and must not be tagged target", code)
		require.Contains(t, spec.Producers, govcode.ProducerAction, code)
	}
}

// The projection carries a reference to the record the call committed: the
// id is a real record under the operation's correlation id, committed=true,
// the sequence matches; reads commit nothing and carry no reference; an
// evidenced refusal (conflict) references its own committed record.
func TestProjection_EvidenceReferenceIsACommittedRecord(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res := h.establish(t, "op-ev-1", "create_refund_request", refundArgs)
	require.True(t, res.Created)
	ref := res.Operation.Evidence
	require.NotNil(t, ref, "establish must reference the committed lifecycle record")
	require.True(t, ref.Committed)
	require.NotEmpty(t, ref.ID)
	recs, err := h.store.ListByCorrelationID(ctx, res.Operation.OperationRef)
	require.NoError(t, err)
	ids := map[string]int{}
	for _, r := range recs {
		ids[r.ID] = r.ActionLifecycle.Sequence
	}
	require.Contains(t, ids, ref.ID)
	require.Equal(t, ids[ref.ID], ref.Sequence)
	require.Equal(t, len(recs), ref.Sequence, "the reference is the LAST record this call committed (approval_requested)")

	proj, err := h.svc.Get(ctx, "op-ev-1")
	require.NoError(t, err)
	require.Nil(t, proj.Evidence, "a read commits nothing and references nothing")

	// Same id, changed payload: the conflict record commits and is referenced
	// on the refusal's state projection.
	changed := []byte(`{"ticket_id":"T-1842","amount":99.00,"currency":"EUR","iban":"DE89370400440532013000"}`)
	_, err = h.svc.Establish(ctx, EstablishRequest{OperationID: "op-ev-1", Action: "create_refund_request", Arguments: changed})
	require.Equal(t, CodeOperationConflict, CodeOf(err))
	var de *Error
	require.ErrorAs(t, err, &de)
	require.NotNil(t, de.State)
	require.NotNil(t, de.State.Evidence)
	require.True(t, de.State.Evidence.Committed)
	conflict, err := h.store.Get(ctx, de.State.Evidence.ID)
	require.NoError(t, err)
	require.Equal(t, CodeOperationConflict, conflict.ActionLifecycle.RefusalCode)
}

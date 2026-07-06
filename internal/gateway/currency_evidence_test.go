package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Evidence records stamp the pricing table's currency at write time (#216),
// on ALLOWED requests and — load-bearing for the #107 governed-session demo —
// on session-budget DENIALS, which must also carry the session id so
// `talon audit verify --session` sees every decision in the session.
func TestEvidenceCurrencyStamp_AllowedAndSessionDeny(t *testing.T) {
	t.Parallel()

	t.Run("allowed request carries currency and session id", func(t *testing.T) {
		t.Parallel()
		evStore, _, handler := newSessionBudgetGateway(t, ModeEnforce, 10)
		rec := sbDo(t, handler, "openai", sbTenantKeyA, "sess-cur-allow")
		require.Equal(t, http.StatusOK, rec.Code)
		ev := lastGatewayEvidence(t, evStore, "tenant-a")
		assert.Equal(t, "USD", ev.Execution.Currency)
		assert.Equal(t, "sess-cur-allow", ev.SessionID)
	})

	t.Run("session budget deny carries currency and session id", func(t *testing.T) {
		t.Parallel()
		// Cap below the deterministic pre-request estimate (1.0): the very
		// first request is denied pre-forward.
		evStore, _, handler := newSessionBudgetGateway(t, ModeEnforce, 0.5)
		rec := sbDo(t, handler, "openai", sbTenantKeyA, "sess-cur-deny")
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Contains(t, rec.Body.String(), "session_budget_exceeded")
		ev := lastGatewayEvidence(t, evStore, "tenant-a")
		require.False(t, ev.PolicyDecision.Allowed)
		assert.Equal(t, "USD", ev.Execution.Currency)
		assert.Equal(t, "sess-cur-deny", ev.SessionID,
			"deny evidence must attach to the session for audit verify --session")
		require.NotNil(t, ev.SessionBudget)
	})
}

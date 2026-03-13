package scoring

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func TestCompute(t *testing.T) {
	list := []evidence.Evidence{
		{AgentID: "a1", PolicyDecision: evidence.PolicyDecision{Allowed: true}, AuditTrail: evidence.AuditTrail{InputHash: "h"}, Signature: "sig"},
		{AgentID: "a1", PolicyDecision: evidence.PolicyDecision{Allowed: false}, AuditTrail: evidence.AuditTrail{InputHash: "h"}, Signature: "sig"},
	}
	s := Compute(list, "a1")
	require.Equal(t, "a1", s.AgentID)
	require.Greater(t, s.Score, 0.0)
}

package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResidualBlockMessagesIncludeApprovalGuidance(t *testing.T) {
	msg := residualBlockMessage("Request blocked", []string{"email"})
	assert.Contains(t, msg, "types: email")
	assert.Contains(t, msg, "use approval workflow")

	serverMsg := mcpResidualBlockMessage("Tool result blocked", nil)
	assert.Contains(t, serverMsg, "use approval workflow")
	assert.Contains(t, serverMsg, "re-run redaction")
}

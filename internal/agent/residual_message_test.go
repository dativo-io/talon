package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResidualPIIMessageIncludesApprovalGuidance(t *testing.T) {
	msg := residualPIIMessage("tool result blocked", []string{"phone"})
	assert.Contains(t, msg, "types: phone")
	assert.Contains(t, msg, "use approval workflow")
	assert.Contains(t, msg, "re-scan")
}

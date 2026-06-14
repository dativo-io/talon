package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResidualPIIBlockMessageIncludesApprovalGuidance(t *testing.T) {
	msg := residualPIIBlockMessage("Response blocked", []string{"email", "iban"})
	assert.Contains(t, msg, "types: email, iban")
	assert.Contains(t, msg, "use approval workflow")
	assert.Contains(t, msg, "re-run redaction")
}

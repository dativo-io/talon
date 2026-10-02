package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TALON_MCP_ALLOWED_ORIGINS is the one MCP origin setting; the same parsed
// list feeds both MCP transports. "*" is never honoured.
func TestServeMCPOrigins(t *testing.T) {
	t.Setenv("TALON_MCP_ALLOWED_ORIGINS", "")
	assert.Nil(t, serveMCPOrigins())
	t.Setenv("TALON_MCP_ALLOWED_ORIGINS", " https://console.example.com , *, ,http://ops.internal:8443 ")
	assert.Equal(t, []string{"https://console.example.com", "http://ops.internal:8443"}, serveMCPOrigins())
	t.Setenv("TALON_MCP_ALLOWED_ORIGINS", "*")
	assert.Nil(t, serveMCPOrigins(), "a wildcard alone allows nothing extra")
}

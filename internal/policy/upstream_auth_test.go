package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ValidateUpstreamAuth is the ONE upstream-credential contract (MCP proxy
// upstream and trusted action sources): a configured credential header may
// never collide with a header the shared MCP client owns, and must be a
// legal header name; legitimate custom credential headers are accepted.
func TestValidateUpstreamAuth(t *testing.T) {
	str := func(s string) *string { return &s }
	accepted := map[string]*UpstreamAuthConfig{
		"nil block":        nil,
		"Authorization":    {SecretName: "k"},
		"explicit header":  {SecretName: "k", Header: "Authorization"},
		"X-Api-Key":        {SecretName: "k", Header: "X-Api-Key"},
		"x-vendor-token":   {SecretName: "k", Header: "x-vendor-token"},
		"raw scheme":       {SecretName: "k", Header: "X-Api-Key", Scheme: str("")},
		"Basic scheme":     {SecretName: "k", Scheme: str("Basic")},
		"Mcp-Paramount ok": {SecretName: "k", Header: "Mcp-Paramount"}, // not the Mcp-Param- prefix
	}
	for name, cfg := range accepted {
		t.Run("accept "+name, func(t *testing.T) { assert.NoError(t, ValidateUpstreamAuth(cfg)) })
	}
	rejected := map[string]*UpstreamAuthConfig{
		"missing secret_name":          {Header: "X-Api-Key"},
		"MCP-Protocol-Version":         {SecretName: "k", Header: "MCP-Protocol-Version"},
		"mcp-protocol-version (lower)": {SecretName: "k", Header: "mcp-protocol-version"},
		"Mcp-Method":                   {SecretName: "k", Header: "Mcp-Method"},
		"MCP-METHOD (upper)":           {SecretName: "k", Header: "MCP-METHOD"},
		"Mcp-Name":                     {SecretName: "k", Header: "Mcp-Name"},
		"Mcp-Param-Foo":                {SecretName: "k", Header: "Mcp-Param-Foo"},
		"mcp-param-region (lower)":     {SecretName: "k", Header: "mcp-param-region"},
		"Content-Type":                 {SecretName: "k", Header: "Content-Type"},
		"Accept":                       {SecretName: "k", Header: "accept"},
		"Content-Length":               {SecretName: "k", Header: "Content-Length"},
		"Host":                         {SecretName: "k", Header: "Host"},
		"Transfer-Encoding":            {SecretName: "k", Header: "Transfer-Encoding"},
		"malformed token (space)":      {SecretName: "k", Header: "X Api Key"},
		"malformed token (colon)":      {SecretName: "k", Header: "X-Api-Key:"},
		"malformed token (CRLF)":       {SecretName: "k", Header: "X-Api-Key\r\nEvil: 1"},
		"scheme with whitespace":       {SecretName: "k", Scheme: str("Bearer extra")},
		"scheme with CRLF":             {SecretName: "k", Scheme: str("Bearer\r\nMcp-Method: x")},
	}
	for name, cfg := range rejected {
		t.Run("reject "+name, func(t *testing.T) {
			err := ValidateUpstreamAuth(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "auth.")
		})
	}
}

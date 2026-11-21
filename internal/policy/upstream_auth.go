package policy

import (
	"fmt"
	"strings"

	"github.com/dativo-io/talon/internal/mcp/wire"
)

// UpstreamAuthConfig is the vault-backed upstream credential surface (#358).
type UpstreamAuthConfig struct {
	// SecretName is the vault entry holding the upstream credential (required).
	SecretName string `yaml:"secret_name" json:"secret_name"`
	// Header receives the credential; default "Authorization".
	Header string `yaml:"header,omitempty" json:"header,omitempty"`
	// Scheme prefixes the value: absent -> "Bearer"; explicit "" -> raw
	// secret value (pointer distinguishes absent from empty).
	Scheme *string `yaml:"scheme,omitempty" json:"scheme,omitempty"`
}

// ValidateUpstreamAuth is the ONE contract for an operator-configured
// upstream credential block (a trusted MCP action source, #431): secret_name is required; the header, when given, must be a legal
// HTTP field-name token that does not collide (case-insensitively) with a
// header the shared MCP client owns (MCP-Protocol-Version, Mcp-Method,
// Mcp-Name, any Mcp-Param-*, Content-Type, Accept, framing headers); the
// scheme, when given, must be a token (no whitespace, no CR/LF). Legitimate
// custom credential headers such as X-Api-Key are accepted. A nil block is
// valid (no upstream auth).
func ValidateUpstreamAuth(auth *UpstreamAuthConfig) error {
	if auth == nil {
		return nil
	}
	if strings.TrimSpace(auth.SecretName) == "" {
		return fmt.Errorf("auth.secret_name is required when the auth block is present")
	}
	if auth.Header != "" {
		if !wire.IsHeaderToken(auth.Header) {
			return fmt.Errorf("auth.header %q is not a valid HTTP header name", auth.Header)
		}
		if wire.IsReservedClientHeader(auth.Header) {
			return fmt.Errorf("auth.header %q is owned by the MCP client contract (protocol version, method/name integrity, Mcp-Param-*, content framing) and cannot carry a credential", auth.Header)
		}
	}
	if auth.Scheme != nil && *auth.Scheme != "" && !wire.IsHeaderToken(*auth.Scheme) {
		return fmt.Errorf("auth.scheme %q must be a single token (e.g. Bearer) or empty", *auth.Scheme)
	}
	return nil
}

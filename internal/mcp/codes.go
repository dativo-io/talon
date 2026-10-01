package mcp

// ServerVersion is stamped by the serve command at startup so server/discover
// and every result's _meta serverInfo advertise the real build version
// without an import cycle on internal/cmd. "dev" when unset (tests, embedders).
var ServerVersion = "dev"

// Stable machine-readable denial codes carried in JSON-RPC error.data as
// {"talon_code": "..."} (#369). Codes are the contract; messages are prose
// and may change. Documented in docs/ARCHITECTURE_MCP_PROXY.md. They describe
// GOVERNANCE outcomes on a validated request; protocol rejections use the
// MCP-defined codes in the wire package and never carry a talon_code.
const (
	TalonCodeToolForbidden      = "TALON_TOOL_FORBIDDEN"      // forbidden_tools match
	TalonCodePolicyDenied       = "TALON_POLICY_DENIED"       // tool-access policy deny
	TalonCodePIIBlocked         = "TALON_PII_BLOCKED"         // PII deny, residual PII, invalid redaction
	TalonCodeScannerUnavailable = "TALON_SCANNER_UNAVAILABLE" // PII scanner fail-closed
	TalonCodeUpstreamError      = "TALON_UPSTREAM_ERROR"      // Talon-shaped upstream failure
)

// talonErrData builds the error.data payload for a denial code.
func talonErrData(code string) map[string]string {
	return map[string]string{"talon_code": code}
}

package mcp

// ServerVersion is stamped by the serve command at startup so server/discover
// and every result's _meta serverInfo advertise the real build version
// without an import cycle on internal/cmd. "dev" when unset (tests, embedders).
var ServerVersion = "dev"

// Deprecated flat denial codes (#369), still carried for one release in
// JSON-RPC error.data as {"talon_code": "..."} next to the versioned
// governance extension (#372, govcode.ExtensionID), which is the contract
// going forward: internal/govcode holds the canonical codes shared with the
// HTTP Action Gateway and the LLM gateway. Protocol rejections use the
// MCP-defined codes in the wire package and carry neither.
const (
	TalonCodeToolForbidden      = "TALON_TOOL_FORBIDDEN"      // forbidden_tools match
	TalonCodePolicyDenied       = "TALON_POLICY_DENIED"       // tool-access policy deny
	TalonCodePIIBlocked         = "TALON_PII_BLOCKED"         // PII deny, residual PII, invalid redaction
	TalonCodeScannerUnavailable = "TALON_SCANNER_UNAVAILABLE" // PII scanner fail-closed
	TalonCodeUpstreamError      = "TALON_UPSTREAM_ERROR"      // Talon-shaped upstream failure
)

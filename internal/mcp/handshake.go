package mcp

import "encoding/json"

// ServerVersion is stamped by the serve command at startup so the MCP
// initialize handshake can advertise the real build version without an
// import cycle on internal/cmd. "dev" when unset (tests, embedders).
var ServerVersion = "dev"

// defaultMCPProtocolVersion is advertised when the client's initialize
// request carries no protocolVersion of its own.
const defaultMCPProtocolVersion = "2025-06-18"

// mcpInitializeResult answers the mandatory MCP initialize handshake LOCALLY
// (#367): both /mcp and /mcp/proxy advertise ONLY the tools capability —
// resources and prompts are not part of the governed surface — and
// initialize is never forwarded upstream, so nothing ungoverned moves. The
// client's requested protocolVersion is echoed (maximizing compatibility on
// the plain-HTTP transport this server speaks); absent one, a fixed recent
// version is advertised.
func mcpInitializeResult(serverName string, params json.RawMessage) map[string]interface{} {
	protocolVersion := defaultMCPProtocolVersion
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(params) > 0 && json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
		protocolVersion = p.ProtocolVersion
	}
	return map[string]interface{}{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    serverName,
			"version": ServerVersion,
		},
	}
}

// Stable machine-readable denial codes carried in JSON-RPC error.data as
// {"talon_code": "..."} (#369). Codes are the contract; messages are prose
// and may change. Documented in docs/ARCHITECTURE_MCP_PROXY.md.
const (
	TalonCodeToolForbidden      = "TALON_TOOL_FORBIDDEN"      // forbidden_tools match
	TalonCodePolicyDenied       = "TALON_POLICY_DENIED"       // tool-access policy deny
	TalonCodePIIBlocked         = "TALON_PII_BLOCKED"         // PII deny, residual PII, invalid redaction
	TalonCodeScannerUnavailable = "TALON_SCANNER_UNAVAILABLE" // PII scanner fail-closed
	TalonCodeMethodNotAllowed   = "TALON_METHOD_NOT_ALLOWED"  // #356 method rejection
	TalonCodeUpstreamError      = "TALON_UPSTREAM_ERROR"      // Talon-shaped upstream failure
)

// talonErrData builds the error.data payload for a denial code.
func talonErrData(code string) map[string]string {
	return map[string]string{"talon_code": code}
}

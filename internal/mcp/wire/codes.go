// Package wire implements the MCP 2026-07-28 Streamable HTTP wire contract
// for Talon's MCP surfaces: one parser, one validation path, one normalized
// request representation and one set of protocol error codes shared by
// every route (#447).
//
// The package owns wire correctness only. It never evaluates policy, never
// touches evidence and never dispatches. Everything it hands to a caller is a
// normalized protocol fact; business authority (tenant, agent, catalog,
// destination, approval) comes from Talon's authenticated runtime, never from
// anything decoded here.
//
// Normative source: https://modelcontextprotocol.io/specification/2026-07-28
// (basic/index, basic/versioning, basic/transports/streamable-http,
// server/discover, server/tools, server/utilities/caching, basic/patterns/mrtr).
package wire

// ProtocolVersion is the only protocol revision this surface speaks. There
// is no negotiation, no fallback and no defaulting of an absent version.
const ProtocolVersion = "2026-07-28"

// SupportedVersions is what server/discover and UnsupportedProtocolVersion
// errors advertise.
var SupportedVersions = []string{ProtocolVersion}

// Standard request headers (streamable-http §Request Metadata). Header
// names are case-insensitive; values are case-sensitive.
const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
	HeaderParamPrefix     = "Mcp-Param-"
)

// Reserved _meta keys (basic/index §_meta).
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaServerInfo         = "io.modelcontextprotocol/serverInfo"
	MetaLogLevel           = "io.modelcontextprotocol/logLevel"
	MetaProgressToken      = "progressToken"
)

// Methods this package understands. The route decides which it serves;
// everything else is -32601 / 404.
const (
	MethodDiscover      = "server/discover"
	MethodToolsList     = "tools/list"
	MethodToolsCall     = "tools/call"
	MethodResourcesRead = "resources/read"
	MethodPromptsGet    = "prompts/get"
)

// Result types (basic/index §ResultType).
const (
	ResultTypeComplete      = "complete"
	ResultTypeInputRequired = "input_required"
)

// Cache scopes (server/utilities/caching).
const (
	CacheScopePublic  = "public"
	CacheScopePrivate = "private"
)

// JSON-RPC and MCP error codes. -32020..-32099 is reserved for the MCP
// specification; nothing else from that range is ever emitted.
const (
	CodeParseError                      = -32700
	CodeInvalidRequest                  = -32600
	CodeMethodNotFound                  = -32601
	CodeInvalidParams                   = -32602
	CodeInternalError                   = -32603
	CodeHeaderMismatch                  = -32020
	CodeMissingRequiredClientCapability = -32021
	CodeUnsupportedProtocolVersion      = -32022
)

// Stable protocol reason codes. They classify a rejection that happened
// BEFORE any trustworthy action could be extracted, are safe to log, and are
// deliberately disjoint from Talon governance codes: a protocol rejection is
// never a policy decision.
const (
	ReasonTransportMethod         = "transport_method_not_allowed"
	ReasonOriginForbidden         = "origin_forbidden"
	ReasonAcceptUnsupported       = "accept_unsupported"
	ReasonContentTypeUnsupported  = "content_type_unsupported"
	ReasonBodyTooLarge            = "body_too_large"
	ReasonParseError              = "parse_error"
	ReasonInvalidRequest          = "invalid_request"
	ReasonBatchUnsupported        = "batch_unsupported"
	ReasonNotificationUnsupported = "notification_method_unsupported"
	ReasonMetaMissing             = "meta_missing"
	ReasonMetaInvalid             = "meta_invalid"
	ReasonVersionHeaderMissing    = "protocol_version_header_missing"
	ReasonVersionHeaderDuplicate  = "protocol_version_header_duplicate"
	ReasonVersionMismatch         = "protocol_version_mismatch"
	ReasonVersionUnsupported      = "protocol_version_unsupported"
	ReasonMethodHeaderMissing     = "method_header_missing"
	ReasonMethodHeaderDuplicate   = "method_header_duplicate"
	ReasonMethodHeaderMismatch    = "method_header_mismatch"
	ReasonNameHeaderMissing       = "name_header_missing"
	ReasonNameHeaderDuplicate     = "name_header_duplicate"
	ReasonNameHeaderMismatch      = "name_header_mismatch"
	ReasonNameHeaderInvalid       = "name_header_invalid"
	ReasonParamHeaderMissing      = "param_header_missing"
	ReasonParamHeaderDuplicate    = "param_header_duplicate"
	ReasonParamHeaderMismatch     = "param_header_mismatch"
	ReasonParamHeaderInvalid      = "param_header_invalid"
	ReasonMethodNotFound          = "method_not_found"
)

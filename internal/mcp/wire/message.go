package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Implementation is the MCP Implementation object (name + version, optional
// display fields). Self-reported, never a security input.
type Implementation struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	WebsiteURL  string `json:"websiteUrl,omitempty"`
}

// Meta is the parsed per-request `_meta` object. Reserved keys are typed;
// every other key is kept verbatim in Extra so forwarding is lossless and
// nothing unknown is interpreted.
type Meta struct {
	ProtocolVersion    string
	ClientInfo         *Implementation
	ClientCapabilities json.RawMessage
	LogLevel           string
	ProgressToken      json.RawMessage
	Extra              map[string]json.RawMessage
}

// Request is the normalized, integrity-checked MCP request handed to a
// route after Accept succeeded. Fields are protocol facts only.
type Request struct {
	ID     json.RawMessage // exact client bytes; never nil for a request
	Method string
	Params json.RawMessage // raw params object (lossless)
	Meta   Meta

	// Name is params.name (tools/call, prompts/get) or params.uri
	// (resources/read) when the method carries one; otherwise "".
	Name string
	// Arguments, RequestState and InputResponses are the tools/call fields
	// preserved verbatim (MRTR retries carry the latter two).
	Arguments      json.RawMessage
	RequestState   string
	InputResponses json.RawMessage
	// Cursor is the list pagination cursor when present.
	Cursor string

	// HeaderParams are the Mcp-Param-* headers found on the request, keyed
	// by the lower-cased name part. They are captured, not trusted: a route
	// validates them against a trusted declaration (ValidateHeaderParams)
	// before any dispatch and never uses them as the argument value.
	HeaderParams map[string]HeaderParam
}

// HeaderParam is one captured Mcp-Param-* header.
type HeaderParam struct {
	Name    string // name part as sent (original case)
	Raw     string
	Decoded string
	Invalid bool // not a valid header value / undecodable sentinel
	Dup     bool // more than one value was sent
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Response is a JSON-RPC response as received from an upstream server.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// envelope is the raw JSON-RPC message as sent by the client. ID keeps the
// exact bytes; nil means the member was absent (a notification), while the
// bytes "null" mean it was present and null (invalid for MCP).
type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Error is a protocol rejection: the HTTP status to answer with, the JSON-RPC
// error to put in the body, and a stable reason code for diagnostics.
type Error struct {
	Status  int
	Code    int
	Message string
	Reason  string
	Data    map[string]any
}

func (e *Error) Error() string { return fmt.Sprintf("mcp protocol %s: %s", e.Reason, e.Message) }

func newErr(status, code int, reason, msg string) *Error {
	return &Error{Status: status, Code: code, Reason: reason, Message: msg}
}

func headerMismatch(reason, msg string) *Error {
	return newErr(http.StatusBadRequest, CodeHeaderMismatch, reason, msg)
}

// parseMessage decodes one JSON-RPC message. Batches (arrays) are not part
// of MCP and are refused.
func parseMessage(body []byte) (*envelope, *Error) {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, newErr(http.StatusBadRequest, CodeParseError, ReasonParseError, "empty body")
	}
	if trimmed[0] == '[' {
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, ReasonBatchUnsupported, "JSON-RPC batches are not supported: one request or notification per POST")
	}
	if trimmed[0] != '{' {
		return nil, newErr(http.StatusBadRequest, CodeParseError, ReasonParseError, "body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var env envelope
	if err := dec.Decode(&env); err != nil {
		return nil, newErr(http.StatusBadRequest, CodeParseError, ReasonParseError, "invalid JSON: "+err.Error())
	}
	if dec.More() {
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, ReasonInvalidRequest, "trailing data after the JSON-RPC message")
	}
	if env.JSONRPC != "2.0" {
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, ReasonInvalidRequest, "jsonrpc must be \"2.0\"")
	}
	if env.Method == "" {
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, ReasonInvalidRequest, "method is required")
	}
	if env.ID != nil {
		if err := checkID(env.ID); err != nil {
			return nil, err
		}
	}
	if len(env.Params) > 0 && !isJSONObject(env.Params) {
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, ReasonInvalidRequest, "params must be an object")
	}
	return &env, nil
}

// checkID enforces MCP's id rules: string or number, never null.
func checkID(id json.RawMessage) *Error {
	t := bytes.TrimSpace(id)
	switch {
	case len(t) == 0, bytes.Equal(t, []byte("null")):
		return newErr(http.StatusBadRequest, CodeInvalidRequest, ReasonInvalidRequest, "request id must not be null")
	case t[0] == '"', t[0] == '-', t[0] >= '0' && t[0] <= '9':
		return nil
	default:
		return newErr(http.StatusBadRequest, CodeInvalidRequest, ReasonInvalidRequest, "request id must be a string or a number")
	}
}

func isJSONObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '{'
}

// parseMeta validates the required per-request protocol fields. A missing
// required field is -32602 / 400 (basic/index §_meta).
func parseMeta(params json.RawMessage) (Meta, *Error) {
	var m Meta
	if len(params) == 0 {
		return m, newErr(http.StatusBadRequest, CodeInvalidParams, ReasonMetaMissing, "params._meta is required: every request carries "+MetaProtocolVersion+" and "+MetaClientCapabilities)
	}
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return m, newErr(http.StatusBadRequest, CodeInvalidParams, ReasonMetaInvalid, "params: "+err.Error())
	}
	if p.Meta == nil {
		return m, newErr(http.StatusBadRequest, CodeInvalidParams, ReasonMetaMissing, "params._meta is required: every request carries "+MetaProtocolVersion+" and "+MetaClientCapabilities)
	}
	m.Extra = map[string]json.RawMessage{}
	for k, v := range p.Meta {
		if err := m.setKey(k, v); err != nil {
			return m, err
		}
	}
	if m.ProtocolVersion == "" {
		return m, newErr(http.StatusBadRequest, CodeInvalidParams, ReasonMetaMissing, "params._meta."+MetaProtocolVersion+" is required")
	}
	if m.ClientCapabilities == nil {
		return m, newErr(http.StatusBadRequest, CodeInvalidParams, ReasonMetaMissing, "params._meta."+MetaClientCapabilities+" is required")
	}
	return m, nil
}

// setKey assigns one _meta member: reserved keys are typed and validated,
// everything else is kept verbatim.
func (m *Meta) setKey(k string, v json.RawMessage) *Error {
	invalid := func(msg string) *Error {
		return newErr(http.StatusBadRequest, CodeInvalidParams, ReasonMetaInvalid, msg)
	}
	switch k {
	case MetaProtocolVersion:
		if err := json.Unmarshal(v, &m.ProtocolVersion); err != nil || m.ProtocolVersion == "" {
			return invalid(MetaProtocolVersion + " must be a non-empty string")
		}
	case MetaClientCapabilities:
		if !isJSONObject(v) {
			return invalid(MetaClientCapabilities + " must be an object")
		}
		m.ClientCapabilities = v
	case MetaClientInfo:
		impl, err := parseImplementation(v)
		if err != nil {
			return invalid(MetaClientInfo + ": " + err.Error())
		}
		m.ClientInfo = impl
	case MetaLogLevel:
		if err := json.Unmarshal(v, &m.LogLevel); err != nil || !validLogLevel(m.LogLevel) {
			return invalid(MetaLogLevel + " must be one of debug, info, notice, warning, error, critical, alert, emergency")
		}
	case MetaProgressToken:
		if !validProgressToken(v) {
			return invalid(MetaProgressToken + " must be a string or an integer")
		}
		m.ProgressToken = v
	default:
		m.Extra[k] = v
	}
	return nil
}

// parseImplementation validates the bounded Implementation wire type:
// name and version are required non-empty strings; the optional display
// fields must be strings and icons, when present, an array.
func parseImplementation(v json.RawMessage) (*Implementation, error) {
	if !isJSONObject(v) {
		return nil, fmt.Errorf("must be an Implementation object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(v, &fields); err != nil {
		return nil, err
	}
	impl := &Implementation{}
	str := func(key string, dst *string, required bool) error {
		raw, has := fields[key]
		if !has {
			if required {
				return fmt.Errorf("%s is required", key)
			}
			return nil
		}
		if err := json.Unmarshal(raw, dst); err != nil || (required && *dst == "") {
			return fmt.Errorf("%s must be a non-empty string", key)
		}
		return nil
	}
	for _, f := range []struct {
		key      string
		dst      *string
		required bool
	}{{"name", &impl.Name, true}, {"version", &impl.Version, true}, {"title", &impl.Title, false}, {"description", &impl.Description, false}, {"websiteUrl", &impl.WebsiteURL, false}} {
		if err := str(f.key, f.dst, f.required); err != nil {
			return nil, err
		}
	}
	if icons, has := fields["icons"]; has {
		t := bytes.TrimSpace(icons)
		if len(t) == 0 || t[0] != '[' {
			return nil, fmt.Errorf("icons must be an array")
		}
	}
	return impl, nil
}

func validLogLevel(l string) bool {
	switch l {
	case "debug", "info", "notice", "warning", "error", "critical", "alert", "emergency":
		return true
	}
	return false
}

// validProgressToken accepts the ProgressToken wire type: string | integer.
func validProgressToken(v json.RawMessage) bool {
	t := bytes.TrimSpace(v)
	if len(t) == 0 {
		return false
	}
	if t[0] == '"' {
		var s string
		return json.Unmarshal(t, &s) == nil
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.UseNumber()
	if dec.Decode(&n) != nil {
		return false
	}
	_, err := n.Int64()
	return err == nil
}

// methodNeedsName reports whether Mcp-Name is REQUIRED for the method and
// which params field it mirrors.
func methodNeedsName(method string) (field string, required bool) {
	switch method {
	case MethodToolsCall, MethodPromptsGet:
		return "name", true
	case MethodResourcesRead:
		return "uri", true
	}
	return "", false
}

// extractFields pulls the typed, method-specific fields out of params.
func extractFields(req *Request) *Error {
	if len(req.Params) == 0 {
		return nil
	}
	var p struct {
		Name           string          `json:"name"`
		URI            string          `json:"uri"`
		Arguments      json.RawMessage `json:"arguments"`
		RequestState   *string         `json:"requestState"`
		InputResponses json.RawMessage `json:"inputResponses"`
		Cursor         string          `json:"cursor"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return newErr(http.StatusBadRequest, CodeInvalidParams, ReasonInvalidRequest, "params: "+err.Error())
	}
	switch field, _ := methodNeedsName(req.Method); field {
	case "name":
		req.Name = p.Name
	case "uri":
		req.Name = p.URI
	}
	if req.Method == MethodToolsCall {
		if len(p.Arguments) > 0 && !bytes.Equal(bytes.TrimSpace(p.Arguments), []byte("null")) && !isJSONObject(p.Arguments) {
			return newErr(http.StatusBadRequest, CodeInvalidParams, ReasonInvalidRequest, "params.arguments must be an object")
		}
		req.Arguments = p.Arguments
		if p.RequestState != nil {
			req.RequestState = *p.RequestState
		}
		if len(p.InputResponses) > 0 && !bytes.Equal(bytes.TrimSpace(p.InputResponses), []byte("null")) {
			if !isJSONObject(p.InputResponses) {
				return newErr(http.StatusBadRequest, CodeInvalidParams, ReasonInvalidRequest, "params.inputResponses must be an object")
			}
			req.InputResponses = p.InputResponses
		}
	}
	req.Cursor = p.Cursor
	return nil
}

// IsNotificationMethod reports whether a method name is in the
// notifications namespace.
func IsNotificationMethod(method string) bool { return strings.HasPrefix(method, "notifications/") }

package wire

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// DefaultMaxBody bounds one MCP POST body. Arguments larger than this are
// not a governed action Talon will carry.
const DefaultMaxBody int64 = 1 << 20

// Transport is the HTTP gate every MCP route runs before touching a body.
// One instance is shared by all routes so they cannot implement different
// versions of the protocol.
type Transport struct {
	// AllowedOrigins are extra browser origins accepted on top of loopback
	// and same-origin. A "*" entry is ignored: MCP has no wildcard origin.
	AllowedOrigins []string
	// MaxBody bounds the request body; 0 means DefaultMaxBody.
	MaxBody int64
	// Methods is the JSON-RPC method allowlist for this route.
	Methods []string
}

// Outcome tells the route what Accept did with the request.
type Outcome int

const (
	// Rejected: a protocol error was already written; stop.
	Rejected Outcome = iota
	// Notified: a notification was accepted with 202 and no body; stop.
	Notified
	// Ready: req is a validated request; dispatch it.
	Ready
)

// Accept runs the full 2026-07-28 request gate:
//
//	HTTP method → Origin → Accept → Content-Type → body size → one JSON-RPC
//	message → envelope rules → notification (202) → required _meta →
//	MCP-Protocol-Version header (presence, single, equal to _meta, supported)
//	→ Mcp-Method (presence, single, equal to body) → Mcp-Name where the
//	method requires it → method allowlist → typed field extraction.
//
// Header/body disagreement is treated as a confused-deputy boundary: the
// request is rejected before the route learns which action it named.
func (t *Transport) Accept(w http.ResponseWriter, r *http.Request) (*Request, Outcome) {
	if err := t.gate(r); err != nil {
		WriteError(w, nil, err)
		return nil, Rejected
	}
	maxBody := t.MaxBody
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			WriteError(w, nil, newErr(http.StatusRequestEntityTooLarge, CodeInvalidRequest, ReasonBodyTooLarge, "request body exceeds the MCP body limit"))
		} else {
			WriteError(w, nil, newErr(http.StatusBadRequest, CodeParseError, ReasonParseError, "reading body: "+err.Error()))
		}
		return nil, Rejected
	}
	env, perr := parseMessage(body)
	if perr != nil {
		WriteError(w, nil, perr)
		return nil, Rejected
	}
	if env.ID == nil {
		// A notification. The core defines no client-to-server notification
		// on Streamable HTTP, so anything in the notifications namespace is
		// accepted and dropped (202, no body); any other id-less method is
		// refused — a side effect must never run without a response.
		if !IsNotificationMethod(env.Method) {
			WriteError(w, nil, newErr(http.StatusBadRequest, CodeInvalidRequest, ReasonNotificationUnsupported, "a message without an id is a notification; only notifications/* methods are accepted"))
			return nil, Rejected
		}
		w.WriteHeader(http.StatusAccepted)
		return nil, Notified
	}
	req := &Request{ID: env.ID, Method: env.Method, Params: env.Params}
	meta, merr := parseMeta(env.Params)
	if merr != nil {
		WriteError(w, req.ID, merr)
		return nil, Rejected
	}
	req.Meta = meta
	if ferr := extractFields(req); ferr != nil {
		WriteError(w, req.ID, ferr)
		return nil, Rejected
	}
	if herr := checkStandardHeaders(r.Header, req); herr != nil {
		WriteError(w, req.ID, herr)
		return nil, Rejected
	}
	if !t.methodAllowed(req.Method) {
		WriteError(w, req.ID, &Error{
			Status: http.StatusNotFound, Code: CodeMethodNotFound, Reason: ReasonMethodNotFound,
			Message: "method not found: " + req.Method + " (supported: " + strings.Join(t.Methods, ", ") + ")",
		})
		return nil, Rejected
	}
	req.HeaderParams = captureHeaderParams(r.Header)
	return req, Ready
}

func (t *Transport) methodAllowed(m string) bool {
	for _, a := range t.Methods {
		if a == m {
			return true
		}
	}
	return false
}

// gate validates everything that does not need the body.
func (t *Transport) gate(r *http.Request) *Error {
	if r.Method != http.MethodPost {
		// GET (legacy session stream) and DELETE (legacy session end) are
		// not part of this revision: 405, nothing minted, nothing echoed.
		return newErr(http.StatusMethodNotAllowed, CodeInvalidRequest, ReasonTransportMethod, "the MCP endpoint accepts POST only")
	}
	if err := t.checkOrigin(r); err != nil {
		return err
	}
	if err := checkAccept(r.Header.Get("Accept")); err != nil {
		return err
	}
	ct := r.Header.Get("Content-Type")
	mt, _, perr := mime.ParseMediaType(ct)
	if ct == "" || perr != nil || mt != "application/json" {
		return newErr(http.StatusUnsupportedMediaType, CodeInvalidRequest, ReasonContentTypeUnsupported, "Content-Type must be application/json")
	}
	return nil
}

// checkOrigin mitigates DNS rebinding: an absent Origin (non-browser client)
// passes; a present Origin must be loopback, the request's own host, or an
// explicitly configured origin. Anything else is 403.
func (t *Transport) checkOrigin(r *http.Request) *Error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	forbidden := newErr(http.StatusForbidden, CodeInvalidRequest, ReasonOriginForbidden, "Origin is not allowed for this MCP endpoint")
	if origin == "null" {
		return forbidden
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" {
		return forbidden
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	if strings.EqualFold(u.Host, r.Host) {
		return nil
	}
	for _, a := range t.AllowedOrigins {
		if a == "*" || a == "" {
			continue
		}
		if strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(origin, "/")) {
			return nil
		}
	}
	return forbidden
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// checkAccept requires an Accept header that admits application/json, the
// response type this surface produces. Clients are REQUIRED by the spec to
// list both application/json and text/event-stream; a client that cannot
// take JSON is incompatible regardless of how its body parses.
func checkAccept(accept string) *Error {
	bad := newErr(http.StatusNotAcceptable, CodeInvalidRequest, ReasonAcceptUnsupported, "Accept must include application/json (and text/event-stream)")
	if strings.TrimSpace(accept) == "" {
		return bad
	}
	for _, part := range strings.Split(accept, ",") {
		mt, _, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		switch strings.ToLower(mt) {
		case "application/json", "application/*", "*/*":
			return nil
		}
	}
	return bad
}

// checkStandardHeaders enforces the mirrored request metadata.
func checkStandardHeaders(h http.Header, req *Request) *Error {
	ver, present, dup := singleHeader(h, HeaderProtocolVersion)
	switch {
	case !present:
		e := headerMismatch(ReasonVersionHeaderMissing, "Header mismatch: required header "+HeaderProtocolVersion+" is missing")
		e.Data = map[string]any{"supported": SupportedVersions}
		return e
	case dup:
		return headerMismatch(ReasonVersionHeaderDuplicate, "Header mismatch: "+HeaderProtocolVersion+" was sent more than once")
	case ver != req.Meta.ProtocolVersion:
		return headerMismatch(ReasonVersionMismatch, "Header mismatch: "+HeaderProtocolVersion+" header value does not match params._meta."+MetaProtocolVersion)
	}
	if ver != ProtocolVersion {
		return &Error{
			Status: http.StatusBadRequest, Code: CodeUnsupportedProtocolVersion, Reason: ReasonVersionUnsupported,
			Message: "Unsupported protocol version", Data: map[string]any{"supported": SupportedVersions, "requested": ver},
		}
	}
	m, present, dup := singleHeader(h, HeaderMethod)
	switch {
	case !present:
		return headerMismatch(ReasonMethodHeaderMissing, "Header mismatch: required header "+HeaderMethod+" is missing")
	case dup:
		return headerMismatch(ReasonMethodHeaderDuplicate, "Header mismatch: "+HeaderMethod+" was sent more than once")
	case m != req.Method:
		return headerMismatch(ReasonMethodHeaderMismatch, "Header mismatch: "+HeaderMethod+" header value does not match body method")
	}
	field, required := methodNeedsName(req.Method)
	if !required {
		return nil
	}
	name, present, dup := singleHeader(h, HeaderName)
	switch {
	case !present:
		return headerMismatch(ReasonNameHeaderMissing, "Header mismatch: required header "+HeaderName+" is missing for "+req.Method)
	case dup:
		return headerMismatch(ReasonNameHeaderDuplicate, "Header mismatch: "+HeaderName+" was sent more than once")
	}
	decoded, err := DecodeHeaderValue(name)
	if err != nil {
		return headerMismatch(ReasonNameHeaderInvalid, "Header mismatch: "+HeaderName+" contains invalid characters or an undecodable sentinel")
	}
	if req.Name == "" {
		return newErr(http.StatusBadRequest, CodeInvalidParams, ReasonInvalidRequest, "params."+field+" is required for "+req.Method)
	}
	if decoded != req.Name {
		return headerMismatch(ReasonNameHeaderMismatch, "Header mismatch: "+HeaderName+" header value does not match body params."+field)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

type errorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Error   rpcErrorOut     `json:"error"`
}

type rpcErrorOut struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type resultResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

// WriteError writes a protocol rejection: its HTTP status and a JSON-RPC
// error body. A nil id yields an error response without an id (the message
// could not be attributed to a request).
func WriteError(w http.ResponseWriter, id json.RawMessage, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.Status)
	out := errorResponse{JSONRPC: "2.0", ID: id, Error: rpcErrorOut{Code: e.Code, Message: e.Message}}
	if len(e.Data) > 0 {
		out.Error.Data = e.Data
	}
	_ = json.NewEncoder(w).Encode(out)
}

// WriteRPCError writes an application-level JSON-RPC error (a governed
// outcome, an upstream failure) with HTTP 200: the request was valid
// protocol; the operation failed.
func WriteRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(errorResponse{JSONRPC: "2.0", ID: id, Error: rpcErrorOut{Code: code, Message: message, Data: data}})
}

// WriteResult writes a JSON result response.
func WriteResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resultResponse{JSONRPC: "2.0", ID: id, Result: result})
}

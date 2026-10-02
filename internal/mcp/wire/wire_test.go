package wire

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const metaOK = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`

func transport() *Transport {
	return &Transport{Methods: []string{MethodDiscover, MethodToolsList, MethodToolsCall}}
}

type fixture struct {
	method  string
	headers map[string]string
	body    string
	origin  string
	accept  string
	ctype   string
}

func (f fixture) request() *http.Request {
	m := f.method
	if m == "" {
		m = http.MethodPost
	}
	r := httptest.NewRequestWithContext(context.Background(), m, "http://127.0.0.1:8080/mcp", strings.NewReader(f.body))
	accept := f.accept
	if accept == "" {
		accept = "application/json, text/event-stream"
	}
	r.Header.Set("Accept", accept)
	ct := f.ctype
	if ct == "" {
		ct = "application/json"
	}
	r.Header.Set("Content-Type", ct)
	if f.origin != "" {
		r.Header.Set("Origin", f.origin)
	}
	for k, v := range f.headers {
		for _, vv := range strings.Split(v, "\x00") {
			r.Header.Add(k, vv)
		}
	}
	return r
}

func std(method, name string) map[string]string {
	h := map[string]string{HeaderProtocolVersion: ProtocolVersion, HeaderMethod: method}
	if name != "" {
		h[HeaderName] = name
	}
	return h
}

type rejected struct {
	status int
	code   int
	reason string
}

func TestAccept_Conformance(t *testing.T) {
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{` + metaOK + `,"name":"ticket_lookup","arguments":{"id":"T-1"}}}`
	cases := []struct {
		name  string
		f     fixture
		want  Outcome
		rej   rejected
		check func(t *testing.T, req *Request)
	}{
		{"valid tools/call", fixture{headers: std("tools/call", "ticket_lookup"), body: call}, Ready, rejected{}, func(t *testing.T, req *Request) {
			require.Equal(t, "ticket_lookup", req.Name)
			require.JSONEq(t, `{"id":"T-1"}`, string(req.Arguments))
			require.Equal(t, "t", req.Meta.ClientInfo.Name)
			require.Equal(t, json.RawMessage(`1`), req.ID)
		}},
		{"valid server/discover", fixture{headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":"d-1","method":"server/discover","params":{` + metaOK + `}}`}, Ready, rejected{}, nil},
		{"valid tools/list with cursor", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{` + metaOK + `,"cursor":"abc"}}`}, Ready, rejected{}, func(t *testing.T, req *Request) { require.Equal(t, "abc", req.Cursor) }},
		{"requestState and inputResponses preserved", fixture{headers: std("tools/call", "ticket_lookup"), body: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{` + metaOK + `,"name":"ticket_lookup","arguments":{},"requestState":"opaque-blob","inputResponses":{"q1":{"action":"accept","content":{"a":1}}}}}`}, Ready, rejected{}, func(t *testing.T, req *Request) {
			require.Equal(t, "opaque-blob", req.RequestState)
			require.JSONEq(t, `{"q1":{"action":"accept","content":{"a":1}}}`, string(req.InputResponses))
		}},
		{"extension _meta keys preserved, not interpreted", fixture{headers: std("tools/call", "x"), body: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}},"traceparent":"00-abc-def-01","com.example/tenant":"evil"},"name":"x"}}`}, Ready, rejected{}, func(t *testing.T, req *Request) {
			require.Equal(t, json.RawMessage(`"00-abc-def-01"`), req.Meta.Extra["traceparent"])
			require.Contains(t, req.Meta.Extra, "com.example/tenant")
			require.Nil(t, req.Meta.ClientInfo, "clientInfo is optional")
		}},
		{"base64 sentinel Mcp-Name", fixture{headers: std("tools/call", "=?base64?"+base64.StdEncoding.EncodeToString([]byte("héllo tool"))+"?="), body: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{` + metaOK + `,"name":"héllo tool"}}`}, Ready, rejected{}, nil},

		{"missing protocol header", fixture{headers: map[string]string{HeaderMethod: "tools/call", HeaderName: "ticket_lookup"}, body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonVersionHeaderMissing}, nil},
		{"missing _meta", fixture{headers: std("tools/call", "ticket_lookup"), body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ticket_lookup"}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaMissing}, nil},
		{"missing clientCapabilities", fixture{headers: std("tools/call", "ticket_lookup"), body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"name":"ticket_lookup"}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaMissing}, nil},
		{"wrong protocol version (header and meta agree)", fixture{headers: map[string]string{HeaderProtocolVersion: "2025-06-18", HeaderMethod: "tools/list"}, body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18","io.modelcontextprotocol/clientCapabilities":{}}}}`}, Rejected, rejected{400, CodeUnsupportedProtocolVersion, ReasonVersionUnsupported}, nil},
		{"header/body protocol mismatch", fixture{headers: map[string]string{HeaderProtocolVersion: "2025-11-25", HeaderMethod: "tools/call", HeaderName: "ticket_lookup"}, body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonVersionMismatch}, nil},
		{"duplicate protocol header", fixture{headers: map[string]string{HeaderProtocolVersion: "2026-07-28\x002026-07-28", HeaderMethod: "tools/call", HeaderName: "ticket_lookup"}, body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonVersionHeaderDuplicate}, nil},
		{"method mismatch", fixture{headers: std("tools/list", "ticket_lookup"), body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonMethodHeaderMismatch}, nil},
		{"method header missing", fixture{headers: map[string]string{HeaderProtocolVersion: ProtocolVersion, HeaderName: "ticket_lookup"}, body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonMethodHeaderMissing}, nil},
		{"name mismatch (smuggle delete behind lookup)", fixture{headers: std("tools/call", "ticket_lookup"), body: strings.Replace(call, `"name":"ticket_lookup"`, `"name":"delete_customer"`, 1)}, Rejected, rejected{400, CodeHeaderMismatch, ReasonNameHeaderMismatch}, nil},
		{"name header missing", fixture{headers: std("tools/call", ""), body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonNameHeaderMissing}, nil},
		{"name header duplicated", fixture{headers: map[string]string{HeaderProtocolVersion: ProtocolVersion, HeaderMethod: "tools/call", HeaderName: "ticket_lookup\x00ticket_lookup"}, body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonNameHeaderDuplicate}, nil},
		{"name header case differs (values are case-sensitive)", fixture{headers: std("tools/call", "Ticket_Lookup"), body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonNameHeaderMismatch}, nil},
		{"name header with bad sentinel", fixture{headers: std("tools/call", "=?base64?***?="), body: call}, Rejected, rejected{400, CodeHeaderMismatch, ReasonNameHeaderInvalid}, nil},
		{"unsupported method", fixture{headers: std("resources/read", "file:///x"), body: `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{` + metaOK + `,"uri":"file:///x"}}`}, Rejected, rejected{404, CodeMethodNotFound, ReasonMethodNotFound}, nil},
		{"legacy initialize", fixture{headers: map[string]string{}, body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaMissing}, nil},
		{"legacy initialize with modern headers", fixture{headers: std("initialize", ""), body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` + metaOK + `}}`}, Rejected, rejected{404, CodeMethodNotFound, ReasonMethodNotFound}, nil},
		{"removed notifications/initialized", fixture{headers: map[string]string{}, body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`}, Rejected, rejected{404, CodeMethodNotFound, ReasonNotificationUnsupported}, nil},
		{"removed notifications/cancelled", fixture{headers: map[string]string{}, body: `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1"}}`}, Rejected, rejected{404, CodeMethodNotFound, ReasonNotificationUnsupported}, nil},
		{"unknown notification", fixture{headers: map[string]string{}, body: `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`}, Rejected, rejected{404, CodeMethodNotFound, ReasonNotificationUnsupported}, nil},
		{"id-less tools/call is an unsupported notification", fixture{headers: std("tools/call", "ticket_lookup"), body: `{"jsonrpc":"2.0","method":"tools/call","params":{` + metaOK + `,"name":"ticket_lookup"}}`}, Rejected, rejected{404, CodeMethodNotFound, ReasonNotificationUnsupported}, nil},
		{"malformed clientInfo (no version)", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"x"}}}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaInvalid}, nil},
		{"malformed clientInfo (title not string)", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"x","version":"1","title":5}}}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaInvalid}, nil},
		{"malformed clientInfo (icons not array)", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"x","version":"1","icons":{}}}}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaInvalid}, nil},
		{"valid clientInfo with display fields", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"x","version":"1","title":"X","websiteUrl":"https://x.example","icons":[{"src":"https://x.example/i.png"}]}}}}`}, Ready, rejected{}, nil},
		{"malformed logLevel", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/logLevel":"loud"}}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaInvalid}, nil},
		{"valid logLevel", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/logLevel":"warning"}}}`}, Ready, rejected{}, func(t *testing.T, req *Request) { require.Equal(t, "warning", req.Meta.LogLevel) }},
		{"malformed progressToken (object)", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":{"a":1}}}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaInvalid}, nil},
		{"malformed progressToken (float)", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":1.5}}}`}, Rejected, rejected{400, CodeInvalidParams, ReasonMetaInvalid}, nil},
		{"valid progressToken (int)", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":7}}}`}, Ready, rejected{}, nil},
		{"null id", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":null,"method":"tools/list","params":{` + metaOK + `}}`}, Rejected, rejected{400, CodeInvalidRequest, ReasonInvalidRequest}, nil},
		{"batch", fixture{headers: std("tools/list", ""), body: `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`}, Rejected, rejected{400, CodeInvalidRequest, ReasonBatchUnsupported}, nil},
		{"parse error", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":`}, Rejected, rejected{400, CodeParseError, ReasonParseError}, nil},
		{"jsonrpc 1.0", fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`}, Rejected, rejected{400, CodeInvalidRequest, ReasonInvalidRequest}, nil},
		{"GET", fixture{method: http.MethodGet, headers: std("tools/list", "")}, Rejected, rejected{405, CodeInvalidRequest, ReasonTransportMethod}, nil},
		{"DELETE", fixture{method: http.MethodDelete, headers: map[string]string{"Mcp-Session-Id": "abc"}}, Rejected, rejected{405, CodeInvalidRequest, ReasonTransportMethod}, nil},
		{"Accept without json", fixture{accept: "text/html", headers: std("tools/list", ""), body: call}, Rejected, rejected{406, CodeInvalidRequest, ReasonAcceptUnsupported}, nil},
		{"Accept json only", fixture{accept: "application/json", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Rejected, rejected{406, CodeInvalidRequest, ReasonAcceptUnsupported}, nil},
		{"Accept SSE only", fixture{accept: "text/event-stream", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Rejected, rejected{406, CodeInvalidRequest, ReasonAcceptUnsupported}, nil},
		{"Accept wildcard only", fixture{accept: "*/*", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Rejected, rejected{406, CodeInvalidRequest, ReasonAcceptUnsupported}, nil},
		{"Accept both plus extra, params and case", fixture{accept: "text/html, Application/JSON;q=0.9, TEXT/EVENT-STREAM; charset=utf-8", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Ready, rejected{}, nil},
		{"Accept missing", fixture{accept: " ", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Rejected, rejected{406, CodeInvalidRequest, ReasonAcceptUnsupported}, nil},
		{"Content-Type text", fixture{ctype: "text/plain", headers: std("tools/list", ""), body: call}, Rejected, rejected{415, CodeInvalidRequest, ReasonContentTypeUnsupported}, nil},
		{"Origin loopback ok", fixture{origin: "http://localhost:3000", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Ready, rejected{}, nil},
		{"Origin same host ok", fixture{origin: "http://127.0.0.1:8080", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Ready, rejected{}, nil},
		{"Origin remote rejected", fixture{origin: "https://evil.example", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Rejected, rejected{403, CodeInvalidRequest, ReasonOriginForbidden}, nil},
		{"Origin null rejected", fixture{origin: "null", headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}, Rejected, rejected{403, CodeInvalidRequest, ReasonOriginForbidden}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, out := transport().Accept(rec, tc.f.request())
			require.Equal(t, tc.want, out, "body: %s", rec.Body.String())
			switch out {
			case Rejected:
				require.Equal(t, tc.rej.status, rec.Code, rec.Body.String())
				var body struct {
					JSONRPC string `json:"jsonrpc"`
					Error   struct {
						Code int            `json:"code"`
						Data map[string]any `json:"data"`
					} `json:"error"`
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
				require.Equal(t, "2.0", body.JSONRPC)
				require.Equal(t, tc.rej.code, body.Error.Code)
				if tc.rej.code == CodeUnsupportedProtocolVersion {
					require.Equal(t, []any{"2026-07-28"}, body.Error.Data["supported"])
				}
			case Ready:
				require.NotNil(t, req)
				if tc.check != nil {
					tc.check(t, req)
				}
			}
		})
	}
}

// Legacy session headers are ignored, never echoed, never minted.
func TestAccept_IgnoresLegacySessionHeaders(t *testing.T) {
	f := fixture{headers: std("server/discover", ""), body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`}
	r := f.request()
	r.Header.Set("Mcp-Session-Id", "legacy-session")
	r.Header.Set("Last-Event-ID", "42")
	rec := httptest.NewRecorder()
	_, out := transport().Accept(rec, r)
	require.Equal(t, Ready, out)
	require.Empty(t, rec.Header().Get("Mcp-Session-Id"))
}

func TestOrigin_ConfiguredAllowlistNoWildcard(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaOK + `}}`
	tr := transport()
	tr.AllowedOrigins = []string{"*", "https://console.example.com"}
	rec := httptest.NewRecorder()
	_, out := tr.Accept(rec, fixture{origin: "https://console.example.com", headers: std("server/discover", ""), body: body}.request())
	require.Equal(t, Ready, out)
	rec = httptest.NewRecorder()
	_, out = tr.Accept(rec, fixture{origin: "https://other.example.com", headers: std("server/discover", ""), body: body}.request())
	require.Equal(t, Rejected, out)
	require.Equal(t, http.StatusForbidden, rec.Code, "a '*' entry never allows arbitrary origins")
}

func TestBodyLimit(t *testing.T) {
	tr := transport()
	tr.MaxBody = 64
	rec := httptest.NewRecorder()
	_, out := tr.Accept(rec, fixture{headers: std("tools/list", ""), body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + metaOK + `,"pad":"` + strings.Repeat("x", 200) + `"}}`}.request())
	require.Equal(t, Rejected, out)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestHeaderValueEncoding(t *testing.T) {
	cases := map[string]string{
		"us-west1":           "us-west1",
		"Hello, 世界":          "=?base64?SGVsbG8sIOS4lueVjA==?=",
		" padded ":           "=?base64?IHBhZGRlZCA=?=",
		"line1\nline2":       "=?base64?bGluZTEKbGluZTI=?=",
		"=?base64?literal?=": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
		"":                   "",
	}
	for in, want := range cases {
		require.Equal(t, want, EncodeHeaderValue(in), in)
		got, err := DecodeHeaderValue(want)
		require.NoError(t, err, in)
		require.Equal(t, in, got, "round trip")
	}
	_, err := DecodeHeaderValue("bad\x01char")
	require.Error(t, err)
	_, err = DecodeHeaderValue("=?base64?!!!?=")
	require.Error(t, err)
}

func TestHeaderParams_SchemaDeclarations(t *testing.T) {
	good := `{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"count":{"type":"integer","x-mcp-header":"Count"},"dry":{"type":"boolean","x-mcp-header":"Dry-Run"},"nested":{"type":"object","properties":{"zone":{"type":"string","x-mcp-header":"Zone"}}},"query":{"type":"string"}}}`
	hp, err := HeaderParamsFromSchema(json.RawMessage(good))
	require.NoError(t, err)
	require.Len(t, hp.Decls(), 4)
	bad := map[string]string{
		"number type":      `{"type":"object","properties":{"amt":{"type":"number","x-mcp-header":"Amt"}}}`,
		"empty name":       `{"type":"object","properties":{"a":{"type":"string","x-mcp-header":""}}}`,
		"non-token name":   `{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"Bad Name"}}}`,
		"CRLF name":        `{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"X\r\nInjected"}}}`,
		"duplicate (case)": `{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"Region"},"b":{"type":"string","x-mcp-header":"region"}}}`,
		"through items":    `{"type":"object","properties":{"a":{"type":"array","items":{"type":"string","x-mcp-header":"A"}}}}`,
		"through oneOf":    `{"type":"object","properties":{"a":{"oneOf":[{"type":"string","x-mcp-header":"A"}]}}}`,
		"through $defs":    `{"type":"object","$defs":{"x":{"type":"string","x-mcp-header":"A"}},"properties":{"a":{"$ref":"#/$defs/x"}}}`,
		"on root":          `{"type":"object","x-mcp-header":"Root","properties":{}}`,
	}
	for name, s := range bad {
		_, err := HeaderParamsFromSchema(json.RawMessage(s))
		require.Error(t, err, name)
	}
}

func TestHeaderParams_ValidateAndOutbound(t *testing.T) {
	hp, err := HeaderParamsFromSchema(json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"count":{"type":"integer","x-mcp-header":"Count"},"dry":{"type":"boolean","x-mcp-header":"Dry"},"nested":{"type":"object","properties":{"zone":{"type":"string","x-mcp-header":"Zone"}}}}}`))
	require.NoError(t, err)
	args := json.RawMessage(`{"region":"us-west1","count":42,"dry":true,"nested":{"zone":"zone é"}}`)
	captured := func(h map[string]string) map[string]HeaderParam {
		hdr := http.Header{}
		for k, v := range h {
			for _, vv := range strings.Split(v, "\x00") {
				hdr.Add(k, vv)
			}
		}
		return captureHeaderParams(hdr)
	}
	ok := map[string]string{"Mcp-Param-Region": "us-west1", "mcp-param-count": "42", "MCP-PARAM-DRY": "true", "Mcp-Param-Zone": EncodeHeaderValue("zone é")}
	require.Nil(t, ValidateHeaderParams(hp, args, captured(ok)))
	numeric := map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-Count": "42.0", "Mcp-Param-Dry": "true", "Mcp-Param-Zone": EncodeHeaderValue("zone é")}
	require.Nil(t, ValidateHeaderParams(hp, args, captured(numeric)), "integers compare numerically")
	withUnknown := map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-Count": "42", "Mcp-Param-Dry": "true", "Mcp-Param-Zone": EncodeHeaderValue("zone é"), "Mcp-Param-Tenant": "other"}
	require.Nil(t, ValidateHeaderParams(hp, args, captured(withUnknown)), "unrecognized Mcp-Param headers are ignored, never used")

	bad := map[string]struct {
		h      map[string]string
		reason string
	}{
		"value mismatch":  {map[string]string{"Mcp-Param-Region": "eu-west1", "Mcp-Param-Count": "42", "Mcp-Param-Dry": "true", "Mcp-Param-Zone": EncodeHeaderValue("zone é")}, ReasonParamHeaderMismatch},
		"missing header":  {map[string]string{"Mcp-Param-Count": "42", "Mcp-Param-Dry": "true", "Mcp-Param-Zone": EncodeHeaderValue("zone é")}, ReasonParamHeaderMissing},
		"duplicate":       {map[string]string{"Mcp-Param-Region": "us-west1\x00us-west1", "Mcp-Param-Count": "42", "Mcp-Param-Dry": "true", "Mcp-Param-Zone": EncodeHeaderValue("zone é")}, ReasonParamHeaderDuplicate},
		"invalid chars":   {map[string]string{"Mcp-Param-Region": "us\x7fwest", "Mcp-Param-Count": "42", "Mcp-Param-Dry": "true", "Mcp-Param-Zone": EncodeHeaderValue("zone é")}, ReasonParamHeaderInvalid},
		"bool case":       {map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-Count": "42", "Mcp-Param-Dry": "True", "Mcp-Param-Zone": EncodeHeaderValue("zone é")}, ReasonParamHeaderMismatch},
		"nested mismatch": {map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-Count": "42", "Mcp-Param-Dry": "true", "Mcp-Param-Zone": "zone"}, ReasonParamHeaderMismatch},
	}
	for name, tc := range bad {
		e := ValidateHeaderParams(hp, args, captured(tc.h))
		require.NotNil(t, e, name)
		require.Equal(t, CodeHeaderMismatch, e.Code, name)
		require.Equal(t, http.StatusBadRequest, e.Status, name)
		require.Equal(t, tc.reason, e.Reason, name)
	}
	// Absent / null argument: header must be absent.
	partial := json.RawMessage(`{"region":"us-west1","count":null}`)
	require.Nil(t, ValidateHeaderParams(hp, partial, captured(map[string]string{"Mcp-Param-Region": "us-west1"})))
	e := ValidateHeaderParams(hp, partial, captured(map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-Count": "1"}))
	require.NotNil(t, e)
	require.Equal(t, ReasonParamHeaderMismatch, e.Reason, "a header for a null/absent argument is a mismatch")
	// Declared integer carrying a float in the body is not mirrorable.
	e = ValidateHeaderParams(hp, json.RawMessage(`{"count":1.5}`), captured(map[string]string{"Mcp-Param-Count": "1.5"}))
	require.NotNil(t, e)
	require.Equal(t, ReasonParamHeaderInvalid, e.Reason)

	// Outbound: generated from the authorized body only.
	out, err := OutboundHeaderParams(hp, args)
	require.NoError(t, err)
	require.Equal(t, "us-west1", out.Get("Mcp-Param-Region"))
	require.Equal(t, "42", out.Get("Mcp-Param-Count"))
	require.Equal(t, "true", out.Get("Mcp-Param-Dry"))
	require.Equal(t, EncodeHeaderValue("zone é"), out.Get("Mcp-Param-Zone"))
	out, err = OutboundHeaderParams(hp, partial)
	require.NoError(t, err)
	require.Empty(t, out.Get("Mcp-Param-Count"), "null argument → no header")
	_, err = OutboundHeaderParams(hp, json.RawMessage(`{"count":1.5}`))
	require.Error(t, err)
}

func TestStripHeaderAnnotations(t *testing.T) {
	in := json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"n":{"type":"object","properties":{"z":{"type":"string","x-mcp-header":"Z"}}},"arr":{"type":"array","items":{"type":"string","x-mcp-header":"A"}}}}`)
	out := StripHeaderAnnotations(in)
	require.NotContains(t, string(out), "x-mcp-header")
	hp, err := HeaderParamsFromSchema(out)
	require.NoError(t, err)
	require.True(t, hp.Empty(), "a stripped definition declares nothing")
	require.Equal(t, json.RawMessage("not json"), StripHeaderAnnotations(json.RawMessage("not json")))
}

func TestValidateUpstreamResult_TruthTable(t *testing.T) {
	srv := Implementation{Name: "talon-mcp-proxy", Version: "x"}
	cases := []struct {
		name string
		raw  string
		err  error
	}{
		{"missing resultType", `{"content":[]}`, ErrResultTypeMissing},
		{"complete", `{"resultType":"complete","content":[]}`, nil},
		{"input_required", `{"resultType":"input_required","inputRequests":{"q":{"method":"elicitation/create","params":{}}},"requestState":"s"}`, nil},
		{"task", `{"resultType":"task","task":{"taskId":"t1"}}`, ErrResultTypeUnsupported},
		{"unknown future value", `{"resultType":"partial"}`, ErrResultTypeUnsupported},
		{"non-object", `[1]`, errors.New("x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ValidateUpstreamResult(json.RawMessage(tc.raw), srv)
			if tc.err != nil {
				require.Error(t, err)
				if errors.Is(tc.err, ErrResultTypeMissing) || errors.Is(tc.err, ErrResultTypeUnsupported) {
					require.ErrorIs(t, err, tc.err)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, srv, out["_meta"].(map[string]any)[MetaServerInfo])
		})
	}
	up, err := ValidateUpstreamResult(json.RawMessage(`{"resultType":"complete","content":[],"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"up","version":"9"},"x":1}}`), srv)
	require.NoError(t, err)
	meta := up["_meta"].(map[string]any)
	require.NotNil(t, meta["io.dativo.talon/upstreamServerInfo"])
	require.Equal(t, float64(1), meta["x"])
}

func TestParseListResult_Strict(t *testing.T) {
	ok, err := ParseListResult(json.RawMessage(`{"resultType":"complete","tools":[{"name":"a"}],"nextCursor":"c2","ttlMs":120000,"cacheScope":"public","com.example/x":true}`))
	require.NoError(t, err)
	require.Len(t, ok.Tools, 1)
	require.Equal(t, "c2", ok.NextCursor)
	require.Equal(t, 120000, ok.TTLMs)
	require.Equal(t, true, ok.Rest["com.example/x"])
	noHints, err := ParseListResult(json.RawMessage(`{"resultType":"complete","tools":[]}`))
	require.NoError(t, err)
	require.Equal(t, 0, noHints.TTLMs)
	require.Equal(t, CacheScopePrivate, noHints.CacheScope)
	for name, raw := range map[string]string{
		"legacy array":        `[{"name":"a"}]`,
		"legacy items key":    `{"resultType":"complete","items":[{"name":"a"}]}`,
		"missing resultType":  `{"tools":[]}`,
		"input_required list": `{"resultType":"input_required","tools":[]}`,
		"tools not array":     `{"resultType":"complete","tools":{"name":"a"}}`,
		"bad cursor":          `{"resultType":"complete","tools":[],"nextCursor":5}`,
		"bad ttl":             `{"resultType":"complete","tools":[],"ttlMs":"soon"}`,
		"bad scope":           `{"resultType":"complete","tools":[],"cacheScope":"shared"}`,
	} {
		_, err := ParseListResult(json.RawMessage(raw))
		require.Error(t, err, name)
	}
}

func TestResults(t *testing.T) {
	srv := Implementation{Name: "talon", Version: "1.2.3"}
	d := Discover(srv, map[string]any{"tools": map[string]any{}}, "", 60000)
	require.Equal(t, ResultTypeComplete, d["resultType"])
	require.Equal(t, []string{"2026-07-28"}, d["supportedVersions"])
	require.Equal(t, 60000, d["ttlMs"])
	require.Equal(t, CacheScopePublic, d["cacheScope"])
	require.Equal(t, srv, d["_meta"].(map[string]any)[MetaServerInfo])

	c := Cacheable(Complete(srv, map[string]any{"tools": []any{}}), -5, "weird")
	require.Equal(t, 0, c["ttlMs"])
	require.Equal(t, CacheScopePrivate, c["cacheScope"])
}

func TestOutboundRequest(t *testing.T) {
	inbound := Meta{ProtocolVersion: ProtocolVersion, ClientInfo: &Implementation{Name: "orig", Version: "1"}, ClientCapabilities: json.RawMessage(`{"elicitation":{"form":{}}}`), ProgressToken: json.RawMessage(`"p1"`), Extra: map[string]json.RawMessage{"traceparent": json.RawMessage(`"00-a-b-01"`), "com.example/k": json.RawMessage(`"v"`)}}
	meta := OutboundMeta(inbound, Implementation{Name: "talon-mcp-proxy", Version: "x"})
	require.JSONEq(t, `"2026-07-28"`, string(meta[MetaProtocolVersion]))
	require.JSONEq(t, `{"name":"talon-mcp-proxy","version":"x"}`, string(meta[MetaClientInfo]), "Talon identifies itself; the inbound clientInfo is not forwarded as ours")
	require.JSONEq(t, `{"elicitation":{"form":{}}}`, string(meta[MetaClientCapabilities]), "originating client capabilities are what MRTR input requests must respect")
	require.JSONEq(t, `"p1"`, string(meta[MetaProgressToken]))
	require.JSONEq(t, `"00-a-b-01"`, string(meta["traceparent"]))
	params := EncodeCallParams(meta, CallParams{Name: "up_tool", Arguments: json.RawMessage(`{"a":1}`), RequestState: "st", InputResponses: json.RawMessage(`{"q":{"action":"accept"}}`)})
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(params, &decoded))
	require.Equal(t, "up_tool", decoded["name"])
	require.Equal(t, "st", decoded["requestState"])
	require.NotNil(t, decoded["inputResponses"])
	hp, _ := HeaderParamsFromSchema(json.RawMessage(`{"type":"object","properties":{"a":{"type":"integer","x-mcp-header":"A"}}}`))
	ph, err := OutboundHeaderParams(hp, json.RawMessage(`{"a":1}`))
	require.NoError(t, err)
	req, err := NewUpstreamRequest(t.Context(), "http://127.0.0.1:1/mcp", json.RawMessage(`7`), MethodToolsCall, params, "up tool é", ph)
	require.NoError(t, err)
	require.Equal(t, ProtocolVersion, req.Header.Get(HeaderProtocolVersion))
	require.Equal(t, MethodToolsCall, req.Header.Get(HeaderMethod))
	require.Equal(t, EncodeHeaderValue("up tool é"), req.Header.Get(HeaderName))
	require.Equal(t, "1", req.Header.Get("Mcp-Param-A"))
	require.Equal(t, "application/json, text/event-stream", req.Header.Get("Accept"))
	require.Empty(t, req.Header.Get("Mcp-Session-Id"))
	_, err = NewUpstreamRequest(t.Context(), "http://127.0.0.1:1/mcp", json.RawMessage(`7`), MethodToolsCall, params, "", nil)
	require.Error(t, err, "tools/call without a name cannot be built")
}

func TestReadUpstreamResponse(t *testing.T) {
	id := json.RawMessage(`1`)
	// ReadUpstreamResponse closes the body itself.
	mk := func(status int, ct, body string) *http.Response { //nolint:bodyclose // closed by ReadUpstreamResponse
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {ct}}, Body: httpBody(body)}
	}
	r, err := ReadUpstreamResponse(mk(200, "application/json", `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[]}}`), id) //nolint:bodyclose // closed by ReadUpstreamResponse
	require.NoError(t, err)
	require.NotNil(t, r.Result)
	_, err = ReadUpstreamResponse(mk(200, "application/json", `{"jsonrpc":"2.0","id":1.0,"result":{"resultType":"complete"}}`), id) //nolint:bodyclose // closed by ReadUpstreamResponse
	require.NoError(t, err, "ids compare by value")
	sse := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n: keep-alive\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\n" +
		"data:  \"result\":{\"resultType\":\"complete\",\"content\":[{\"type\":\"text\",\"text\":\"done\"}]}}\n\n"
	r, err = ReadUpstreamResponse(mk(200, "text/event-stream", sse), id) //nolint:bodyclose // closed by ReadUpstreamResponse
	require.NoError(t, err, "notifications before the matching response are skipped")
	require.Contains(t, string(r.Result), "done")
	r, err = ReadUpstreamResponse(mk(400, "application/json", `{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch"}}`), id) //nolint:bodyclose // closed by ReadUpstreamResponse
	require.NoError(t, err)
	require.Equal(t, CodeHeaderMismatch, r.Error.Code)
	_, err = ReadUpstreamResponse(mk(502, "text/html", "<h1>bad gateway</h1>"), id) //nolint:bodyclose // closed by ReadUpstreamResponse
	require.ErrorIs(t, err, ErrUpstreamStatus)

	bad := map[string]struct {
		ct, body string
	}{
		"wrong id":                           {"application/json", `{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete"}}`},
		"missing id":                         {"application/json", `{"jsonrpc":"2.0","result":{"resultType":"complete"}}`},
		"null id":                            {"application/json", `{"jsonrpc":"2.0","id":null,"result":{"resultType":"complete"}}`},
		"string id for numeric request":      {"application/json", `{"jsonrpc":"2.0","id":"1","result":{"resultType":"complete"}}`},
		"jsonrpc 1.0":                        {"application/json", `{"jsonrpc":"1.0","id":1,"result":{"resultType":"complete"}}`},
		"both result and error":              {"application/json", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}`},
		"neither result nor error":           {"application/json", `{"jsonrpc":"2.0","id":1}`},
		"SSE response with another id":       {"text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{\"resultType\":\"complete\"}}\n\n"},
		"SSE malformed response id":          {"text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"id\":{\"x\":1},\"result\":{\"resultType\":\"complete\"}}\n\n"},
		"SSE malformed event":                {"text/event-stream", "data: {not json\n\n"},
		"SSE only comments":                  {"text/event-stream", ": only comments\n\n"},
		"SSE other-id result before correct": {"text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resultType\":\"complete\"}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\"}}\n\n"},
	}
	for name, tc := range bad {
		_, err := ReadUpstreamResponse(mk(200, tc.ct, tc.body), id) //nolint:bodyclose // closed by ReadUpstreamResponse
		require.Error(t, err, name)
	}
}

func httpBody(s string) *nopCloser { return &nopCloser{Reader: strings.NewReader(s)} }

type nopCloser struct{ *strings.Reader }

func (n *nopCloser) Close() error { return nil }

// Fuzz: the gate never panics and never yields Ready for a request whose
// Mcp-Name disagrees with the body name.
func FuzzAcceptNeverPanicsOrSmuggles(f *testing.F) {
	f.Add("ticket_lookup", "ticket_lookup", `{"id":"T-1"}`)
	f.Add("ticket_lookup", "delete_customer", `{"id":"T-1"}`)
	f.Add("=?base64?dGlja2V0X2xvb2t1cA==?=", "ticket_lookup", `{}`)
	f.Add("a\x00b", "a", `{"x":[1,2,{"y":null}]}`)
	f.Fuzz(func(t *testing.T, header, bodyName, args string) {
		if strings.ContainsAny(header, "\r\n") {
			return // net/http rejects these before any handler runs
		}
		nameJSON, _ := json.Marshal(bodyName)
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{` + metaOK + `,"name":` + string(nameJSON) + `,"arguments":` + args + `}}`
		rec := httptest.NewRecorder()
		req, out := transport().Accept(rec, fixture{headers: std("tools/call", header), body: body}.request())
		if out == Ready {
			dec, err := DecodeHeaderValue(header)
			require.NoError(t, err)
			require.Equal(t, bodyName, dec)
			require.Equal(t, bodyName, req.Name)
		}
	})
}

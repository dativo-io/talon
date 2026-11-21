package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/secrets"
)

// SecretGetter resolves a vault-backed credential under the AI use case's
// ACL identity (*secrets.SecretStore satisfies it).
type SecretGetter interface {
	Get(ctx context.Context, name, tenantID, agentID string) (*secrets.Secret, error)
}

// MCP _meta keys Talon sets on a forwarded tools/call: the operation-scoped
// idempotency identity (the same on every attempt of one operation), the
// operation reference and the attempt id. A source that deduplicates on the
// idempotency key turns a safe retry into a no-op; Talon never relies on it.
const (
	MetaIdempotencyKey = "io.dativo.talon/idempotencyKey"
	MetaOperationRef   = "io.dativo.talon/operationRef"
	MetaAttemptID      = "io.dativo.talon/attemptId"
)

// MCPClientName is the identity Talon presents to a source when it forwards
// an authorized tools/call.
const MCPClientName = "talon-action-gateway"

// MCPDispatcher forwards an authorized, claimed and armed attempt of an
// MCP-sourced definition as ONE tools/call to the definition's trusted
// source (#431). It shares the HTTP dispatcher's replay and redirect
// properties and its outcome truth table:
//
//	request never written                         → failed / not_dispatched
//	written, JSON-RPC result, resultType complete,
//	  isError absent or false                      → succeeded / observed
//	written, anything else (isError true, a JSON-RPC
//	  error, input_required, a task, a malformed or
//	  lost answer, a timeout)                      → UNKNOWN / unknown
//
// A tool-reported error after the request reached the source is UNKNOWN,
// not failed: the source may have performed part of the effect, and only a
// request that never left Talon is a safely retryable failure.
type MCPDispatcher struct {
	Client  *http.Client
	Secrets SecretGetter
	// Timeout bounds one dispatch (default 30s).
	Timeout time.Duration
	// Version is the Talon version presented in clientInfo.
	Version string
}

// NewMCPDispatcher returns an MCP dispatcher whose client can neither replay
// a request nor follow a redirect (see NewHTTPDispatcher).
func NewMCPDispatcher(client *http.Client, sec SecretGetter, version string) *MCPDispatcher {
	return &MCPDispatcher{Client: NewHTTPDispatcher(client).Client, Secrets: sec, Timeout: 30 * time.Second, Version: version}
}

// Dispatch implements Dispatcher.
func (d *MCPDispatcher) Dispatch(ctx context.Context, req DispatchRequest) Outcome {
	def := req.Definition
	if def == nil || def.Destination.Type != DestinationTypeMCP || def.UpstreamName == "" {
		return notDispatched("dispatch_destination_unsupported")
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hreq, id, code := d.newRequest(ctx, req)
	if code != "" {
		return notDispatched(code)
	}
	if code := d.authorize(ctx, hreq, req); code != "" {
		return notDispatched(code)
	}
	wrote := false
	hreq = hreq.WithContext(httptrace.WithClientTrace(hreq.Context(), &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wrote = true }}))
	client := d.Client
	if client == nil {
		client = NewHTTPDispatcher(nil).Client
	}
	//nolint:gosec // G704: the endpoint is the trusted, validated source configuration bound into the definition digest
	resp, err := client.Do(hreq)
	if err != nil {
		if !wrote {
			return notDispatched("dispatch_transport_error")
		}
		code := "dispatch_response_lost"
		if errors.Is(err, context.DeadlineExceeded) {
			code = "dispatch_timeout_after_send"
		}
		return Outcome{Status: AttemptUnknown, Provenance: ResultProvenanceUnknown, RequestWritten: true, Code: code}
	}
	return d.observe(resp, id)
}

// newRequest builds the one tools/call from the authorized payload: the
// upstream tool name from the trusted definition, Talon's own _meta with the
// operation-scoped idempotency identity, the Mcp-Param-* headers generated
// from the authorized arguments, and the idempotency headers.
func (d *MCPDispatcher) newRequest(ctx context.Context, req DispatchRequest) (*http.Request, json.RawMessage, string) {
	def := req.Definition
	meta := wire.OutboundMeta(wire.Meta{}, wire.Implementation{Name: MCPClientName, Version: d.Version})
	for k, v := range map[string]string{MetaIdempotencyKey: req.IdempotencyKey, MetaOperationRef: req.OperationRef, MetaAttemptID: req.AttemptID} {
		b, _ := json.Marshal(v)
		meta[k] = b
	}
	params := wire.EncodeCallParams(meta, wire.CallParams{Name: def.UpstreamName, Arguments: req.Payload})
	decls := make([]wire.ParamDecl, len(def.MirroredParams))
	for i, p := range def.MirroredParams {
		decls[i] = wire.ParamDecl{Header: p.Header, Path: append([]string(nil), p.Path...), Type: p.Type}
	}
	hp, err := wire.HeaderParamsFromDecls(decls)
	if err != nil {
		return nil, nil, "dispatch_header_params_invalid"
	}
	headers, err := wire.OutboundHeaderParams(hp, req.Payload)
	if err != nil {
		return nil, nil, "dispatch_header_params_invalid"
	}
	id, _ := json.Marshal(req.AttemptID)
	hreq, err := wire.NewUpstreamRequest(ctx, def.Destination.URL, id, wire.MethodToolsCall, params, def.UpstreamName, headers)
	if err != nil {
		return nil, nil, "dispatch_request_invalid"
	}
	hreq.Header.Set("Idempotency-Key", req.IdempotencyKey)
	hreq.Header.Set("X-Talon-Operation-Ref", req.OperationRef)
	hreq.Header.Set("X-Talon-Attempt-Id", req.AttemptID)
	// Non-replayable for net/http (see HTTPDispatcher).
	hreq.GetBody = nil
	return hreq, id, ""
}

// authorize adds the source's vault-backed credential, read under the AI
// use case's ACL identity for every attempt (a rotation applies at once).
func (d *MCPDispatcher) authorize(ctx context.Context, hreq *http.Request, req DispatchRequest) string {
	auth := req.Definition.Source.Auth
	if auth == nil {
		return ""
	}
	if d.Secrets == nil {
		return "dispatch_credential_unavailable"
	}
	sec, err := d.Secrets.Get(ctx, auth.SecretName, req.TenantID, req.AgentID)
	if err != nil || sec == nil {
		return "dispatch_credential_unavailable"
	}
	header := auth.Header
	if header == "" {
		header = "Authorization"
	}
	value := string(sec.Value)
	if auth.Scheme == nil || *auth.Scheme != "" {
		scheme := "Bearer"
		if auth.Scheme != nil {
			scheme = *auth.Scheme
		}
		value = scheme + " " + value
	}
	hreq.Header.Set(header, value)
	return ""
}

// observe reads the one JSON-RPC response and applies the truth table. Only
// a validated complete result with no tool error is a success; the result
// object travels back to the adapter in Outcome.Result and is never stored.
func (d *MCPDispatcher) observe(resp *http.Response, id json.RawMessage) Outcome {
	status := resp.StatusCode
	unknown := func(code string, observed bool) Outcome {
		return Outcome{Status: AttemptUnknown, Provenance: ResultProvenanceUnknown, RequestWritten: true, ResponseObserved: observed, HTTPStatus: status, Code: code}
	}
	if status >= 300 && status < 400 {
		_ = resp.Body.Close()
		return unknown("dispatch_redirect_refused", true)
	}
	rpc, err := wire.ReadUpstreamResponse(resp, id)
	if err != nil {
		if errors.Is(err, wire.ErrUpstreamStatus) {
			return unknown("upstream_http_status", true)
		}
		return unknown("upstream_response_invalid", false)
	}
	raw := rpc.Result
	if rpc.Error != nil {
		raw, _ = json.Marshal(rpc.Error)
	}
	sum := sha256.Sum256(raw)
	out := unknown("", true)
	out.Ref = hex.EncodeToString(sum[:])
	out.Result = append(json.RawMessage(nil), raw...)
	if rpc.Error != nil {
		out.Code = wire.RPCErrorToken("upstream_jsonrpc_error", rpc.Error.Code)
		return out
	}
	res, err := wire.ValidateUpstreamResult(rpc.Result, wire.Implementation{Name: MCPClientName, Version: d.Version})
	if err != nil {
		out.Code = "upstream_result_invalid"
		if errors.Is(err, wire.ErrResultTypeUnsupported) || errors.Is(err, wire.ErrResultTypeMissing) {
			out.Code = "upstream_result_type_unsupported"
		}
		return out
	}
	if res["resultType"] != wire.ResultTypeComplete {
		// input_required asks the original client for input: an authorized
		// effect cannot be continued through an elicitation round-trip.
		out.Code = "upstream_input_required_unsupported"
		return out
	}
	if isErr, _ := res["isError"].(bool); isErr {
		out.Code = "upstream_tool_error"
		return out
	}
	out.Status, out.Provenance, out.Code = AttemptSucceeded, ResultProvenanceObserved, "mcp_result_complete"
	return out
}

func notDispatched(code string) Outcome {
	return Outcome{Status: AttemptFailed, Provenance: ResultProvenanceNotDispatched, Code: code}
}

// Dispatchers routes an attempt to the dispatcher of its destination type.
// A destination type without a dispatcher is refused at establish
// (execution_unsupported) and, defensively, here before any request exists.
type Dispatchers map[string]Dispatcher

// Dispatch implements Dispatcher.
func (m Dispatchers) Dispatch(ctx context.Context, req DispatchRequest) Outcome {
	if req.Definition == nil {
		return notDispatched("dispatch_destination_unsupported")
	}
	d, ok := m[req.Definition.Destination.Type]
	if !ok || d == nil {
		return notDispatched("dispatch_destination_unsupported")
	}
	return d.Dispatch(ctx, req)
}

// Supports implements destinationSupporter.
func (m Dispatchers) Supports(destinationType string) bool {
	d, ok := m[destinationType]
	return ok && d != nil
}

// destinationSupporter is implemented by a dispatcher that can tell, before
// anything is bound, whether it executes a destination type.
type destinationSupporter interface {
	Supports(destinationType string) bool
}

// Supports implements destinationSupporter: the HTTP dispatcher executes
// http destinations only.
func (d *HTTPDispatcher) Supports(destinationType string) bool {
	return destinationType == DestinationTypeHTTP
}

// Supports implements destinationSupporter.
func (d *MCPDispatcher) Supports(destinationType string) bool {
	return destinationType == DestinationTypeMCP
}

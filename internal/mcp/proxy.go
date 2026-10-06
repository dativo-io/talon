// Package mcp implements the MCP proxy for vendor integration. Governed calls
// are always intercepted and enforced (#442): forbidden tools, policy denials
// and PII denials never reach the upstream.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/secrets"
)

var proxyTracer = otel.Tracer("github.com/dativo-io/talon/internal/mcp")

// UpstreamSecretGetter is the vault surface the proxy needs for upstream
// auth (#358) — satisfied by *secrets.SecretStore; an interface so tests can
// fake retrieval failures.
type UpstreamSecretGetter interface {
	Get(ctx context.Context, name, tenantID, agentID string) (*secrets.Secret, error)
}

// ProxyHandler forwards MCP requests to an upstream vendor endpoint with policy and PII handling.
type ProxyHandler struct {
	config        *policy.ProxyPolicyConfig
	proxyEngine   *policy.ProxyEngine
	evidenceStore *evidence.Store
	classifier    classifier.Facade
	secrets       UpstreamSecretGetter
	httpClient    *http.Client
	runtime       ProxyRuntimeConfig
	// Transport is the shared 2026-07-28 protocol gate (same implementation
	// as the native route).
	Transport *wire.Transport

	captureMu sync.Mutex
	capture   *definitionCapture
}

// NewProxyHandler creates an MCP proxy handler. secretsStore may be nil when
// the proxy config declares no upstream auth; with an auth block and no
// store, every upstream call fails closed.
func NewProxyHandler(
	cfg *policy.ProxyPolicyConfig,
	proxyEngine *policy.ProxyEngine,
	evidenceStore *evidence.Store,
	cls classifier.Facade,
	secretsStore UpstreamSecretGetter,
) *ProxyHandler {
	timeout := 30 * time.Second
	return &ProxyHandler{
		config:        cfg,
		proxyEngine:   proxyEngine,
		evidenceStore: evidenceStore,
		classifier:    cls,
		secrets:       secretsStore,
		httpClient:    newUpstreamClient(timeout),
		runtime:       DefaultProxyRuntime(),
		Transport:     newTransport(),
	}
}

// newUpstreamClient never follows redirects: the configured upstream is the
// only endpoint an authorized call may reach, and a redirect would carry the
// upstream credential elsewhere.
func newUpstreamClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// proxyServer is the identity this route reports and uses as the MCP client
// of the upstream.
func proxyServer() wire.Implementation {
	return wire.Implementation{Name: "talon-mcp-proxy", Version: ServerVersion}
}

// definitionCapture is the proxy's ONE trusted protocol-definition source
// (#447): the tool definitions of the last validated upstream tools/list,
// filtered to allowed_tools and purged of definitions whose x-mcp-header
// annotations violate the spec. It expires on the upstream's ttlMs. The
// same capture is what tools/list presents, what inbound Mcp-Param-*
// headers are validated against, and what outbound Mcp-Param-* headers are
// generated from — so advertisement and validation can never drift. It is
// protocol metadata only: it never defines policy, materiality or approval.
type definitionCapture struct {
	presented []capturedTool           // allowed_tools subset, sorted by name: what tools/list shows
	byName    map[string]*capturedTool // every valid upstream definition by upstream name: what tools/call resolves
	ttlMs     json.Number
	expires   time.Time
}

type capturedTool struct {
	name string
	raw  json.RawMessage
	decl *wire.HeaderParams
}

// upstreamToolName maps a Talon-facing tool name to the upstream name.
func (h *ProxyHandler) upstreamToolName(toolName string) string {
	for _, m := range h.config.Proxy.AllowedTools {
		if m.Name == toolName && m.UpstreamName != "" {
			return m.UpstreamName
		}
	}
	return toolName
}

// trustedDefinitions returns the live capture, refreshing it from the
// upstream (through the same strict list validation) when absent or
// expired. A failure leaves no partial capture and is returned to the
// caller as the upstream error to surface — fail closed, zero dispatch.
func (h *ProxyHandler) trustedDefinitions(ctx context.Context, req *wire.Request, inv *proxyInvocation) (*definitionCapture, *captureFailure) {
	h.captureMu.Lock()
	defer h.captureMu.Unlock()
	if h.capture != nil && time.Now().Before(h.capture.expires) {
		return h.capture, nil
	}
	cap, fail := h.fetchDefinitions(ctx, req, inv)
	if fail != nil {
		return nil, fail
	}
	h.capture = cap
	return cap, nil
}

// fetchDefinitions performs upstream tools/list through the shared wire
// fetch (every page, strict validation, bounded pagination) and builds a
// capture from the validated result.
func (h *ProxyHandler) fetchDefinitions(ctx context.Context, req *wire.Request, inv *proxyInvocation) (*definitionCapture, *captureFailure) {
	allowedSet := make(map[string]bool, len(h.config.Proxy.AllowedTools))
	for _, t := range h.config.Proxy.AllowedTools {
		allowedSet[t.Name] = true
		if t.UpstreamName != "" {
			allowedSet[t.UpstreamName] = true
		}
	}
	do := wire.DoerFunc(func(r *http.Request) (*http.Response, error) { return h.doUpstream(r.Context(), r, inv) })
	list, err := wire.FetchToolList(ctx, do, h.config.Proxy.Upstream.URL, req.ID, wire.OutboundMeta(req.Meta, proxyServer()))
	if err != nil {
		return nil, h.captureFailureFor(req, err)
	}
	cap := &definitionCapture{byName: map[string]*capturedTool{}, ttlMs: list.TTLMs}
	for _, toolRaw := range list.Tools {
		name := toolNameFromRaw(toolRaw)
		if name == "" {
			continue
		}
		decl, err := capturedDeclaration(toolRaw)
		if err != nil {
			// Spec: a definition with an invalid x-mcp-header annotation
			// is excluded (from tools/list and from tools/call); log the
			// tool and the reason.
			log.Warn().Str("tool", name).Err(err).Msg("mcp_proxy_tool_excluded_invalid_header_annotation")
			continue
		}
		cap.byName[name] = &capturedTool{name: name, raw: toolRaw, decl: decl}
	}
	for name, ct := range cap.byName {
		if allowedSet[name] {
			cap.presented = append(cap.presented, *ct)
		}
	}
	sort.Slice(cap.presented, func(i, j int) bool { return cap.presented[i].name < cap.presented[j].name })
	cap.expires = captureExpiry(cap.ttlMs)
	return cap, nil
}

// captureFailureFor maps a classified upstream failure to the evidence
// reason and the JSON-RPC answer the proxy returns: an unreachable upstream
// leaves egress unconfirmed, a vault failure stays a generic configuration
// error, an upstream JSON-RPC error is relayed, and every contract
// violation is an invalid upstream response.
func (h *ProxyHandler) captureFailureFor(req *wire.Request, err error) *captureFailure {
	upstreamErr := func(reason, msg string) *captureFailure {
		return &captureFailure{reason: reason, resp: &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: msg, Data: talonErrData(TalonCodeUpstreamError)}}}
	}
	var ue *wire.UpstreamError
	if !errors.As(err, &ue) {
		return upstreamErr("upstream_response_invalid", "upstream response invalid: "+err.Error())
	}
	switch ue.Kind {
	case wire.UpstreamKindRequest:
		return upstreamErr("outbound_request_invalid", ue.Err.Error())
	case wire.UpstreamKindTransport:
		if errors.Is(ue, errSecretRetrieval) {
			// Fail-closed vault failure (#358): generic message, no detail leak.
			f := upstreamErr("secret retrieval error", "Service configuration error")
			f.transport = true
			return f
		}
		f := upstreamErr("upstream_error: "+ue.Err.Error(), ue.Err.Error())
		f.transport = true
		return f
	case wire.UpstreamKindRPC:
		out := &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: ue.RPC.Code, Message: ue.RPC.Message}}
		if len(ue.RPC.Data) > 0 {
			out.Error.Data = ue.RPC.Data
		}
		return &captureFailure{reason: fmt.Sprintf("upstream_jsonrpc_error: %d %s", ue.RPC.Code, ue.RPC.Message), resp: out}
	default:
		return upstreamErr("upstream_response_invalid", "upstream response invalid: "+ue.Err.Error())
	}
}

// captureExpiry turns the upstream ttlMs hint into the capture's deadline;
// 0 (or an invalid value) is immediately stale, re-captured per request.
func captureExpiry(ttlMs json.Number) time.Time {
	ttl, ok := new(big.Rat).SetString(string(ttlMs))
	if !ok || ttl.Sign() <= 0 {
		return time.Now()
	}
	f, _ := ttl.Float64()
	return time.Now().Add(time.Duration(f * float64(time.Millisecond)))
}

// capturedDeclaration derives the mirrored-parameter declaration from the
// exact upstream definition that will be presented.
func capturedDeclaration(toolRaw json.RawMessage) (*wire.HeaderParams, error) {
	var t struct {
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	if err := json.Unmarshal(toolRaw, &t); err != nil {
		return nil, err
	}
	if len(t.InputSchema) == 0 {
		return &wire.HeaderParams{}, nil
	}
	return wire.HeaderParamsFromSchema(t.InputSchema)
}

// captureFailure is why a definition capture could not be completed: the
// evidence reason (same vocabulary as a failed dispatch) and the response.
type captureFailure struct {
	reason    string
	transport bool // nothing reached the upstream's handler (egress unconfirmed)
	resp      *jsonrpcResponse
}

// proxyInvocation carries request-scoped attribution for evidence (#350):
// resolved once at the HTTP boundary and reused by every record the call
// produces, so tenant, agent, session, and correlation stay consistent
// across the intent/result records of one MCP call and joinable with the
// same use case's LLM gateway traffic.
type proxyInvocation struct {
	tenantID string
	// agentID is the authenticated agent from the key middleware when
	// present; otherwise the proxy config's agent name; "mcp-proxy" only as
	// the final legacy fallback (admin/dev-open paths with an unnamed config).
	agentID string
	team    string
	// sessionID is the validated X-Talon-Session-ID ("" when not asserted).
	// Client-asserted: attribution, not authentication — never a policy input.
	sessionID string
	// correlationID is the validated inbound X-Correlation-ID, or one
	// generated ID reused across all records of this request.
	correlationID string
	orch          *evidence.OrchestrationContext
}

// proxyAttributionHeaders are the client-asserted attribution headers the
// proxy validates and consumes (#350).
var proxyAttributionHeaders = []string{
	"X-Talon-Session-ID",
	"X-Talon-Agent-ID",
	"X-Talon-Parent-Agent-ID",
	"X-Talon-Client",
	"X-Correlation-ID",
}

// resolveProxyInvocation builds the invocation context from the authenticated
// request context and the neutral X-Talon-* attribution headers. Header
// values follow the same hygiene contract as the gateway (128-byte cap, RFC
// 7230 token charset, reject — never truncate): an error here must become an
// HTTP 400 before any evidence is written. Vendor header adapters are an LLM
// wire concern and deliberately not consulted on the MCP wire.
func (h *ProxyHandler) resolveProxyInvocation(r *http.Request) (*proxyInvocation, error) {
	ctx := r.Context()
	inv := &proxyInvocation{}

	inv.tenantID = requestctx.TenantID(ctx)
	if inv.tenantID == "" {
		inv.tenantID = "default"
	}
	if id, ok := requestctx.AgentIdentityFrom(ctx); ok {
		inv.agentID = id.AgentID
		inv.team = id.Team
	} else if h.config != nil && h.config.Agent.Name != "" {
		// Admin-key and dev-open paths carry no agent identity: attribute to
		// the proxy's own declared agent identity from the config.
		inv.agentID = h.config.Agent.Name
	} else {
		inv.agentID = "mcp-proxy"
	}

	vals := make(map[string]string, len(proxyAttributionHeaders))
	for _, name := range proxyAttributionHeaders {
		v, err := evidence.ValidateOrchValue(name, r.Header.Get(name))
		if err != nil {
			return nil, err
		}
		vals[name] = v
	}
	sessionID := vals["X-Talon-Session-ID"]
	subagent := vals["X-Talon-Agent-ID"]
	parent := vals["X-Talon-Parent-Agent-ID"]
	client := vals["X-Talon-Client"]
	correlationID := vals["X-Correlation-ID"]
	if correlationID == "" {
		correlationID = "mcp_proxy_" + uuid.New().String()[:8]
	}
	inv.sessionID = sessionID
	inv.correlationID = correlationID

	// Same emission rule as the gateway: a bare session id fills the
	// session_id column only; the orchestration block exists when the client
	// asserted identity beyond the session.
	if subagent != "" || parent != "" || client != "" {
		if client == "" {
			client = "generic"
		}
		sessionSource := ""
		if sessionID != "" {
			sessionSource = "client_asserted"
		}
		inv.orch = &evidence.OrchestrationContext{
			SessionID:     sessionID,
			AgentID:       subagent,
			ParentAgentID: parent,
			Client:        client,
			SessionSource: sessionSource,
			Provenance:    "client_asserted",
		}
	}
	return inv, nil
}

// SetRuntime overrides timeout and auth for upstream calls.
func (h *ProxyHandler) SetRuntime(cfg ProxyRuntimeConfig) {
	h.runtime = cfg
	timeout := cfg.UpstreamTimeout
	if timeout <= 0 {
		timeout = DefaultProxyRuntime().UpstreamTimeout
	}
	// The hardened client is rebuilt, never replaced by a default one:
	// redirect denial survives every runtime change.
	h.httpClient = newUpstreamClient(timeout)
}

// ServeHTTP handles POST /mcp/proxy JSON-RPC 2.0 and forwards to upstream.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := proxyTracer.Start(r.Context(), "mcp.proxy.serve")
	defer span.End()

	// Protocol gate first (#447): transport, version, _meta, header/body
	// integrity and the method allowlist. A rejection here is a protocol
	// error with no governance evidence — no trustworthy action exists yet.
	req, outcome := h.Transport.Accept(w, r)
	if outcome != wire.Ready {
		span.SetAttributes(attribute.Bool("mcp.protocol_rejected", outcome == wire.Rejected))
		return
	}
	span.SetAttributes(attribute.String("mcp.method", req.Method))

	// Attribution is resolved once per request (#350). Header hygiene
	// violations are rejected before any evidence is written, mirroring the
	// gateway contract (reject, never truncate).
	inv, err := h.resolveProxyInvocation(r)
	if err != nil {
		wire.WriteError(w, req.ID, &wire.Error{Status: http.StatusBadRequest, Code: wire.CodeInvalidRequest, Reason: wire.ReasonInvalidRequest, Message: "invalid attribution header: " + err.Error()})
		return
	}
	// Echo the resolved identifiers so callers can join their receipts to
	// the audit trail. X-Talon-Session-ID is Talon application correlation,
	// never an MCP transport session (there is none).
	w.Header().Set("X-Correlation-ID", inv.correlationID)
	if inv.sessionID != "" {
		w.Header().Set("X-Talon-Session-ID", inv.sessionID)
	}

	var resp *jsonrpcResponse
	switch req.Method {
	case wire.MethodDiscover:
		resp = &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: wire.Discover(proxyServer(), map[string]interface{}{"tools": map[string]interface{}{}}, "", listTTLMs)}
	case wire.MethodToolsList:
		resp = h.handleToolsList(ctx, req, inv)
	case wire.MethodToolsCall:
		resp = h.handleProxyToolCall(ctx, w, req, inv)
		if resp == nil {
			return // protocol rejection already written
		}
	}
	resp.write(w)
}

//nolint:gocyclo // proxy flow: forbidden, policy, PII, forward, evidence
func (h *ProxyHandler) handleProxyToolCall(ctx context.Context, w http.ResponseWriter, req *wire.Request, inv *proxyInvocation) *jsonrpcResponse {
	ctx, span := proxyTracer.Start(ctx, "mcp.proxy.tools.call")
	defer span.End()

	params := toolsCallParams{Name: req.Name, Arguments: req.Arguments}
	toolName := params.Name
	if toolName == "" {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "tool name is required"}}
	}

	// Map to upstream name
	upstreamName := toolName
	for _, m := range h.config.Proxy.AllowedTools {
		if m.Name == toolName {
			if m.UpstreamName != "" {
				upstreamName = m.UpstreamName
			}
			break
		}
	}

	// Forbidden check (fail-closed): an explicitly forbidden tool is blocked
	// before any policy evaluation and never reaches the upstream.
	for _, f := range h.config.Proxy.ForbiddenTools {
		if f == toolName || (strings.HasSuffix(f, "*") && strings.HasPrefix(toolName, strings.TrimSuffix(f, "*"))) {
			span.SetAttributes(attribute.String("proxy.blocked", "forbidden"))
			h.recordEvidence(ctx, inv, "proxy_tool_blocked", toolName, "forbidden_tools", nil)
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "tool not allowed by policy", Data: talonErrData(TalonCodeToolForbidden)}}
		}
	}

	// Mcp-Param-* integrity against the captured trusted definition (the
	// exact definition tools/list presents), before forbidden/policy/PII: a
	// mismatch is a protocol rejection with zero governance evidence and
	// zero upstream dispatch. An unknown tool (not upstream, or excluded for
	// an invalid annotation) is the spec's protocol error.
	var flow proxyFlowState

	// Policy: tool access
	proxyInput := &policy.ProxyInput{
		ToolName:       toolName,
		Vendor:         h.config.Proxy.Upstream.Vendor,
		UpstreamRegion: h.upstreamRegion(),
		Arguments:      paramsToMap(params.Arguments),
	}
	decision, err := h.proxyEngine.EvaluateProxyToolAccess(ctx, proxyInput)
	if err != nil {
		span.RecordError(err)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error()}}
	}
	if !decision.Allowed {
		denyReason := strings.Join(decision.Reasons, "; ")
		h.recordEvidence(ctx, inv, "proxy_tool_blocked", toolName, denyReason, nil)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: denyReason, Data: talonErrData(TalonCodePolicyDenied)}}
	}

	// PII scan on arguments. A scanner failure blocks the call fail-closed:
	// arguments Talon cannot classify must not reach the upstream tool.
	if h.classifier != nil {
		argStr := string(params.Arguments)
		result, scanErr := h.classifier.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
		if scanErr != nil {
			flow.requestBlocked = true
			flow.scannerFailure = scannerFailureKind(scanErr)
			h.recordEvidence(ctx, inv, "proxy_pii_scan_error", toolName, "scanner_unavailable", &flow)
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "Request blocked: PII scanner unavailable (fail-closed)", Data: talonErrData(TalonCodeScannerUnavailable)}}
		}
		if result != nil && len(result.Entities) > 0 {
			flow.requestEntities = classifier.MergeEntitySpans(argStr, result.Entities)
			flow.requestEntities = applyFlowFieldPath(flow.requestEntities, "arguments")
			flow.requestTier = result.Tier
			for _, e := range result.Entities {
				proxyInput.DetectedPII = append(proxyInput.DetectedPII, e.Type)
			}
			piiDecision, piiErr := h.proxyEngine.EvaluateProxyPII(ctx, proxyInput)
			if piiErr != nil {
				// Fail closed: arguments whose PII verdict Talon cannot
				// compute must not reach the upstream tool.
				flow.requestBlocked = true
				h.recordEvidence(ctx, inv, "proxy_pii_eval_error", toolName, piiErr.Error(), &flow)
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "PII policy evaluation failed (fail-closed)", Data: talonErrData(TalonCodePIIBlocked)}}
			}
			if piiDecision != nil && !piiDecision.Allowed {
				flow.requestBlocked = true
				h.recordEvidence(ctx, inv, "proxy_pii_request_detected", toolName, "pii_detected_in_request", &flow)
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "PII detected in request", Data: talonErrData(TalonCodePIIBlocked)}}
			}
			redactedArgs, redactErr := h.classifier.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
			if redactErr != nil {
				flow.requestBlocked = true
				flow.scannerFailure = scannerFailureKind(redactErr)
				h.recordEvidence(ctx, inv, "proxy_pii_scan_error", toolName, "scanner_unavailable", &flow)
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "Request blocked: PII redaction failed (fail-closed)", Data: talonErrData(TalonCodeScannerUnavailable)}}
			}
			if verifyErr := h.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), redactedArgs); verifyErr != nil {
				flow.requestBlocked = true
				reason := "request_residual_pii_after_redaction"
				msg := residualBlockMessage("Request blocked: recognized PII remains after redaction", classifier.ResidualTypes(verifyErr))
				code := TalonCodePIIBlocked
				if !errors.Is(verifyErr, classifier.ErrPIIDetected) {
					reason = "request_redaction_verification_scanner_unavailable"
					msg = "Request blocked: redaction could not be verified (fail-closed)"
					flow.scannerFailure = scannerFailureKind(verifyErr)
					code = TalonCodeScannerUnavailable
				}
				h.recordEvidence(ctx, inv, "proxy_pii_request_detected", toolName, reason, &flow)
				return &jsonrpcResponse{
					JSONRPC: jsonrpcVersion,
					ID:      req.ID,
					Error: &rpcError{
						Code:    codeServerError,
						Message: msg,
						Data:    talonErrData(code),
					},
				}
			}
			if redactedArgs != argStr {
				if !json.Valid([]byte(redactedArgs)) {
					flow.requestBlocked = true
					h.recordEvidence(ctx, inv, "proxy_pii_request_detected", toolName, "request_redaction_invalid_json", &flow)
					return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "PII redaction produced invalid JSON (fail-closed)", Data: talonErrData(TalonCodePIIBlocked)}}
				}
				params.Arguments = json.RawMessage(redactedArgs)
				proxyInput.Arguments = paramsToMap(params.Arguments)
				flow.requestRedacted = true
			}
			// #357: no separate allowed "note" record here — the request-side
			// classification and data flow ride on the call's terminal record
			// (one call = one request-class record). Denied PII paths above
			// keep their own terminal records.
		}
	}

	capture, fail := h.trustedDefinitions(ctx, req, inv)
	if fail != nil {
		// The call was attempted and the upstream could not provide its
		// definitions: the terminal record is an upstream error carrying the
		// request-side classification. A transport failure leaves egress
		// unconfirmed; a response that arrived is a truthful flow item.
		flow.egressUnconfirmed = fail.transport
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, fail.reason, &flow)
		return fail.resp
	}
	captured, known := capture.byName[h.upstreamToolName(toolName)]
	if !known {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "Unknown tool: " + toolName}}
	}
	// Inbound mirrors are checked against the ORIGINAL parsed arguments (the
	// client mirrored what it sent); outbound mirrors below are generated
	// from the redacted, authorized arguments Talon actually forwards.
	if perr := wire.ValidateHeaderParams(captured.decl, req.Arguments, req.HeaderParams); perr != nil {
		span.SetAttributes(attribute.String("mcp.protocol_reason", perr.Reason))
		wire.WriteError(w, req.ID, perr)
		return nil
	}

	// Forward: a FRESH request built from the authorized, normalized
	// payload — canonical upstream name, redacted arguments, the client's
	// MRTR continuation (requestState/inputResponses) and permitted _meta,
	// this protocol version, Talon's identity, and Mcp-* headers generated
	// from that body (never copied from inbound headers).
	outMeta := wire.OutboundMeta(req.Meta, proxyServer())
	outParams := wire.EncodeCallParams(outMeta, wire.CallParams{Name: upstreamName, Arguments: params.Arguments, RequestState: req.RequestState, InputResponses: req.InputResponses})
	// Generated from the AUTHORIZED, redacted outbound arguments and the
	// captured declaration — never from inbound header values.
	paramHeaders, err := wire.OutboundHeaderParams(captured.decl, params.Arguments)
	if err != nil {
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "outbound_header_params_invalid", &flow)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "argument cannot be mirrored into the declared header: " + err.Error(), Data: talonErrData(TalonCodeUpstreamError)}}
	}
	httpReq, err := wire.NewUpstreamRequest(ctx, h.config.Proxy.Upstream.URL, req.ID, wire.MethodToolsCall, outParams, upstreamName, paramHeaders)
	if err != nil {
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "outbound_request_invalid", &flow)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error(), Data: talonErrData(TalonCodeUpstreamError)}}
	}
	upstreamResp, err := h.doUpstream(ctx, httpReq, inv) //nolint:bodyclose // closed by wire.ReadUpstreamResponse
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		// #357: with the PII note folded into the terminal record, the
		// upstream-failure path must still leave the call's trail —
		// including any request-side PII classification in flow. Transport
		// errors mean egress is UNCONFIRMED (connection refused = nothing
		// left; timeout = maybe): the signed record keeps the classification
		// but must not assert a data flow to the vendor that may never have
		// happened.
		flow.egressUnconfirmed = true
		if errors.Is(err, errSecretRetrieval) {
			// Vault failure (#358): fail-closed, generic message to the
			// vendor (gateway parity — no vault detail leaks), evidence
			// carries the typed reason.
			h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "secret retrieval error", &flow)
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "Service configuration error", Data: talonErrData(TalonCodeUpstreamError)}}
		}
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "upstream_error: "+err.Error(), &flow)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error(), Data: talonErrData(TalonCodeUpstreamError)}}
	}
	upstream, err := wire.ReadUpstreamResponse(upstreamResp, req.ID)
	if err != nil {
		// A response arrived, so egress happened — the flow item is truthful.
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "upstream_response_invalid", &flow)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "upstream response invalid: " + err.Error(), Data: talonErrData(TalonCodeUpstreamError)}}
	}
	out := jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID}
	if upstream.Error != nil {
		// The vendor answered with a JSON-RPC error: the call executed and
		// failed — record it as such, never as a clean allowed completion.
		out.Error = &rpcError{Code: upstream.Error.Code, Message: upstream.Error.Message}
		if len(upstream.Error.Data) > 0 {
			out.Error.Data = upstream.Error.Data
		}
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName,
			fmt.Sprintf("upstream_jsonrpc_error: %d %s", upstream.Error.Code, upstream.Error.Message), &flow)
		return &out
	}
	// resultType truth table (#447): complete continues, input_required
	// (MRTR) passes through losslessly, a missing resultType is an upstream
	// protocol violation, and task or any other value is unsupported on this
	// surface (the Tasks extension is not advertised, #448).
	normalized, err := wire.ValidateUpstreamResult(upstream.Result, proxyServer())
	if err != nil {
		reason := "upstream_result_type_unsupported"
		if errors.Is(err, wire.ErrResultTypeMissing) {
			reason = "upstream_result_type_missing"
		}
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, reason, &flow)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "upstream response invalid: " + err.Error(), Data: talonErrData(TalonCodeUpstreamError)}}
	}
	out.Result = normalized

	// Response PII scanning: scan tool result before returning to caller.
	// A scanner failure blocks the result fail-closed.
	if h.classifier != nil && out.Result != nil {
		resultBytes, _ := json.Marshal(out.Result)
		resultStr := string(resultBytes)
		cls, scanErr := h.classifier.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), resultStr)
		if scanErr != nil {
			flow.responseBlocked = true
			flow.scannerFailure = scannerFailureKind(scanErr)
			h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "output_scanner_unavailable", &flow)
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "Tool result blocked: PII scanner unavailable (fail-closed)", Data: talonErrData(TalonCodeScannerUnavailable)}}
		}
		if cls != nil && cls.HasPII {
			piiTypes := make([]string, 0, len(cls.Entities))
			for _, e := range cls.Entities {
				piiTypes = append(piiTypes, e.Type)
			}
			span.SetAttributes(
				attribute.Bool("proxy.output_pii_detected", true),
				attribute.StringSlice("proxy.output_pii_types", piiTypes),
				attribute.String("proxy.upstream_region", h.upstreamRegion()),
			)
			flow.responseEntities = classifier.MergeEntitySpans(resultStr, cls.Entities)
			flow.responseEntities = applyFlowFieldPath(flow.responseEntities, "result")
			flow.responseTier = cls.Tier
			flow.responseRedacted = true
			redacted, redactErr := h.classifier.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), resultStr)
			if redactErr != nil {
				flow.responseBlocked = true
				flow.scannerFailure = scannerFailureKind(redactErr)
				h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "output_scanner_unavailable", &flow)
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "Tool result blocked: PII redaction failed (fail-closed)", Data: talonErrData(TalonCodeScannerUnavailable)}}
			}
			if verifyErr := h.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), redacted); verifyErr != nil {
				flow.responseBlocked = true
				reason := "output_pii_blocked_residual"
				msg := residualBlockMessage("Tool result blocked: recognized PII remains after redaction", classifier.ResidualTypes(verifyErr))
				code := TalonCodePIIBlocked
				if !errors.Is(verifyErr, classifier.ErrPIIDetected) {
					reason = "output_redaction_verification_scanner_unavailable"
					msg = "Tool result blocked: redaction could not be verified (fail-closed)"
					flow.scannerFailure = scannerFailureKind(verifyErr)
					code = TalonCodeScannerUnavailable
				}
				h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, reason, &flow)
				return &jsonrpcResponse{
					JSONRPC: jsonrpcVersion,
					ID:      req.ID,
					Error: &rpcError{
						Code:    codeServerError,
						Message: msg,
						Data:    talonErrData(code),
					},
				}
			}
			var redactedResult interface{}
			if err := json.Unmarshal([]byte(redacted), &redactedResult); err != nil {
				flow.responseBlocked = true
				h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "output_redaction_invalid_json", &flow)
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "PII redaction of tool result produced invalid JSON (fail-closed)", Data: talonErrData(TalonCodePIIBlocked)}}
			}
			out.Result = redactedResult
			h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "output_pii_redacted", &flow)
		} else {
			h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "", &flow)
		}
	} else {
		h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "", &flow)
	}

	return &out
}

func residualBlockMessage(prefix string, types []string) string {
	remediation := " Remediation required: use approval workflow to adjust policy or content, re-run redaction, then re-scan."
	if len(types) == 0 {
		return prefix + "." + remediation
	}
	return prefix + " (types: " + strings.Join(types, ", ") + ")." + remediation
}

func applyFlowFieldPath(entities []classifier.PIIEntity, fieldPath string) []classifier.PIIEntity {
	if len(entities) == 0 {
		return entities
	}
	out := make([]classifier.PIIEntity, 0, len(entities))
	for _, e := range entities {
		cpy := e
		if cpy.FieldPath == "" {
			cpy.FieldPath = fieldPath
		}
		out = append(out, cpy)
	}
	return out
}

// toolNameFromRaw returns the tool's name for allowlist check (MCP uses "name"; some impls use "id").
func toolNameFromRaw(raw json.RawMessage) string {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	if n, ok := m["name"].(string); ok && n != "" {
		return n
	}
	if id, ok := m["id"].(string); ok && id != "" {
		return id
	}
	return ""
}

// handleToolsList presents the captured trusted definitions: exactly the
// definitions tools/call validates against. Talon's list is a single page
// (the capture already followed upstream pagination), so a client cursor
// is invalid params. Cache hints: the upstream's exact ttlMs, and always
// cacheScope private because the list is filtered for this governed route.
func (h *ProxyHandler) handleToolsList(ctx context.Context, req *wire.Request, inv *proxyInvocation) *jsonrpcResponse {
	ctx, span := proxyTracer.Start(ctx, "mcp.proxy.tools.list")
	defer span.End()
	if req.Cursor != "" {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "invalid cursor: this list is a single page"}}
	}
	capture, fail := h.trustedDefinitions(ctx, req, inv)
	if fail != nil {
		return fail.resp
	}
	tools := make([]interface{}, 0, len(capture.presented))
	for _, ct := range capture.presented {
		var v interface{}
		_ = json.Unmarshal(ct.raw, &v)
		tools = append(tools, v)
	}
	span.SetAttributes(attribute.Int("proxy.tools_presented", len(tools)))
	result := wire.Cacheable(wire.Complete(proxyServer(), map[string]interface{}{"tools": tools}), capture.ttlMs, wire.CacheScopePrivate)
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: result}
}

// errSecretRetrieval marks a vault failure on the upstream-auth path (#358):
// fail-closed, surfaced to the caller as a generic configuration error
// (gateway parity — vault details never leak to the vendor).
var errSecretRetrieval = errors.New("secret retrieval error")

// doUpstream attaches the vault-backed upstream credential to an already
// constructed MCP request and sends it.
func (h *ProxyHandler) doUpstream(ctx context.Context, req *http.Request, inv *proxyInvocation) (*http.Response, error) {
	// Vault-backed upstream auth (#358): resolved PER REQUEST — rotation via
	// `talon secrets set` lands immediately, and retrieval failure is
	// fail-closed (the request never leaves without its credential). The
	// vault ACL identity is the proxy's own declared agent, stable
	// regardless of caller.
	if auth := h.config.Proxy.Upstream.Auth; auth != nil {
		if h.secrets == nil {
			return nil, fmt.Errorf("%w: no secrets store wired", errSecretRetrieval)
		}
		sec, err := h.secrets.Get(ctx, auth.SecretName, inv.tenantID, h.config.Agent.Name)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errSecretRetrieval, err)
		}
		header := auth.Header
		if header == "" {
			header = "Authorization"
		}
		value := string(sec.Value)
		scheme := "Bearer"
		if auth.Scheme != nil {
			scheme = *auth.Scheme
		}
		if scheme != "" {
			value = scheme + " " + value
		}
		req.Header.Set(header, value)
	}
	//nolint:gosec // G704: upstream URL is from proxy config (validated at load), not user request input
	return h.httpClient.Do(req)
}

// proxyFlowState carries in-memory classification results across the proxy
// pipeline so evidence records get classification and data-flow sections.
// Entity values stay in memory only — evidence carries digests.
// scannerFailureKind returns the typed adapter failure kind (timeout,
// transport, status, decode, validation) for evidence, falling back to the
// generic scanner_unavailable for non-adapter engines.
func scannerFailureKind(err error) string {
	if kind := adapter.FailureKind(err); kind != "" {
		return kind
	}
	return "scanner_unavailable"
}

type proxyFlowState struct {
	requestEntities  []classifier.PIIEntity // merged (non-overlapping) spans from tool arguments
	requestTier      int
	requestBlocked   bool // arguments were not forwarded upstream
	requestRedacted  bool
	responseEntities []classifier.PIIEntity // merged spans from the tool result
	responseTier     int
	responseRedacted bool
	responseBlocked  bool
	// scannerFailure is the typed adapter failure kind (timeout, transport,
	// status, decode, validation) when a scanner failure drove a block;
	// "scanner_unavailable" for non-adapter engines.
	scannerFailure string
	// egressUnconfirmed marks upstream TRANSPORT failures (#357 review):
	// classification still attaches to the record, but no data-flow item is
	// emitted — a signed flow entry must never assert delivery to the vendor
	// when the connection may never have been established.
	egressUnconfirmed bool
}

// upstreamRegion returns the configured jurisdiction of the upstream vendor
// endpoint, or "unknown" when not configured. Never a guess.
func (h *ProxyHandler) upstreamRegion() string {
	if r := strings.TrimSpace(h.config.Proxy.Upstream.Region); r != "" {
		return r
	}
	return evidence.FlowRegionUnknown
}

// upstreamEndpointHost returns the host of the upstream URL (no path/query).
func (h *ProxyHandler) upstreamEndpointHost() string {
	u, err := url.Parse(h.config.Proxy.Upstream.URL)
	if err != nil {
		return ""
	}
	return u.Host
}

// proxyRecordAllowed decides the record's PolicyDecision.Allowed. It must
// reflect what actually happened, not the event label: the output fail-closed
// branches (scanner unavailable, residual PII, invalid redaction JSON) record
// eventType proxy_tool_call with a blocked flow, and evidence must say denied
// for those. An upstream error is an ALLOWED record (policy permitted the call; the
// vendor failed): counting it as a deny would inflate the attention queue's
// denial rate on vendor outages — the failure lives in Status/FailureReason.
func proxyRecordAllowed(eventType, reason string, flow *proxyFlowState) bool {
	if flow != nil && (flow.requestBlocked || flow.responseBlocked) {
		return false
	}
	return eventType == "proxy_tool_call" ||
		eventType == "proxy_upstream_error"
}

// attachProxyFlow copies the flow's classification and data-flow sections
// onto the record.
func (h *ProxyHandler) attachProxyFlow(ev *evidence.Evidence, inv *proxyInvocation, toolName string, flow *proxyFlowState) {
	ev.Classification = evidence.Classification{
		InputTier:         flow.requestTier,
		OutputTier:        flow.responseTier,
		PIIDetected:       entityTypeSet(flow.requestEntities),
		OutputPIIDetected: len(flow.responseEntities) > 0,
		OutputPIITypes:    entityTypeSet(flow.responseEntities),
		PIIRedacted:       flow.responseRedacted,
	}
	if flow.egressUnconfirmed {
		// Transport failure (#357 review): no flow item — a signed data-flow
		// entry must never assert delivery the wire may not have made.
		return
	}
	ev.DataFlow = h.buildProxyDataFlow(inv.tenantID, inv.correlationID, toolName, flow)
	if ev.DataFlow != nil {
		log.Info().
			Str("correlation_id", inv.correlationID).
			Str("tenant_id", inv.tenantID).
			Str("agent_id", inv.agentID).
			Str("flow_destination", evidence.FlowDestMCPTool+":"+h.config.Proxy.Upstream.Vendor).
			Str("flow_region", h.upstreamRegion()).
			Int("flow_items", len(ev.DataFlow.Items)).
			Msg("data_flow_recorded")
	}
}

func (h *ProxyHandler) recordEvidence(ctx context.Context, inv *proxyInvocation, eventType, toolName, reason string, flow *proxyFlowState) {
	if h.evidenceStore == nil {
		return
	}
	allowed := proxyRecordAllowed(eventType, reason, flow)
	action := "allow"
	if !allowed {
		action = "deny"
	}
	var reasons []string
	if reason != "" {
		reasons = []string{reason}
	}
	ev := &evidence.Evidence{
		ID:              "proxy_" + uuid.New().String()[:8],
		CorrelationID:   inv.correlationID,
		SessionID:       inv.sessionID,
		Timestamp:       time.Now(),
		TenantID:        inv.tenantID,
		AgentID:         inv.agentID,
		Team:            inv.team,
		InvocationType:  eventType,
		RequestSourceID: h.config.Proxy.Upstream.Vendor,
		PolicyDecision:  evidence.PolicyDecision{Allowed: allowed, Action: action, Reasons: reasons},
		Execution: evidence.Execution{
			ToolsCalled: []string{toolName},
		},
		Orchestration: inv.orch,
	}
	// Execution.Error only on records that actually denied/failed: session
	// summaries count any non-empty Execution.Error as a session error, and
	// allowed records (output_pii_redacted notes) join sessions via
	// SessionID — their reason already lives in PolicyDecision.Reasons.
	if !allowed {
		ev.Execution.Error = reason
	}
	// Upstream failures (#357) are policy-ALLOWED records whose execution
	// failed: the error must count in session summaries, and the failure is
	// typed in Status/FailureReason rather than faking a policy deny.
	if eventType == "proxy_upstream_error" {
		ev.Execution.Error = reason
		ev.Status = "failed"
		ev.FailureReason = "upstream_error"
	}
	// Upstream auth evidence (#358): mode-only, exact gateway parity in
	// secret mode (fingerprint/source stay client_bearer-only vocabulary).
	if h.config.Proxy.Upstream.Auth != nil {
		ev.UpstreamAuthMode = "secret"
	}
	if flow != nil {
		h.attachProxyFlow(ev, inv, toolName, flow)
	}
	// Every record identifies the scan engine behind its classification;
	// scanner-driven denials also carry the typed failure kind.
	if scannerInfo := evidence.NewScannerInfo(h.classifier); scannerInfo != nil {
		switch {
		case flow != nil && flow.scannerFailure != "":
			scannerInfo.Failure = flow.scannerFailure
		case strings.Contains(reason, "scanner_unavailable"):
			scannerInfo.Failure = "scanner_unavailable"
		}
		ev.Classification.Scanner = scannerInfo
	}
	ev.Explanations = explanation.BuildFromFacts(proxyExplanationFacts(eventType, reason, toolName))
	_ = h.evidenceStore.Store(ctx, ev)
}

// buildProxyDataFlow links tool arguments to the upstream vendor and
// classified tool results to the client. Every proxied call records at least
// the tool_args -> vendor flow, classified or not: data movement is evidence.
// Digests only, never raw values.
func (h *ProxyHandler) buildProxyDataFlow(tenantID, correlationID, toolName string, flow *proxyFlowState) *evidence.DataFlow {
	var items []evidence.DataFlowItem
	disposition := evidence.FlowDispositionForwarded
	switch {
	case flow.requestBlocked:
		disposition = evidence.FlowDispositionBlocked
	case flow.requestRedacted:
		disposition = evidence.FlowDispositionRedacted
	}
	items = append(items, evidence.NewDataFlowItem(
		tenantID, correlationID,
		evidence.FlowSourceToolArgs, toolName,
		flow.requestTier, flow.requestEntities,
		disposition, evidence.FlowDestination{
			Kind:     evidence.FlowDestMCPTool,
			Name:     h.config.Proxy.Upstream.Vendor,
			Endpoint: h.upstreamEndpointHost(),
			Region:   h.upstreamRegion(),
		}))
	if len(flow.responseEntities) > 0 {
		disposition := evidence.FlowDispositionSurfaced
		switch {
		case flow.responseBlocked:
			disposition = evidence.FlowDispositionBlocked
		case flow.responseRedacted:
			disposition = evidence.FlowDispositionRedacted
		}
		items = append(items, evidence.NewDataFlowItem(
			tenantID, correlationID,
			evidence.FlowSourceToolResult, toolName,
			flow.responseTier, flow.responseEntities,
			disposition, evidence.FlowDestination{
				Kind: evidence.FlowDestClient,
				Name: tenantID,
			}))
	}
	detector := ""
	if h.classifier != nil {
		detector = h.classifier.Detector()
	}
	return &evidence.DataFlow{Detector: detector, Items: items}
}

// entityTypeSet returns the deduped, sorted entity types of merged spans.
func entityTypeSet(entities []classifier.PIIEntity) []string {
	if len(entities) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(entities))
	for _, e := range entities {
		set[e.Type] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func proxyExplanationFacts(eventType, reason, toolName string) []explanation.Fact {
	trigger := strings.TrimSpace(reason)
	if trigger == "" {
		trigger = strings.TrimSpace(toolName)
	}
	switch eventType {
	case "proxy_tool_blocked", "proxy_method_rejected":
		return []explanation.Fact{{
			Code:     explanation.CodePolicyDeniedTool,
			Decision: explanation.DecisionDeny,
			Stage:    explanation.StageToolExecution,
			Trigger:  trigger,
		}}
	case "proxy_pii_eval_error":
		return []explanation.Fact{{
			Code:     explanation.CodeExecutionFailed,
			Decision: explanation.DecisionFailure,
			Stage:    explanation.StagePolicyEvaluation,
			Trigger:  trigger,
		}}
	case "proxy_upstream_error":
		return []explanation.Fact{{
			Code:     explanation.CodeExecutionFailed,
			Decision: explanation.DecisionFailure,
			Stage:    explanation.StageToolExecution,
			Trigger:  trigger,
		}}
	case "proxy_pii_request_detected":
		// Always a deny: every writer of this event blocks the request.
		return []explanation.Fact{{
			Code:     explanation.CodePolicyDeniedPIIInput,
			Decision: explanation.DecisionDeny,
			Stage:    explanation.StagePolicyEvaluation,
			Trigger:  trigger,
		}}
	default:
		if reason == "output_pii_redacted" {
			return []explanation.Fact{{
				Code:     explanation.CodePolicyFiltered,
				Decision: explanation.DecisionFilter,
				Stage:    explanation.StageOutputValidation,
				Trigger:  reason,
			}}
		}
		return []explanation.Fact{{
			Code:     explanation.CodePolicyAllowed,
			Decision: explanation.DecisionAllow,
			Stage:    explanation.StageToolExecution,
			Trigger:  trigger,
		}}
	}
}

func paramsToMap(raw json.RawMessage) map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	return m
}

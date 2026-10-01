// Package mcp implements the MCP proxy for vendor integration. Governed calls
// are always intercepted and enforced (#442): forbidden tools, policy denials
// and PII denials never reach the upstream.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
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

// headerDecl returns the trusted Mcp-Param declaration for a Talon-facing
// tool name (validated at config load).
func (h *ProxyHandler) headerDecl(toolName string) *wire.HeaderParams {
	for _, m := range h.config.Proxy.AllowedTools {
		if m.Name == toolName {
			decl, err := wire.HeaderParamsFromConfig(m.HeaderParams)
			if err != nil {
				return &wire.HeaderParams{}
			}
			return decl
		}
	}
	return &wire.HeaderParams{}
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
func (h *ProxyHandler) SetRuntime(r ProxyRuntimeConfig) {
	h.runtime = r
	if h.runtime.UpstreamTimeout > 0 {
		h.httpClient = &http.Client{Timeout: h.runtime.UpstreamTimeout}
	}
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
	// Mcp-Param-* integrity against the operator-trusted declaration, before
	// forbidden/policy/PII: a mismatch is a protocol rejection with zero
	// governance evidence and zero upstream dispatch.
	if perr := wire.ValidateHeaderParams(h.headerDecl(toolName), params.Arguments, req.HeaderParams); perr != nil {
		span.SetAttributes(attribute.String("mcp.protocol_reason", perr.Reason))
		wire.WriteError(w, req.ID, perr)
		return nil
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
	var flow proxyFlowState
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

	// Forward: a FRESH request built from the authorized, normalized
	// payload — canonical upstream name, redacted arguments, the client's
	// MRTR continuation (requestState/inputResponses) and permitted _meta,
	// this protocol version, Talon's identity, and Mcp-* headers generated
	// from that body (never copied from inbound headers).
	outMeta := wire.OutboundMeta(req.Meta, proxyServer())
	outParams := wire.EncodeCallParams(outMeta, wire.CallParams{Name: upstreamName, Arguments: params.Arguments, RequestState: req.RequestState, InputResponses: req.InputResponses})
	paramHeaders, err := wire.OutboundHeaderParams(h.headerDecl(toolName), params.Arguments)
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
	upstream, err := wire.ReadUpstreamResponse(upstreamResp)
	if err != nil {
		// A response arrived, so egress happened — the flow item is truthful.
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "upstream_response_invalid", &flow)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "upstream response invalid", Data: talonErrData(TalonCodeUpstreamError)}}
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
	// Lossless result: complete and input_required (MRTR) results pass
	// through with resultType made explicit and this server's identity.
	normalized, err := wire.NormalizeUpstreamResult(upstream.Result, proxyServer())
	if err != nil {
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "upstream_response_invalid", &flow)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "upstream response invalid", Data: talonErrData(TalonCodeUpstreamError)}}
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

// toolsListExtract holds the result of parsing an upstream tools/list result
// so we can support MCP-canonical shape and common variants (array-at-top, other keys).
type toolsListExtract struct {
	Tools      []json.RawMessage      // tool items (with "name" or "id")
	Shape      string                 // "object", "array", or "unknown"
	ToolsKey   string                 // key that held the array in result object (e.g. "tools")
	ObjectRest map[string]interface{} // other keys to preserve when Shape == "object"
}

// extractToolsListFromResult parses resp.Result into a list of tool entries and
// the original shape so we can rebuild the response correctly. Supports:
//   - MCP-canonical: result = { "tools": [...], "nextCursor": "..." }
//   - Array-at-top: result = [...]
//   - Other keys: result = { "items": [...] } or { "list": [...] } (common variants)
//
// Returns Shape "unknown" and empty Tools when the result is not recognizable,
// so the caller can return a safe empty list instead of leaking unfiltered data.
func extractToolsListFromResult(result interface{}) toolsListExtract {
	if result == nil {
		return toolsListExtract{Shape: "unknown"}
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return toolsListExtract{Shape: "unknown"}
	}

	// Try object with "tools" (MCP canonical) or common alternate keys.
	var obj map[string]interface{}
	if err := json.Unmarshal(resultBytes, &obj); err == nil && len(obj) > 0 {
		for _, key := range []string{"tools", "items", "list"} {
			raw, ok := obj[key]
			if !ok {
				continue
			}
			arr, ok := raw.([]interface{})
			if !ok {
				continue
			}
			tools := make([]json.RawMessage, 0, len(arr))
			for _, item := range arr {
				b, _ := json.Marshal(item)
				tools = append(tools, b)
			}
			rest := make(map[string]interface{}, len(obj)-1)
			for k, v := range obj {
				if k != key {
					rest[k] = v
				}
			}
			return toolsListExtract{Tools: tools, Shape: "object", ToolsKey: key, ObjectRest: rest}
		}
	}

	// Try result as array directly.
	var arr []interface{}
	if err := json.Unmarshal(resultBytes, &arr); err == nil {
		tools := make([]json.RawMessage, 0, len(arr))
		for _, item := range arr {
			b, _ := json.Marshal(item)
			tools = append(tools, b)
		}
		return toolsListExtract{Tools: tools, Shape: "array"}
	}

	return toolsListExtract{Shape: "unknown"}
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

// handleToolsList rebuilds a tools/list request for the upstream (Talon's
// own _meta, the client's cursor), filters the response to the policy's
// allowed_tools and excludes definitions whose x-mcp-header annotations are
// invalid. The result carries current cache hints: the upstream ttlMs when
// it sent one (else 0), always cacheScope private because the list is
// filtered for this governed route.
func (h *ProxyHandler) handleToolsList(ctx context.Context, req *wire.Request, inv *proxyInvocation) *jsonrpcResponse {
	ctx, span := proxyTracer.Start(ctx, "mcp.proxy.tools.list")
	defer span.End()

	outParams := wire.EncodeListParams(wire.OutboundMeta(req.Meta, proxyServer()), req.Cursor)
	httpReq, err := wire.NewUpstreamRequest(ctx, h.config.Proxy.Upstream.URL, req.ID, wire.MethodToolsList, outParams, "", nil)
	if err != nil {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error(), Data: talonErrData(TalonCodeUpstreamError)}}
	}
	upstreamResp, err := h.doUpstream(ctx, httpReq, inv) //nolint:bodyclose // closed by wire.ReadUpstreamResponse
	if err != nil {
		if errors.Is(err, errSecretRetrieval) {
			// Fail-closed vault failure (#358): generic message, no detail leak.
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "Service configuration error", Data: talonErrData(TalonCodeUpstreamError)}}
		}
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error(), Data: talonErrData(TalonCodeUpstreamError)}}
	}
	upstream, err := wire.ReadUpstreamResponse(upstreamResp)
	if err != nil {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "upstream response invalid", Data: talonErrData(TalonCodeUpstreamError)}}
	}
	if upstream.Error != nil {
		out := &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: upstream.Error.Code, Message: upstream.Error.Message}}
		if len(upstream.Error.Data) > 0 {
			out.Error.Data = upstream.Error.Data
		}
		return out
	}

	var raw interface{}
	_ = json.Unmarshal(upstream.Result, &raw)
	extract := extractToolsListFromResult(raw)
	filtered := h.filterUpstreamTools(extract.Tools)
	span.SetAttributes(
		attribute.Int("proxy.tools_upstream", len(extract.Tools)),
		attribute.Int("proxy.tools_filtered", len(filtered)),
		attribute.String("proxy.tools_result_shape", extract.Shape),
	)
	fields, ttl := listFields(extract)
	fields["tools"] = filtered
	result := wire.Cacheable(wire.Complete(proxyServer(), fields), ttl, wire.CacheScopePrivate)
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: result}
}

// filterUpstreamTools keeps allowed_tools entries whose x-mcp-header
// annotations are valid, in deterministic name order.
func (h *ProxyHandler) filterUpstreamTools(tools []json.RawMessage) []interface{} {
	allowedSet := make(map[string]bool, len(h.config.Proxy.AllowedTools))
	for _, t := range h.config.Proxy.AllowedTools {
		allowedSet[t.Name] = true
		if t.UpstreamName != "" {
			allowedSet[t.UpstreamName] = true
		}
	}
	filtered := make([]interface{}, 0, len(tools))
	for _, toolRaw := range tools {
		name := toolNameFromRaw(toolRaw)
		if name == "" || !allowedSet[name] {
			continue
		}
		if err := validToolHeaderAnnotations(toolRaw); err != nil {
			log.Warn().Str("tool", name).Err(err).Msg("mcp_proxy_tool_excluded_invalid_header_annotation")
			continue
		}
		var v interface{}
		_ = json.Unmarshal(toolRaw, &v)
		filtered = append(filtered, v)
	}
	sort.SliceStable(filtered, func(i, j int) bool { return toolNameOf(filtered[i]) < toolNameOf(filtered[j]) })
	return filtered
}

// listFields carries the upstream's non-tool result members (e.g.
// nextCursor) forward and reads its ttlMs hint; resultType, _meta and the
// cache fields are always set by Talon.
func listFields(extract toolsListExtract) (fields map[string]interface{}, ttlMs int) {
	fields = map[string]interface{}{}
	if extract.Shape != "object" {
		return fields, 0
	}
	for k, v := range extract.ObjectRest {
		switch k {
		case "resultType", "_meta", "ttlMs", "cacheScope":
			continue
		}
		fields[k] = v
	}
	if v, ok := extract.ObjectRest["ttlMs"].(float64); ok && v > 0 {
		ttlMs = int(v)
	}
	return fields, ttlMs
}

// validToolHeaderAnnotations applies the client-side x-mcp-header rejection
// rule to an upstream tool definition.
func validToolHeaderAnnotations(toolRaw json.RawMessage) error {
	var t struct {
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	if err := json.Unmarshal(toolRaw, &t); err != nil || len(t.InputSchema) == 0 {
		return nil
	}
	_, err := wire.HeaderParamsFromSchema(t.InputSchema)
	return err
}

func toolNameOf(v interface{}) string {
	if m, ok := v.(map[string]interface{}); ok {
		if n, ok := m["name"].(string); ok {
			return n
		}
		if id, ok := m["id"].(string); ok {
			return id
		}
	}
	return ""
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

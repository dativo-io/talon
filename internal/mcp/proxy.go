// Package mcp implements the MCP proxy for vendor integration (intercept, passthrough, shadow).
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
)

var proxyTracer = otel.Tracer("github.com/dativo-io/talon/internal/mcp")

// ProxyHandler forwards MCP requests to an upstream vendor endpoint with policy and PII handling.
type ProxyHandler struct {
	config        *policy.ProxyPolicyConfig
	proxyEngine   *policy.ProxyEngine
	evidenceStore *evidence.Store
	classifier    classifier.Facade
	httpClient    *http.Client
	runtime       ProxyRuntimeConfig
}

// NewProxyHandler creates an MCP proxy handler.
func NewProxyHandler(
	cfg *policy.ProxyPolicyConfig,
	proxyEngine *policy.ProxyEngine,
	evidenceStore *evidence.Store,
	cls classifier.Facade,
) *ProxyHandler {
	// Defense in depth for #346: the loaders default/validate mode, but a
	// handler constructed directly (tests, future callers) must never run
	// with an empty OR unknown mode — empty used to fail open as passthrough,
	// and an unrecognized value must get the strictest semantics, not
	// shadow's forward-with-record.
	if cfg != nil {
		switch cfg.Proxy.Mode {
		case policy.ProxyModeIntercept, policy.ProxyModePassthrough, policy.ProxyModeShadow:
		default:
			cfg.Proxy.Mode = policy.ProxyModeIntercept
		}
	}
	timeout := 30 * time.Second
	return &ProxyHandler{
		config:        cfg,
		proxyEngine:   proxyEngine,
		evidenceStore: evidenceStore,
		classifier:    cls,
		httpClient:    &http.Client{Timeout: timeout},
		runtime:       DefaultProxyRuntime(),
	}
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
	if r.Method != http.MethodPost {
		writeRPCError(w, nil, codeInvalidRequest, "method must be POST")
		return
	}
	ctx, span := proxyTracer.Start(r.Context(), "mcp.proxy.serve")
	defer span.End()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeRPCError(w, nil, codeParseError, "reading body: "+err.Error())
		return
	}
	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, nil, codeParseError, "invalid JSON: "+err.Error())
		return
	}
	if req.JSONRPC != jsonrpcVersion {
		writeRPCError(w, req.ID, codeInvalidRequest, "jsonrpc must be 2.0")
		return
	}

	// Attribution is resolved once per request (#350). Header hygiene
	// violations are rejected before any evidence is written, mirroring the
	// gateway contract (reject, never truncate).
	inv, err := h.resolveProxyInvocation(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(&jsonrpcResponse{
			JSONRPC: jsonrpcVersion, ID: req.ID,
			Error: &rpcError{Code: codeInvalidRequest, Message: "invalid attribution header: " + err.Error()},
		})
		return
	}
	// Echo the resolved identifiers so callers can join their receipts to
	// the audit trail.
	w.Header().Set("X-Correlation-ID", inv.correlationID)
	if inv.sessionID != "" {
		w.Header().Set("X-Talon-Session-ID", inv.sessionID)
	}

	// MCP lifecycle (#367): initialize is answered LOCALLY — tools capability
	// only, never forwarded upstream (nothing ungoverned moves) — and
	// notifications/initialized is accepted with 202/no body, so
	// spec-conformant clients (Copilot CLI, Claude Code, MCP Inspector,
	// SDKs) can complete the mandatory handshake against the proxy.
	if req.Method == "notifications/initialized" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	var resp *jsonrpcResponse
	switch req.Method {
	case "initialize":
		resp = &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: mcpInitializeResult("talon-mcp-proxy", req.Params)}
	case "tools/list":
		resp = h.handleToolsList(ctx, body, inv, &req)
	case "tools/call":
		resp = h.handleProxyToolCall(ctx, &req, inv)
	default:
		// Fail-closed method allowlist (#356): the proxy governs the MCP
		// lifecycle plus tools/list and tools/call; every other method is
		// rejected with evidence, mirroring the native /mcp server's -32601.
		// Forwarding ungoverned methods (resources/read, prompts/get) would
		// open an unscanned, unaudited data lane through the governance proxy.
		h.recordEvidence(ctx, inv, "proxy_method_rejected", req.Method, "unsupported_method:"+req.Method, nil, nil)
		resp = &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{
			Code:    codeMethodNotFound,
			Message: "method not found: " + req.Method + " (the proxy governs initialize, tools/list, and tools/call only)",
			Data:    talonErrData(TalonCodeMethodNotAllowed),
		}}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

//nolint:gocyclo // proxy flow: forbidden, policy, PII, forward, evidence
func (h *ProxyHandler) handleProxyToolCall(ctx context.Context, req *jsonrpcRequest, inv *proxyInvocation) *jsonrpcResponse {
	ctx, span := proxyTracer.Start(ctx, "mcp.proxy.tools.call")
	defer span.End()

	var params toolsCallParams
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &params)
	}
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

	// Forbidden check (#346, fail-closed): explicitly forbidden tools are
	// forwarded ONLY under explicit passthrough mode — intercept, shadow, and
	// any unexpected mode value block. Evidence must say what actually
	// happened: a block records proxy_tool_blocked; a passthrough forward
	// records a shadow violation on an allowed record, never a fake "blocked".
	for _, f := range h.config.Proxy.ForbiddenTools {
		if f == toolName || (strings.HasSuffix(f, "*") && strings.HasPrefix(toolName, strings.TrimSuffix(f, "*"))) {
			span.SetAttributes(attribute.String("proxy.blocked", "forbidden"))
			if h.config.Proxy.Mode != policy.ProxyModePassthrough {
				h.recordEvidence(ctx, inv, "proxy_tool_blocked", toolName, "forbidden_tools", nil, nil)
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "tool not allowed by policy", Data: talonErrData(TalonCodeToolForbidden)}}
			}
			h.recordEvidence(ctx, inv, "proxy_shadow_violation", toolName, "forbidden_tools", nil, &evidence.ShadowViolation{
				Type:   "tool_block",
				Detail: "forbidden tool " + toolName + " forwarded in passthrough mode",
				Action: "block",
			})
			break
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
		if h.config.Proxy.Mode == policy.ProxyModeIntercept {
			h.recordEvidence(ctx, inv, "proxy_tool_blocked", toolName, denyReason, nil, nil)
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: denyReason, Data: talonErrData(TalonCodePolicyDenied)}}
		}
		// shadow/passthrough (#346): the deny is recorded as a would-have-
		// denied shadow violation — previously these modes produced no
		// evidence of the deny at all.
		h.recordEvidence(ctx, inv, "proxy_shadow_violation", toolName, denyReason, nil, &evidence.ShadowViolation{
			Type:   "policy_deny",
			Detail: denyReason,
			Action: "block",
		})
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
			h.recordEvidence(ctx, inv, "proxy_pii_scan_error", toolName, "scanner_unavailable", &flow, nil)
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
				if h.config.Proxy.Mode == policy.ProxyModeIntercept {
					flow.requestBlocked = true
					h.recordEvidence(ctx, inv, "proxy_pii_eval_error", toolName, piiErr.Error(), &flow, nil)
					return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "PII policy evaluation failed (fail-closed)", Data: talonErrData(TalonCodePIIBlocked)}}
				}
				// shadow/passthrough (#346): enforce mode would block
				// fail-closed on an eval error — record it, then continue.
				h.recordEvidence(ctx, inv, "proxy_shadow_violation", toolName, "pii_eval_error: "+piiErr.Error(), &flow, &evidence.ShadowViolation{
					Type:   "pii_block",
					Detail: "PII policy evaluation failed: " + piiErr.Error(),
					Action: "block",
				})
			}
			if piiDecision != nil && !piiDecision.Allowed {
				if h.config.Proxy.Mode == policy.ProxyModeIntercept {
					flow.requestBlocked = true
					h.recordEvidence(ctx, inv, "proxy_pii_request_detected", toolName, "pii_detected_in_request", &flow, nil)
					return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "PII detected in request", Data: talonErrData(TalonCodePIIBlocked)}}
				}
				// shadow/passthrough (#346): record the would-have-denied PII
				// decision, then continue to redaction as before.
				h.recordEvidence(ctx, inv, "proxy_shadow_violation", toolName, "pii_detected_in_request", &flow, &evidence.ShadowViolation{
					Type:   "pii_block",
					Detail: "PII detected in request: " + strings.Join(proxyInput.DetectedPII, ", "),
					Action: "block",
				})
			}
			redactedArgs, redactErr := h.classifier.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
			if redactErr != nil {
				flow.requestBlocked = true
				flow.scannerFailure = scannerFailureKind(redactErr)
				h.recordEvidence(ctx, inv, "proxy_pii_scan_error", toolName, "scanner_unavailable", &flow, nil)
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
				h.recordEvidence(ctx, inv, "proxy_pii_request_detected", toolName, reason, &flow, nil)
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
					h.recordEvidence(ctx, inv, "proxy_pii_request_detected", toolName, "request_redaction_invalid_json", &flow, nil)
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

	// Forward to upstream (with optional name mapping)
	forwardParams := params
	forwardParams.Name = upstreamName
	forwardBody, _ := json.Marshal(forwardParams)
	forwardReq := jsonrpcRequest{JSONRPC: jsonrpcVersion, Method: req.Method, Params: forwardBody, ID: req.ID}
	forwardJSON, _ := json.Marshal(forwardReq)

	upstreamResp, err := h.doUpstreamRequest(ctx, forwardJSON)
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
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "upstream_error: "+err.Error(), &flow, nil)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error(), Data: talonErrData(TalonCodeUpstreamError)}}
	}
	defer upstreamResp.Body.Close()
	var out jsonrpcResponse
	if err := json.NewDecoder(upstreamResp.Body).Decode(&out); err != nil {
		// A response arrived, so egress happened — the flow item is truthful.
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName, "upstream_response_invalid", &flow, nil)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "upstream response invalid", Data: talonErrData(TalonCodeUpstreamError)}}
	}
	out.ID = req.ID
	if out.Error != nil {
		// The vendor answered with a JSON-RPC error: the call executed and
		// failed — record it as such, never as a clean allowed completion.
		h.recordEvidence(ctx, inv, "proxy_upstream_error", toolName,
			fmt.Sprintf("upstream_jsonrpc_error: %d %s", out.Error.Code, out.Error.Message), &flow, nil)
		return &out
	}

	// Response PII scanning: scan tool result before returning to caller.
	// A scanner failure blocks the result fail-closed.
	if h.classifier != nil && out.Result != nil {
		resultBytes, _ := json.Marshal(out.Result)
		resultStr := string(resultBytes)
		cls, scanErr := h.classifier.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), resultStr)
		if scanErr != nil {
			flow.responseBlocked = true
			flow.scannerFailure = scannerFailureKind(scanErr)
			h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "output_scanner_unavailable", &flow, nil)
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
				h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "output_scanner_unavailable", &flow, nil)
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
				h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, reason, &flow, nil)
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
				h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "output_redaction_invalid_json", &flow, nil)
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "PII redaction of tool result produced invalid JSON (fail-closed)", Data: talonErrData(TalonCodePIIBlocked)}}
			}
			out.Result = redactedResult
			h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "output_pii_redacted", &flow, nil)
		} else {
			h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "", &flow, nil)
		}
	} else {
		h.recordEvidence(ctx, inv, "proxy_tool_call", toolName, "", &flow, nil)
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

// handleToolsList forwards a tools/list request and filters the response to
// only include tools in the policy's allowed_tools list. This prevents agents
// from discovering (and attempting to call) tools they are not authorized to use.
// It supports multiple upstream result shapes (object with "tools", array at top,
// or other common keys) and preserves the response shape. If the result shape
// is unrecognizable, it returns an empty tool list to avoid leaking unfiltered data.
func (h *ProxyHandler) handleToolsList(ctx context.Context, body []byte, _ *proxyInvocation, req *jsonrpcRequest) *jsonrpcResponse {
	ctx, span := proxyTracer.Start(ctx, "mcp.proxy.tools.list")
	defer span.End()

	resp := h.forwardRequest(ctx, body, req)
	if resp == nil || resp.Error != nil || resp.Result == nil {
		return resp
	}

	allowedSet := make(map[string]bool, len(h.config.Proxy.AllowedTools))
	for _, t := range h.config.Proxy.AllowedTools {
		allowedSet[t.Name] = true
		if t.UpstreamName != "" {
			allowedSet[t.UpstreamName] = true
		}
	}

	extract := extractToolsListFromResult(resp.Result)

	filtered := make([]json.RawMessage, 0, len(extract.Tools))
	for _, toolRaw := range extract.Tools {
		name := toolNameFromRaw(toolRaw)
		if name != "" && allowedSet[name] {
			filtered = append(filtered, toolRaw)
		}
	}

	span.SetAttributes(
		attribute.Int("proxy.tools_upstream", len(extract.Tools)),
		attribute.Int("proxy.tools_filtered", len(filtered)),
		attribute.String("proxy.tools_result_shape", extract.Shape),
	)

	var resultIface interface{}
	switch extract.Shape {
	case "object":
		out := make(map[string]interface{}, 1)
		for k, v := range extract.ObjectRest {
			out[k] = v
		}
		filteredSlice := make([]interface{}, 0, len(filtered))
		for _, b := range filtered {
			var v interface{}
			_ = json.Unmarshal(b, &v)
			filteredSlice = append(filteredSlice, v)
		}
		out[extract.ToolsKey] = filteredSlice
		resultIface = out
	case "array":
		filteredSlice := make([]interface{}, 0, len(filtered))
		for _, b := range filtered {
			var v interface{}
			_ = json.Unmarshal(b, &v)
			filteredSlice = append(filteredSlice, v)
		}
		resultIface = filteredSlice
	default:
		// Unrecognized shape: return canonical empty result so we never leak unfiltered tools.
		resultIface = map[string]interface{}{"tools": []interface{}{}}
	}

	resp.Result = resultIface
	return resp
}

func (h *ProxyHandler) forwardRequest(ctx context.Context, body []byte, req *jsonrpcRequest) *jsonrpcResponse {
	upstreamResp, err := h.doUpstreamRequest(ctx, body)
	if err != nil {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error()}}
	}
	defer upstreamResp.Body.Close()
	var out jsonrpcResponse
	if err := json.NewDecoder(upstreamResp.Body).Decode(&out); err != nil {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "upstream response invalid"}}
	}
	out.ID = req.ID
	return &out
}

func (h *ProxyHandler) doUpstreamRequest(ctx context.Context, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.config.Proxy.Upstream.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.runtime.AuthHeader != "" {
		parts := strings.SplitN(h.runtime.AuthHeader, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
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
// for those. A shadow violation is an ALLOWED record — the call was forwarded
// — with the would-have-denied verdict carried in ShadowViolations +
// ObservationModeOverride (#346), matching the gateway's shadow vocabulary.
// An upstream error is likewise ALLOWED (policy permitted the call; the
// vendor failed): counting it as a deny would inflate the attention queue's
// denial rate on vendor outages — the failure lives in Status/FailureReason.
func proxyRecordAllowed(eventType, reason string, flow *proxyFlowState) bool {
	if flow != nil && (flow.requestBlocked || flow.responseBlocked) {
		return false
	}
	return eventType == "proxy_tool_call" ||
		eventType == "proxy_shadow_violation" ||
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

func (h *ProxyHandler) recordEvidence(ctx context.Context, inv *proxyInvocation, eventType, toolName, reason string, flow *proxyFlowState, sv *evidence.ShadowViolation) {
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
	// allowed records (shadow violations, output_pii_redacted notes) now
	// join sessions via SessionID — their reason already lives in
	// PolicyDecision.Reasons.
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
	if sv != nil {
		ev.ObservationModeOverride = true
		ev.ShadowViolations = []evidence.ShadowViolation{*sv}
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
	ev.Explanations = explanation.BuildFromFacts(proxyExplanationFacts(eventType, reason, toolName, allowed))
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

func proxyExplanationFacts(eventType, reason, toolName string, allowed bool) []explanation.Fact {
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
	case "proxy_shadow_violation":
		// The call was forwarded (allowed); the would-have-denied verdict
		// lives in ShadowViolations. Gateway precedent: shadow evidence
		// explains as allowed, with the trigger naming what enforce would
		// have denied.
		return []explanation.Fact{{
			Code:     explanation.CodePolicyAllowed,
			Decision: explanation.DecisionAllow,
			Stage:    explanation.StageToolExecution,
			Trigger:  trigger,
			Fix:      "Observation mode forwarded a call enforce mode would deny; set proxy.mode: intercept to enforce.",
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
		if !allowed {
			return []explanation.Fact{{
				Code:     explanation.CodePolicyDeniedPIIInput,
				Decision: explanation.DecisionDeny,
				Stage:    explanation.StagePolicyEvaluation,
				Trigger:  trigger,
			}}
		}
		return []explanation.Fact{{
			Code:     explanation.CodePolicyAllowed,
			Decision: explanation.DecisionAllow,
			Stage:    explanation.StagePolicyEvaluation,
			Trigger:  "pii_detected_in_request",
			Fix:      "Review request arguments for sensitive values; forwarding was allowed in current policy mode.",
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

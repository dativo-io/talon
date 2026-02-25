// Package mcp implements the MCP proxy for vendor integration (intercept, passthrough, shadow).
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
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
	classifier    *classifier.Scanner
	httpClient    *http.Client
	runtime       ProxyRuntimeConfig
}

// NewProxyHandler creates an MCP proxy handler.
func NewProxyHandler(
	cfg *policy.ProxyPolicyConfig,
	proxyEngine *policy.ProxyEngine,
	evidenceStore *evidence.Store,
	cls *classifier.Scanner,
) *ProxyHandler {
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

	tenantID := requestctx.TenantID(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	var resp *jsonrpcResponse
	switch req.Method {
	case "tools/list":
		resp = h.handleToolsList(ctx, body, tenantID, &req)
	case "tools/call":
		resp = h.handleProxyToolCall(ctx, &req, tenantID)
	default:
		resp = h.forwardRequest(ctx, body, tenantID, &req)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

//nolint:gocyclo // proxy flow: forbidden, policy, PII, forward, evidence
func (h *ProxyHandler) handleProxyToolCall(ctx context.Context, req *jsonrpcRequest, tenantID string) *jsonrpcResponse {
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

	// Forbidden check: explicitly forbidden tools are never forwarded in intercept or shadow.
	// intercept = block; shadow = audit then block; passthrough = log only then forward.
	for _, f := range h.config.Proxy.ForbiddenTools {
		if f == toolName || (strings.HasSuffix(f, "*") && strings.HasPrefix(toolName, strings.TrimSuffix(f, "*"))) {
			h.recordEvidence(ctx, tenantID, "proxy_tool_blocked", toolName, nil, "forbidden_tools")
			span.SetAttributes(attribute.String("proxy.blocked", "forbidden"))
			switch h.config.Proxy.Mode {
			case "intercept", "shadow":
				// Block: intercept always; shadow audits then blocks (never forward forbidden tools).
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "tool not allowed by policy"}}
			}
			// passthrough: evidence recorded, fall through to forward
			break
		}
	}

	// Policy: tool access
	proxyInput := &policy.ProxyInput{
		ToolName:       toolName,
		Vendor:         h.config.Proxy.Upstream.Vendor,
		UpstreamRegion: "eu",
		Arguments:      paramsToMap(params.Arguments),
	}
	decision, err := h.proxyEngine.EvaluateProxyToolAccess(ctx, proxyInput)
	if err != nil {
		span.RecordError(err)
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error()}}
	}
	if !decision.Allowed && h.config.Proxy.Mode == "intercept" {
		h.recordEvidence(ctx, tenantID, "proxy_tool_blocked", toolName, nil, strings.Join(decision.Reasons, "; "))
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: strings.Join(decision.Reasons, "; ")}}
	}

	// PII scan on arguments
	if h.classifier != nil {
		argStr := string(params.Arguments)
		result := h.classifier.Scan(ctx, argStr)
		if result != nil && len(result.Entities) > 0 {
			for _, e := range result.Entities {
				proxyInput.DetectedPII = append(proxyInput.DetectedPII, e.Type)
			}
			piiDecision, _ := h.proxyEngine.EvaluateProxyPII(ctx, proxyInput)
			if piiDecision != nil && !piiDecision.Allowed && h.config.Proxy.Mode == "intercept" {
				h.recordEvidence(ctx, tenantID, "proxy_pii_redaction", toolName, nil, "PII detected")
				return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "PII detected in request"}}
			}
			h.recordEvidence(ctx, tenantID, "proxy_pii_redaction", toolName, nil, "")
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
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error()}}
	}
	defer upstreamResp.Body.Close()
	var out jsonrpcResponse
	if err := json.NewDecoder(upstreamResp.Body).Decode(&out); err != nil {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "upstream response invalid"}}
	}
	out.ID = req.ID

	// Response PII scanning: scan tool result before returning to caller
	if h.classifier != nil && out.Result != nil {
		resultBytes, _ := json.Marshal(out.Result)
		resultStr := string(resultBytes)
		cls := h.classifier.Scan(ctx, resultStr)
		if cls != nil && cls.HasPII {
			piiTypes := make([]string, 0, len(cls.Entities))
			for _, e := range cls.Entities {
				piiTypes = append(piiTypes, e.Type)
			}
			span.SetAttributes(
				attribute.Bool("proxy.output_pii_detected", true),
				attribute.StringSlice("proxy.output_pii_types", piiTypes),
			)
			redacted := h.classifier.Redact(ctx, resultStr)
			var redactedResult interface{}
			if err := json.Unmarshal([]byte(redacted), &redactedResult); err == nil {
				out.Result = redactedResult
			}
			h.recordEvidence(ctx, tenantID, "proxy_tool_call", toolName, nil, "output_pii_redacted")
		} else {
			h.recordEvidence(ctx, tenantID, "proxy_tool_call", toolName, nil, "")
		}
	} else {
		h.recordEvidence(ctx, tenantID, "proxy_tool_call", toolName, nil, "")
	}

	return &out
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
func (h *ProxyHandler) handleToolsList(ctx context.Context, body []byte, tenantID string, req *jsonrpcRequest) *jsonrpcResponse {
	ctx, span := proxyTracer.Start(ctx, "mcp.proxy.tools.list")
	defer span.End()

	resp := h.forwardRequest(ctx, body, tenantID, req)
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

func (h *ProxyHandler) forwardRequest(ctx context.Context, body []byte, tenantID string, req *jsonrpcRequest) *jsonrpcResponse {
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

func (h *ProxyHandler) recordEvidence(ctx context.Context, tenantID, eventType, toolName string, result []byte, reason string) {
	if h.evidenceStore == nil {
		return
	}
	allowed := eventType == "proxy_tool_call" || (eventType == "proxy_pii_redaction" && reason == "")
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
		CorrelationID:   "mcp_proxy_" + uuid.New().String()[:8],
		Timestamp:       time.Now(),
		TenantID:        tenantID,
		AgentID:         "mcp-proxy",
		InvocationType:  eventType,
		RequestSourceID: h.config.Proxy.Upstream.Vendor,
		PolicyDecision:  evidence.PolicyDecision{Allowed: allowed, Action: action, Reasons: reasons},
		Execution: evidence.Execution{
			ToolsCalled: []string{toolName},
			Error:       reason,
		},
	}
	_ = h.evidenceStore.Store(ctx, ev)
}

func paramsToMap(raw json.RawMessage) map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	return m
}

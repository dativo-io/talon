// Package mcp implements the Model Context Protocol: JSON-RPC 2.0 server for tools/list and tools/call.
package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
)

var tracer = otel.Tracer("github.com/dativo-io/talon/internal/mcp")

const jsonrpcVersion = "2.0"

// JSON-RPC 2.0 types
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

type jsonrpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard JSON-RPC 2.0 error codes
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
	codeServerError    = -32000
)

// Handler implements the native MCP server: tools/list and tools/call over JSON-RPC 2.0.
type Handler struct {
	registry      *tools.ToolRegistry
	policyEngine  *policy.Engine
	evidenceStore *evidence.Store
}

// NewHandler creates an MCP handler with the given registry, policy engine, and evidence store.
func NewHandler(registry *tools.ToolRegistry, policyEngine *policy.Engine, evidenceStore *evidence.Store) *Handler {
	return &Handler{
		registry:      registry,
		policyEngine:  policyEngine,
		evidenceStore: evidenceStore,
	}
}

// ServeHTTP handles POST /mcp JSON-RPC 2.0 requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, nil, codeInvalidRequest, "method must be POST")
		return
	}
	ctx, span := tracer.Start(r.Context(), "mcp.serve",
		trace.WithAttributes(
			attribute.String("http.request.method", r.Method),
		))
	defer span.End()

	var req jsonrpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPCError(w, nil, codeParseError, "invalid JSON: "+err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	if req.JSONRPC != jsonrpcVersion {
		writeRPCError(w, req.ID, codeInvalidRequest, "jsonrpc must be 2.0")
		return
	}

	var resp *jsonrpcResponse
	switch req.Method {
	case "tools/list":
		resp = h.handleToolsList(ctx, req.ID)
	case "tools/call":
		resp = h.handleToolsCall(ctx, &req)
	default:
		resp = &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleToolsList(ctx context.Context, id interface{}) *jsonrpcResponse {
	_, span := tracer.Start(ctx, "mcp.tools.list")
	defer span.End()

	list := h.registry.List()
	tools := make([]map[string]interface{}, 0, len(list))
	for _, t := range list {
		tools = append(tools, map[string]interface{}{
			"name":        t.Name(),
			"description": t.Description(),
			"inputSchema": t.InputSchema(),
		})
	}
	span.SetAttributes(attribute.Int("tools.count", len(tools)))
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: id, Result: map[string]interface{}{"tools": tools}}
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (h *Handler) handleToolsCall(ctx context.Context, req *jsonrpcRequest) *jsonrpcResponse {
	ctx, span := tracer.Start(ctx, "mcp.tools.call")
	defer span.End()

	var params toolsCallParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()}}
		}
	}
	if params.Name == "" {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "tool name is required"}}
	}

	span.SetAttributes(attribute.String("tool.name", params.Name))

	tenantID := requestctx.TenantID(ctx)
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := "mcp-client"

	// Policy check
	var paramsMap map[string]interface{}
	if len(params.Arguments) > 0 {
		_ = json.Unmarshal(params.Arguments, &paramsMap)
	}
	if paramsMap == nil {
		paramsMap = make(map[string]interface{})
	}
	decision, err := h.policyEngine.EvaluateToolAccess(ctx, params.Name, paramsMap, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: err.Error()}}
	}
	if !decision.Allowed {
		msg := "policy denied"
		if len(decision.Reasons) > 0 {
			msg = decision.Reasons[0]
		}
		span.SetAttributes(attribute.String("policy.deny", msg))
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: msg}}
	}

	tool, ok := h.registry.Get(params.Name)
	if !ok {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "tool not found: " + params.Name}}
	}

	start := time.Now()
	result, execErr := tool.Execute(ctx, params.Arguments)
	duration := time.Since(start).Milliseconds()

	// Record evidence
	correlationID := "mcp_" + uuid.New().String()[:8]
	ev := &evidence.Evidence{
		ID:              "req_" + uuid.New().String()[:8],
		CorrelationID:   correlationID,
		Timestamp:       time.Now(),
		TenantID:        tenantID,
		AgentID:         agentID,
		InvocationType:  "mcp",
		RequestSourceID: "mcp",
		PolicyDecision: evidence.PolicyDecision{
			Allowed:       true,
			Action:        "allow",
			PolicyVersion: decision.PolicyVersion,
		},
		Execution: evidence.Execution{
			ToolsCalled: []string{params.Name},
			DurationMS:  duration,
		},
	}
	if execErr != nil {
		ev.Execution.Error = execErr.Error()
	}
	if storeErr := h.evidenceStore.Store(ctx, ev); storeErr != nil {
		span.RecordError(storeErr)
	}

	if execErr != nil {
		span.RecordError(execErr)
		span.SetStatus(codes.Error, execErr.Error())
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: execErr.Error()}}
	}

	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: map[string]interface{}{"content": result}}
}

func writeRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(&jsonrpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	})
}

// Package mcp implements the Model Context Protocol: JSON-RPC 2.0 server for tools/list and tools/call.
package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
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
	classifier    *classifier.Scanner
}

// NewHandler creates an MCP handler with the given registry, policy engine,
// evidence store, and PII classifier (used for tool argument/result
// classification and data-flow evidence).
func NewHandler(registry *tools.ToolRegistry, policyEngine *policy.Engine, evidenceStore *evidence.Store, cls *classifier.Scanner) *Handler {
	return &Handler{
		registry:      registry,
		policyEngine:  policyEngine,
		evidenceStore: evidenceStore,
		classifier:    cls,
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

//nolint:gocyclo // MCP tools/call: policy, schema validation, execute, evidence — branching required
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
		if unmarshalErr := json.Unmarshal(params.Arguments, &paramsMap); unmarshalErr != nil {
			span.RecordError(unmarshalErr)
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "malformed tool arguments: " + unmarshalErr.Error()}}
		}
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

	// Classify tool arguments: every governed tool call records what data
	// reached the tool, classified or not (same posture as gateway/proxy).
	var argEntities []classifier.PIIEntity
	argTier := 0
	if h.classifier != nil && len(params.Arguments) > 0 {
		argStr := string(params.Arguments)
		cls := h.classifier.Scan(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
		argTier = cls.Tier
		if cls.HasPII {
			argEntities = classifier.MergeEntitySpans(argStr, cls.Entities)
			redactedArgs := h.classifier.Redact(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
			if verifyErr := h.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), redactedArgs); verifyErr != nil {
				return &jsonrpcResponse{
					JSONRPC: jsonrpcVersion,
					ID:      req.ID,
					Error: &rpcError{
						Code:    codeServerError,
						Message: mcpResidualBlockMessage("Tool arguments blocked: recognized PII remains after redaction", classifier.ResidualTypes(verifyErr)),
					},
				}
			}
			if !json.Valid([]byte(redactedArgs)) {
				return &jsonrpcResponse{
					JSONRPC: jsonrpcVersion,
					ID:      req.ID,
					Error:   &rpcError{Code: codeServerError, Message: "PII redaction produced invalid JSON (fail-closed)"},
				}
			}
			params.Arguments = json.RawMessage(redactedArgs)
		}
	}

	if !decision.Allowed {
		msg := "policy denied"
		if len(decision.Reasons) > 0 {
			msg = decision.Reasons[0]
		}
		span.SetAttributes(attribute.String("policy.deny", msg))
		denyCorrelationID := "mcp_" + uuid.New().String()[:8]
		denyEv := &evidence.Evidence{
			ID:              "req_" + uuid.New().String()[:8],
			CorrelationID:   denyCorrelationID,
			Timestamp:       time.Now(),
			TenantID:        tenantID,
			AgentID:         agentID,
			InvocationType:  "mcp",
			RequestSourceID: "mcp",
			PolicyDecision: evidence.PolicyDecision{
				Allowed:       false,
				Action:        decision.Action,
				Reasons:       decision.Reasons,
				PolicyVersion: decision.PolicyVersion,
			},
			Execution: evidence.Execution{
				ToolsCalled: []string{params.Name},
				Error:       msg,
			},
			Classification: evidence.Classification{
				InputTier:   argTier,
				PIIDetected: entityTypeSet(argEntities),
			},
			DataFlow: h.buildServerDataFlow(tenantID, denyCorrelationID, params.Name,
				argTier, argEntities, evidence.FlowDispositionBlocked, 0, nil),
			Explanations: explanation.BuildFromFacts(explanation.BuildLegacyFacts(
				false,
				decision.Action,
				decision.Reasons,
				explanation.StagePolicyEvaluation,
				explanation.PolicyRef(decision.PolicyVersion),
				decision.PolicyVersion,
			)),
		}
		if storeErr := h.evidenceStore.Store(ctx, denyEv); storeErr != nil {
			span.RecordError(storeErr)
		}
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: msg}}
	}

	tool, ok := h.registry.Get(params.Name)
	if !ok {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeServerError, Message: "tool not found: " + params.Name}}
	}

	if schema := tool.InputSchema(); len(schema) > 0 && string(schema) != "null" {
		if valErr := tools.ValidateAgainstSchema(schema, params.Arguments); valErr != nil {
			return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "schema validation failed: " + valErr.Error()}}
		}
	}

	start := time.Now()
	result, execErr := tool.Execute(ctx, params.Arguments)
	duration := time.Since(start).Milliseconds()

	// Classify the tool result before it is surfaced to the client.
	var resultEntities []classifier.PIIEntity
	resultTier := 0
	if h.classifier != nil && execErr == nil && result != nil {
		if resultJSON, marshalErr := json.Marshal(result); marshalErr == nil {
			resultStr := string(resultJSON)
			cls := h.classifier.Scan(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), resultStr)
			resultTier = cls.Tier
			if cls.HasPII {
				resultEntities = classifier.MergeEntitySpans(resultStr, cls.Entities)
				redacted := h.classifier.Redact(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), resultStr)
				if verifyErr := h.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), redacted); verifyErr != nil {
					return &jsonrpcResponse{
						JSONRPC: jsonrpcVersion,
						ID:      req.ID,
						Error: &rpcError{
							Code:    codeServerError,
							Message: mcpResidualBlockMessage("Tool result blocked: recognized PII remains after redaction", classifier.ResidualTypes(verifyErr)),
						},
					}
				}
				result = json.RawMessage(redacted)
			}
		}
	}

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
		Classification: evidence.Classification{
			InputTier:         argTier,
			OutputTier:        resultTier,
			PIIDetected:       entityTypeSet(argEntities),
			OutputPIIDetected: len(resultEntities) > 0,
			OutputPIITypes:    entityTypeSet(resultEntities),
		},
		DataFlow: h.buildServerDataFlow(tenantID, correlationID, params.Name,
			argTier, argEntities, evidence.FlowDispositionForwarded, resultTier, resultEntities),
	}
	ev.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
		Code:            explanation.CodePolicyAllowed,
		Decision:        explanation.DecisionAllow,
		Stage:           explanation.StageToolExecution,
		Trigger:         params.Name,
		PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
		VersionIdentity: decision.PolicyVersion,
	}})
	if execErr != nil {
		ev.Execution.Error = execErr.Error()
		ev.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
			Code:            explanation.CodeExecutionFailed,
			Decision:        explanation.DecisionFailure,
			Stage:           explanation.StageToolExecution,
			Trigger:         "tool_execution_failed",
			PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
			VersionIdentity: decision.PolicyVersion,
		}})
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

func mcpResidualBlockMessage(prefix string, types []string) string {
	remediation := " Remediation required: use approval workflow to adjust policy or content, re-run redaction, then re-scan."
	if len(types) == 0 {
		return prefix + "." + remediation
	}
	return prefix + " (types: " + strings.Join(types, ", ") + ")." + remediation
}

// buildServerDataFlow links tool arguments to the embedded tool and classified
// tool results back to the MCP client. Every tools/call records at least the
// tool_args -> tool flow, classified or not — same posture as the gateway,
// agent runner, and MCP proxy. Embedded tools execute in-process, so the
// destination region is LOCAL (a fact, not a guess). Digests only, never raw values.
func (h *Handler) buildServerDataFlow(
	tenantID, correlationID, toolName string,
	argTier int, argEntities []classifier.PIIEntity, argDisposition string,
	resultTier int, resultEntities []classifier.PIIEntity,
) *evidence.DataFlow {
	items := []evidence.DataFlowItem{evidence.NewDataFlowItem(
		tenantID, correlationID,
		evidence.FlowSourceToolArgs, toolName,
		argTier, argEntities,
		argDisposition, evidence.FlowDestination{
			Kind:   evidence.FlowDestMCPTool,
			Name:   toolName,
			Region: "LOCAL",
		})}
	if len(resultEntities) > 0 {
		items = append(items, evidence.NewDataFlowItem(
			tenantID, correlationID,
			evidence.FlowSourceToolResult, toolName,
			resultTier, resultEntities,
			evidence.FlowDispositionSurfaced, evidence.FlowDestination{
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

func writeRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(&jsonrpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	})
}

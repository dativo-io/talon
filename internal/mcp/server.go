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
	classifier    classifier.Facade
}

// NewHandler creates an MCP handler with the given registry, policy engine,
// evidence store, and PII classifier (used for tool argument/result
// classification and data-flow evidence).
func NewHandler(registry *tools.ToolRegistry, policyEngine *policy.Engine, evidenceStore *evidence.Store, cls classifier.Facade) *Handler {
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
	flow := &serverFlowState{}

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
	// A scanner failure blocks the call fail-closed.
	if h.classifier != nil && len(params.Arguments) > 0 {
		argStr := string(params.Arguments)
		cls, scanErr := h.classifier.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
		if scanErr != nil {
			flow.argBlocked = true
			correlationID := "mcp_" + uuid.New().String()[:8]
			blockEv := h.newServerEvidence(tenantID, agentID, correlationID, params.Name, evidence.PolicyDecision{
				Allowed:       false,
				Action:        "deny",
				Reasons:       []string{"scanner_unavailable"},
				PolicyVersion: decision.PolicyVersion,
			}, "scanner unavailable", 0, flow)
			blockEv.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
				Code:            explanation.CodeExecutionFailed,
				Decision:        explanation.DecisionDeny,
				Stage:           explanation.StagePolicyEvaluation,
				Trigger:         "scanner_unavailable",
				PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
				VersionIdentity: decision.PolicyVersion,
			}})
			if storeErr := h.evidenceStore.Store(ctx, blockEv); storeErr != nil {
				span.RecordError(storeErr)
			}
			return &jsonrpcResponse{
				JSONRPC: jsonrpcVersion,
				ID:      req.ID,
				Error:   &rpcError{Code: codeServerError, Message: "Tool arguments blocked: PII scanner unavailable (fail-closed)"},
			}
		}
		flow.argTier = cls.Tier
		if cls.HasPII {
			flow.argEntities = classifier.MergeEntitySpans(argStr, cls.Entities)
			flow.argEntities = applyServerFlowFieldPath(flow.argEntities, "arguments")
			redactedArgs, redactErr := h.classifier.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
			if redactErr != nil {
				flow.argBlocked = true
				correlationID := "mcp_" + uuid.New().String()[:8]
				blockEv := h.newServerEvidence(tenantID, agentID, correlationID, params.Name, evidence.PolicyDecision{
					Allowed:       false,
					Action:        "deny",
					Reasons:       []string{"scanner_unavailable"},
					PolicyVersion: decision.PolicyVersion,
				}, "redaction failed: scanner unavailable", 0, flow)
				blockEv.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
					Code:            explanation.CodeExecutionFailed,
					Decision:        explanation.DecisionDeny,
					Stage:           explanation.StagePolicyEvaluation,
					Trigger:         "scanner_unavailable",
					PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
					VersionIdentity: decision.PolicyVersion,
				}})
				if storeErr := h.evidenceStore.Store(ctx, blockEv); storeErr != nil {
					span.RecordError(storeErr)
				}
				return &jsonrpcResponse{
					JSONRPC: jsonrpcVersion,
					ID:      req.ID,
					Error:   &rpcError{Code: codeServerError, Message: "Tool arguments blocked: PII redaction failed (fail-closed)"},
				}
			}
			flow.argRedacted = redactedArgs != argStr
			if verifyErr := h.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), redactedArgs); verifyErr != nil {
				flow.argBlocked = true
				correlationID := "mcp_" + uuid.New().String()[:8]
				blockEv := h.newServerEvidence(tenantID, agentID, correlationID, params.Name, evidence.PolicyDecision{
					Allowed:       false,
					Action:        "deny",
					Reasons:       []string{"request_residual_pii_after_redaction"},
					PolicyVersion: decision.PolicyVersion,
				}, "request residual pii after redaction", 0, flow)
				blockEv.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
					Code:            explanation.CodePolicyDeniedPIIInput,
					Decision:        explanation.DecisionDeny,
					Stage:           explanation.StagePolicyEvaluation,
					Trigger:         "request_residual_pii_after_redaction",
					PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
					VersionIdentity: decision.PolicyVersion,
				}})
				if storeErr := h.evidenceStore.Store(ctx, blockEv); storeErr != nil {
					span.RecordError(storeErr)
				}
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
				flow.argBlocked = true
				correlationID := "mcp_" + uuid.New().String()[:8]
				blockEv := h.newServerEvidence(tenantID, agentID, correlationID, params.Name, evidence.PolicyDecision{
					Allowed:       false,
					Action:        "deny",
					Reasons:       []string{"request_redaction_invalid_json"},
					PolicyVersion: decision.PolicyVersion,
				}, "request redaction invalid json", 0, flow)
				blockEv.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
					Code:            explanation.CodeExecutionFailed,
					Decision:        explanation.DecisionFailure,
					Stage:           explanation.StagePolicyEvaluation,
					Trigger:         "request_redaction_invalid_json",
					PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
					VersionIdentity: decision.PolicyVersion,
				}})
				if storeErr := h.evidenceStore.Store(ctx, blockEv); storeErr != nil {
					span.RecordError(storeErr)
				}
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
		flow.argBlocked = true
		denyCorrelationID := "mcp_" + uuid.New().String()[:8]
		denyEv := h.newServerEvidence(tenantID, agentID, denyCorrelationID, params.Name, evidence.PolicyDecision{
			Allowed:       false,
			Action:        decision.Action,
			Reasons:       decision.Reasons,
			PolicyVersion: decision.PolicyVersion,
		}, msg, 0, flow)
		denyEv.Explanations = explanation.BuildFromFacts(explanation.BuildLegacyFacts(
			false,
			decision.Action,
			decision.Reasons,
			explanation.StagePolicyEvaluation,
			explanation.PolicyRef(decision.PolicyVersion),
			decision.PolicyVersion,
		))
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
	// A scanner failure blocks the result fail-closed.
	if h.classifier != nil && execErr == nil && result != nil {
		if resultJSON, marshalErr := json.Marshal(result); marshalErr == nil {
			resultStr := string(resultJSON)
			cls, scanErr := h.classifier.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), resultStr)
			if scanErr != nil {
				flow.resultBlocked = true
				correlationID := "mcp_" + uuid.New().String()[:8]
				blockEv := h.newServerEvidence(tenantID, agentID, correlationID, params.Name, evidence.PolicyDecision{
					Allowed:       false,
					Action:        "deny",
					Reasons:       []string{"output_scanner_unavailable"},
					PolicyVersion: decision.PolicyVersion,
				}, "output scanner unavailable", duration, flow)
				blockEv.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
					Code:            explanation.CodeExecutionFailed,
					Decision:        explanation.DecisionDeny,
					Stage:           explanation.StageOutputValidation,
					Trigger:         "output_scanner_unavailable",
					PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
					VersionIdentity: decision.PolicyVersion,
				}})
				if storeErr := h.evidenceStore.Store(ctx, blockEv); storeErr != nil {
					span.RecordError(storeErr)
				}
				return &jsonrpcResponse{
					JSONRPC: jsonrpcVersion,
					ID:      req.ID,
					Error:   &rpcError{Code: codeServerError, Message: "Tool result blocked: PII scanner unavailable (fail-closed)"},
				}
			}
			flow.resultTier = cls.Tier
			if cls.HasPII {
				flow.resultEntities = classifier.MergeEntitySpans(resultStr, cls.Entities)
				flow.resultEntities = applyServerFlowFieldPath(flow.resultEntities, "result")
				redacted, redactErr := h.classifier.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), resultStr)
				if redactErr != nil {
					flow.resultBlocked = true
					correlationID := "mcp_" + uuid.New().String()[:8]
					blockEv := h.newServerEvidence(tenantID, agentID, correlationID, params.Name, evidence.PolicyDecision{
						Allowed:       false,
						Action:        "deny",
						Reasons:       []string{"output_scanner_unavailable"},
						PolicyVersion: decision.PolicyVersion,
					}, "output redaction failed: scanner unavailable", duration, flow)
					blockEv.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
						Code:            explanation.CodeExecutionFailed,
						Decision:        explanation.DecisionDeny,
						Stage:           explanation.StageOutputValidation,
						Trigger:         "output_scanner_unavailable",
						PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
						VersionIdentity: decision.PolicyVersion,
					}})
					if storeErr := h.evidenceStore.Store(ctx, blockEv); storeErr != nil {
						span.RecordError(storeErr)
					}
					return &jsonrpcResponse{
						JSONRPC: jsonrpcVersion,
						ID:      req.ID,
						Error:   &rpcError{Code: codeServerError, Message: "Tool result blocked: PII redaction failed (fail-closed)"},
					}
				}
				flow.resultRedacted = redacted != resultStr
				if verifyErr := h.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), redacted); verifyErr != nil {
					flow.resultBlocked = true
					correlationID := "mcp_" + uuid.New().String()[:8]
					blockEv := h.newServerEvidence(tenantID, agentID, correlationID, params.Name, evidence.PolicyDecision{
						Allowed:       false,
						Action:        "deny",
						Reasons:       []string{"output_pii_blocked_residual"},
						PolicyVersion: decision.PolicyVersion,
					}, "output pii blocked residual", duration, flow)
					blockEv.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
						Code:            explanation.CodePolicyDeniedPIIOutput,
						Decision:        explanation.DecisionDeny,
						Stage:           explanation.StageOutputValidation,
						Trigger:         "output_pii_blocked_residual",
						PolicyRef:       explanation.PolicyRef(decision.PolicyVersion),
						VersionIdentity: decision.PolicyVersion,
					}})
					if storeErr := h.evidenceStore.Store(ctx, blockEv); storeErr != nil {
						span.RecordError(storeErr)
					}
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
	ev := h.newServerEvidence(tenantID, agentID, correlationID, params.Name, evidence.PolicyDecision{
		Allowed:       true,
		Action:        "allow",
		PolicyVersion: decision.PolicyVersion,
	}, "", duration, flow)
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
type serverFlowState struct {
	argTier        int
	argEntities    []classifier.PIIEntity
	argBlocked     bool
	argRedacted    bool
	resultTier     int
	resultEntities []classifier.PIIEntity
	resultBlocked  bool
	resultRedacted bool
}

func (h *Handler) buildServerDataFlow(
	tenantID, correlationID, toolName string,
	flow *serverFlowState,
) *evidence.DataFlow {
	argDisposition := evidence.FlowDispositionForwarded
	switch {
	case flow.argBlocked:
		argDisposition = evidence.FlowDispositionBlocked
	case flow.argRedacted:
		argDisposition = evidence.FlowDispositionRedacted
	}
	items := []evidence.DataFlowItem{evidence.NewDataFlowItem(
		tenantID, correlationID,
		evidence.FlowSourceToolArgs, toolName,
		flow.argTier, flow.argEntities,
		argDisposition, evidence.FlowDestination{
			Kind:   evidence.FlowDestMCPTool,
			Name:   toolName,
			Region: "LOCAL",
		})}
	if len(flow.resultEntities) > 0 {
		resultDisposition := evidence.FlowDispositionSurfaced
		switch {
		case flow.resultBlocked:
			resultDisposition = evidence.FlowDispositionBlocked
		case flow.resultRedacted:
			resultDisposition = evidence.FlowDispositionRedacted
		}
		items = append(items, evidence.NewDataFlowItem(
			tenantID, correlationID,
			evidence.FlowSourceToolResult, toolName,
			flow.resultTier, flow.resultEntities,
			resultDisposition, evidence.FlowDestination{
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

func (h *Handler) newServerEvidence(
	tenantID, agentID, correlationID, toolName string,
	decision evidence.PolicyDecision,
	execErr string,
	durationMS int64,
	flow *serverFlowState,
) *evidence.Evidence {
	ev := &evidence.Evidence{
		ID:              "req_" + uuid.New().String()[:8],
		CorrelationID:   correlationID,
		Timestamp:       time.Now(),
		TenantID:        tenantID,
		AgentID:         agentID,
		InvocationType:  "mcp",
		RequestSourceID: "mcp",
		PolicyDecision:  decision,
		Execution: evidence.Execution{
			ToolsCalled: []string{toolName},
			DurationMS:  durationMS,
			Error:       execErr,
		},
		Classification: evidence.Classification{
			InputTier:         flow.argTier,
			OutputTier:        flow.resultTier,
			PIIDetected:       entityTypeSet(flow.argEntities),
			PIIRedacted:       flow.resultRedacted,
			InputPIIRedacted:  flow.argRedacted,
			OutputPIIDetected: len(flow.resultEntities) > 0,
			OutputPIITypes:    entityTypeSet(flow.resultEntities),
		},
	}
	ev.DataFlow = h.buildServerDataFlow(tenantID, correlationID, toolName, flow)
	return ev
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

func applyServerFlowFieldPath(entities []classifier.PIIEntity, fieldPath string) []classifier.PIIEntity {
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

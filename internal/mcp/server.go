// Package mcp implements Talon's MCP surfaces (native /mcp and the governance
// proxy /mcp/proxy) over MCP 2026-07-28 Streamable HTTP. Both routes share
// the wire package: one parser, one gate, one error vocabulary (#447).
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
)

var tracer = otel.Tracer("github.com/dativo-io/talon/internal/mcp")

const jsonrpcVersion = "2.0"

// jsonrpcResponse is the internal response shape the governed paths build.
// The wire package writes it; ID keeps the client's exact id bytes.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// Data carries the stable machine-readable denial code (#369):
	// {"talon_code": "TALON_..."} — integrators key on this, never on the
	// prose Message.
	Data interface{} `json:"data,omitempty"`
}

// Application-level JSON-RPC codes used AFTER the protocol gate accepted the
// request. Protocol rejections never reach these: they use wire's codes.
const (
	codeInvalidParams = wire.CodeInvalidParams
	codeServerError   = -32000 // Talon governance / execution outcome (grandfathered legacy range)
)

// write sends a governed-path response: an application error (HTTP 200,
// JSON-RPC error) or a result.
func (r *jsonrpcResponse) write(w http.ResponseWriter) {
	if r.Error != nil {
		wire.WriteRPCError(w, r.ID, r.Error.Code, r.Error.Message, r.Error.Data)
		return
	}
	wire.WriteResult(w, r.ID, r.Result)
}

// nativeServer is the identity this route reports in every result.
func nativeServer() wire.Implementation {
	return wire.Implementation{Name: "talon", Version: ServerVersion}
}

// listTTLMs is the freshness hint for native tools/list and discovery: the
// registry is fixed for the process lifetime, so a short TTL only bounds
// how stale a client may be across a restart.
const listTTLMs = 60_000

// Handler implements the native MCP server: server/discover, tools/list and
// tools/call over MCP 2026-07-28 Streamable HTTP (#447).
type Handler struct {
	registry      *tools.ToolRegistry
	policyEngine  *policy.Engine
	evidenceStore *evidence.Store
	classifier    classifier.Facade
	// Transport is the shared protocol gate; routes share one implementation
	// so /mcp and /mcp/proxy cannot speak different MCP versions.
	Transport *wire.Transport
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
		Transport:     newTransport(),
	}
}

// newTransport is the one method allowlist both routes serve.
func newTransport() *wire.Transport {
	return &wire.Transport{Methods: []string{wire.MethodDiscover, wire.MethodToolsList, wire.MethodToolsCall}}
}

// ServeHTTP handles POST /mcp. Every request is self-describing: the wire
// gate validates transport, protocol version, required _meta and header/body
// integrity before any method runs; nothing is inferred from earlier
// traffic and a protocol rejection writes no governance evidence.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracer.Start(r.Context(), "mcp.serve",
		trace.WithAttributes(
			attribute.String("http.request.method", r.Method),
		))
	defer span.End()

	req, outcome := h.Transport.Accept(w, r)
	if outcome != wire.Ready {
		span.SetAttributes(attribute.Bool("mcp.protocol_rejected", outcome == wire.Rejected))
		return
	}
	span.SetAttributes(attribute.String("mcp.method", req.Method))

	var resp *jsonrpcResponse
	switch req.Method {
	case wire.MethodDiscover:
		resp = &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: h.discoverResult()}
	case wire.MethodToolsList:
		resp = h.handleToolsList(ctx, req.ID)
	case wire.MethodToolsCall:
		resp = h.handleToolsCall(ctx, w, req)
		if resp == nil {
			return // protocol rejection already written
		}
	}
	resp.write(w)
}

// discoverResult advertises exactly what this route implements: the one
// protocol version, the tools capability (no listChanged: there is no
// subscriptions/listen stream here), no extensions.
func (h *Handler) discoverResult() map[string]interface{} {
	return wire.Discover(nativeServer(), map[string]interface{}{"tools": map[string]interface{}{}}, "", listTTLMs)
}

func (h *Handler) handleToolsList(ctx context.Context, id json.RawMessage) *jsonrpcResponse {
	_, span := tracer.Start(ctx, "mcp.tools.list")
	defer span.End()

	list := h.registry.List()
	entries := make([]map[string]interface{}, 0, len(list))
	for _, t := range list {
		schema := t.InputSchema()
		if len(schema) == 0 || string(schema) == "null" {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		if _, err := wire.HeaderParamsFromSchema(schema); err != nil {
			// A definition with an invalid x-mcp-header annotation is
			// excluded from the list (streamable-http §Schema Extension).
			log.Warn().Str("tool", t.Name()).Err(err).Msg("mcp_tool_excluded_invalid_header_annotation")
			continue
		}
		entries = append(entries, map[string]interface{}{
			"name":        t.Name(),
			"description": t.Description(),
			"inputSchema": schema,
		})
	}
	// Deterministic order: the registry's order is insertion order, which is
	// stable for a process; sort by name so it is stable across restarts.
	sort.Slice(entries, func(i, j int) bool { return entries[i]["name"].(string) < entries[j]["name"].(string) })
	span.SetAttributes(attribute.Int("tools.count", len(entries)))
	result := wire.Cacheable(wire.Complete(nativeServer(), map[string]interface{}{"tools": entries}), listTTLMs, wire.CacheScopePrivate)
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: id, Result: result}
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

//nolint:gocyclo // MCP tools/call: policy, schema validation, execute, evidence — branching required
func (h *Handler) handleToolsCall(ctx context.Context, w http.ResponseWriter, req *wire.Request) *jsonrpcResponse {
	ctx, span := tracer.Start(ctx, "mcp.tools.call")
	defer span.End()

	params := toolsCallParams{Name: req.Name, Arguments: req.Arguments}
	if params.Name == "" {
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "tool name is required"}}
	}
	// Mcp-Param-* integrity (#447): when the trusted tool schema declares
	// mirrored parameters, every recognized header must equal the parsed
	// argument. A mismatch is a protocol rejection — before policy, before
	// execution, with no evidence (no trustworthy action exists yet). The
	// header is never the argument value.
	if tool, ok := h.registry.Get(params.Name); ok {
		decl, derr := wire.HeaderParamsFromSchema(tool.InputSchema())
		if derr != nil {
			wire.WriteError(w, req.ID, &wire.Error{Status: http.StatusBadRequest, Code: wire.CodeInvalidParams, Reason: wire.ReasonInvalidRequest, Message: "tool definition is invalid: " + derr.Error()})
			return nil
		}
		if perr := wire.ValidateHeaderParams(decl, params.Arguments, req.HeaderParams); perr != nil {
			span.SetAttributes(attribute.String("mcp.protocol_reason", perr.Reason))
			wire.WriteError(w, req.ID, perr)
			return nil
		}
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
			return h.scannerBlockedResponse(ctx, span, req.ID, tenantID, agentID, params.Name, decision.PolicyVersion,
				scanErr, "scanner_unavailable", "scanner unavailable", "Tool arguments blocked: PII scanner unavailable (fail-closed)", explanation.StagePolicyEvaluation, 0, flow)
		}
		flow.argTier = cls.Tier
		if cls.HasPII {
			flow.argEntities = classifier.MergeEntitySpans(argStr, cls.Entities)
			flow.argEntities = applyServerFlowFieldPath(flow.argEntities, "arguments")
			redactedArgs, redactErr := h.classifier.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
			if redactErr != nil {
				flow.argBlocked = true
				return h.scannerBlockedResponse(ctx, span, req.ID, tenantID, agentID, params.Name, decision.PolicyVersion,
					redactErr, "scanner_unavailable", "redaction failed: scanner unavailable", "Tool arguments blocked: PII redaction failed (fail-closed)", explanation.StagePolicyEvaluation, 0, flow)
			}
			flow.argRedacted = redactedArgs != argStr
			if verifyErr := h.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), redactedArgs); verifyErr != nil {
				flow.argBlocked = true
				if !errors.Is(verifyErr, classifier.ErrPIIDetected) {
					return h.scannerBlockedResponse(ctx, span, req.ID, tenantID, agentID, params.Name, decision.PolicyVersion,
						verifyErr, "request_redaction_verification_scanner_unavailable", "request redaction verification failed: scanner unavailable",
						"Tool arguments blocked: redaction could not be verified (fail-closed)", explanation.StagePolicyEvaluation, 0, flow)
				}
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
		// Unknown tool is a protocol error per server/tools §Error Handling.
		return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "Unknown tool: " + params.Name}}
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
				return h.scannerBlockedResponse(ctx, span, req.ID, tenantID, agentID, params.Name, decision.PolicyVersion,
					scanErr, "output_scanner_unavailable", "output scanner unavailable", "Tool result blocked: PII scanner unavailable (fail-closed)", explanation.StageOutputValidation, duration, flow)
			}
			flow.resultTier = cls.Tier
			if cls.HasPII {
				flow.resultEntities = classifier.MergeEntitySpans(resultStr, cls.Entities)
				flow.resultEntities = applyServerFlowFieldPath(flow.resultEntities, "result")
				redacted, redactErr := h.classifier.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), resultStr)
				if redactErr != nil {
					flow.resultBlocked = true
					return h.scannerBlockedResponse(ctx, span, req.ID, tenantID, agentID, params.Name, decision.PolicyVersion,
						redactErr, "output_scanner_unavailable", "output redaction failed: scanner unavailable", "Tool result blocked: PII redaction failed (fail-closed)", explanation.StageOutputValidation, duration, flow)
				}
				flow.resultRedacted = redacted != resultStr
				if verifyErr := h.classifier.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), redacted); verifyErr != nil {
					flow.resultBlocked = true
					if !errors.Is(verifyErr, classifier.ErrPIIDetected) {
						return h.scannerBlockedResponse(ctx, span, req.ID, tenantID, agentID, params.Name, decision.PolicyVersion,
							verifyErr, "output_redaction_verification_scanner_unavailable", "output redaction verification failed: scanner unavailable",
							"Tool result blocked: redaction could not be verified (fail-closed)", explanation.StageOutputValidation, duration, flow)
					}
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

	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: toolResult(result)}
}

// toolResult renders a native tool's JSON result as a CallToolResult: the
// serialized JSON as a text content block (every client can read it) plus
// the same value as structuredContent.
func toolResult(result json.RawMessage) map[string]interface{} {
	if len(result) == 0 {
		result = json.RawMessage("null")
	}
	return wire.Complete(nativeServer(), map[string]interface{}{
		"content":           []map[string]interface{}{{"type": "text", "text": string(result)}},
		"structuredContent": result,
		"isError":           false,
	})
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

// scannerBlockedResponse records fail-closed deny evidence for a scan-engine
// failure (typed failure kind included) and returns the JSON-RPC error to
// surface to the caller.
func (h *Handler) scannerBlockedResponse(ctx context.Context, span trace.Span, reqID json.RawMessage, tenantID, agentID, toolName, policyVersion string, scanErr error, trigger, evReason, clientMsg, stage string, durationMS int64, flow *serverFlowState) *jsonrpcResponse {
	correlationID := "mcp_" + uuid.New().String()[:8]
	blockEv := h.newServerEvidence(tenantID, agentID, correlationID, toolName, evidence.PolicyDecision{
		Allowed:       false,
		Action:        "deny",
		Reasons:       []string{trigger},
		PolicyVersion: policyVersion,
	}, evReason, durationMS, flow)
	if blockEv.Classification.Scanner != nil {
		blockEv.Classification.Scanner.Failure = scannerFailureKind(scanErr)
	}
	blockEv.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
		Code:            explanation.CodeExecutionFailed,
		Decision:        explanation.DecisionDeny,
		Stage:           stage,
		Trigger:         trigger,
		PolicyRef:       explanation.PolicyRef(policyVersion),
		VersionIdentity: policyVersion,
	}})
	if storeErr := h.evidenceStore.Store(ctx, blockEv); storeErr != nil {
		span.RecordError(storeErr)
	}
	return &jsonrpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      reqID,
		Error:   &rpcError{Code: codeServerError, Message: clientMsg},
	}
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
	// Every record identifies the scan engine behind its classification;
	// scanner-driven denials also carry the failure kind.
	if scannerInfo := evidence.NewScannerInfo(h.classifier); scannerInfo != nil {
		for _, r := range decision.Reasons {
			if strings.Contains(r, "scanner_unavailable") {
				scannerInfo.Failure = "scanner_unavailable"
			}
		}
		ev.Classification.Scanner = scannerInfo
	}
	ev.DataFlow = h.buildServerDataFlow(tenantID, correlationID, toolName, flow)
	return ev
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

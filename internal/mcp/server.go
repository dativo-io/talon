// Package mcp implements Talon's governed MCP surface, POST /mcp, over MCP
// 2026-07-28 Streamable HTTP (#447, #431).
//
// The route is a protocol adapter over the canonical Action Gateway
// (internal/action): it never decides, approves or dispatches anything
// itself. tools/list projects the authenticated AI use case's MCP-sourced
// action definitions; tools/call establishes (or resumes) one canonical
// operation through the same in-process action.Service the HTTP Action
// Gateway uses, and an authorized operation is executed by the service's
// trusted MCP dispatcher: one tools/call to the definition's source, at
// most once per operation.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/govcode"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/otel"
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
	// Data carries the versioned governance extension (#372,
	// govcode.ExtensionID) and, for one release, the deprecated flat
	// {"talon_code": "TALON_..."} alias (#369). Integrators key on these,
	// never on the prose Message.
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

// listTTLMs is the freshness hint for tools/list and discovery: the list is
// a projection of the use case's current runtime generation, so a short TTL
// bounds how stale a client may be across a reload.
const listTTLMs = 60_000

// ExecuteToolName is the one tool Talon itself presents: it executes a
// PREPARED operation by its operation id (the second call of the two-call
// flow). It is listed whenever the use case has a governed MCP tool.
const ExecuteToolName = "talon_execute_operation"

// MetaOperationID is the optional _meta key through which an advanced client
// supplies its own stable operation id. With it, the call is executed in the
// same tools/call when authorized (a repeated call with the same id resolves
// the same operation); without it, Talon generates the id and the call only
// prepares the operation.
const MetaOperationID = "io.dativo.talon/operationId"

// ServiceResolver resolves the authenticated AI use case's Action Gateway
// service: the same per-generation instance /v1/action-operations uses.
type ServiceResolver func(id requestctx.AgentIdentity) (*action.Service, error)

// UseCasePII is the use case's effective PII handling for governed MCP
// calls: the company pii_action / response_pii_action, which a use case can
// only tighten (block > redact > warn > allow), and the use case's
// policy-aware scanner.
type UseCasePII struct {
	Request    string
	Response   string
	Classifier classifier.Facade
}

// PIIResolver returns the effective PII handling of an authenticated use
// case.
type PIIResolver func(id requestctx.AgentIdentity) UseCasePII

// Config wires the governed route.
type Config struct {
	// Services resolves the use case's action.Service (nil: no use case
	// has an action catalog; the route lists nothing and resolves nothing).
	Services ServiceResolver
	// PII resolves the use case's effective PII handling (nil: allow, no
	// scanning).
	PII PIIResolver
	// Evidence stores the adapter's own records (PII refusals and
	// redactions). The lifecycle records belong to the action service.
	Evidence *evidence.Store
	// Classifier is the scanner used when the use case has none of its own.
	Classifier classifier.Facade
}

// Handler implements the governed MCP route: server/discover, tools/list and
// tools/call over MCP 2026-07-28 Streamable HTTP.
type Handler struct {
	services      ServiceResolver
	pii           PIIResolver
	evidenceStore *evidence.Store
	classifier    classifier.Facade
	// Transport is the protocol gate (#447).
	Transport *wire.Transport
	// attr is the request's client-asserted attribution; set only on the
	// per-request copy (forCall), never on the shared handler.
	attr *action.Attribution
}

// NewHandler creates the governed MCP handler.
func NewHandler(cfg Config) *Handler {
	return &Handler{
		services:      cfg.Services,
		pii:           cfg.PII,
		evidenceStore: cfg.Evidence,
		classifier:    cfg.Classifier,
		Transport:     newTransport(),
	}
}

// newTransport is the method allowlist the route serves.
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
	attr, aerr := attributionFrom(r)
	if aerr != nil {
		// Malformed client-asserted attribution is rejected before anything
		// is evaluated or recorded (the same header hygiene as the gateway).
		wire.WriteError(w, req.ID, &wire.Error{Status: http.StatusBadRequest, Code: wire.CodeInvalidRequest, Reason: wire.ReasonInvalidRequest, Message: govcode.Bounded(aerr.Error())})
		return
	}
	echoAttribution(w, attr)
	ctx = withAttribution(ctx, attr)

	var resp *jsonrpcResponse
	switch req.Method {
	case wire.MethodDiscover:
		resp = &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: h.discoverResult()}
	case wire.MethodToolsList:
		resp = h.handleToolsList(ctx, w, req)
	case wire.MethodToolsCall:
		resp = h.handleToolsCall(ctx, w, req)
	}
	if resp == nil {
		return // protocol rejection already written
	}
	resp.write(w)
}

// discoverResult advertises exactly what this route implements: the one
// protocol version, the tools capability (no listChanged: there is no
// subscriptions/listen stream here) and the governance extension (#372);
// no Tasks.
func (h *Handler) discoverResult() map[string]interface{} {
	return wire.Discover(nativeServer(), discoverCapabilities(), "", listTTLMs)
}

// useCase is the authenticated AI use case one request acts for.
type useCase struct {
	id   requestctx.AgentIdentity
	svc  *action.Service // nil: the use case has no action catalog
	pii  UseCasePII
	attr *action.Attribution // client-asserted; nil when none
}

// generation is the short runtime-generation identity for the extension.
func (u *useCase) generation() string {
	g := u.id.Generation
	if len(g) > 12 {
		g = g[:12]
	}
	return g
}

// resolveUseCase binds the request to the authenticated use case. A missing
// identity or a generation that changed since authentication is a governed
// failure before anything is evaluated.
func (h *Handler) resolveUseCase(reqID json.RawMessage, ctx context.Context) (*useCase, *jsonrpcResponse) {
	id, ok := requestctx.AgentIdentityFrom(ctx)
	if !ok || id.AgentID == "" {
		return nil, actionResponse(reqID, govcode.AgentIdentityRequired, "an AI use case key is required for /mcp", nil, nil)
	}
	uc := &useCase{id: id, pii: UseCasePII{Classifier: h.classifier}, attr: attributionOf(ctx)}
	if h.pii != nil {
		uc.pii = h.pii(id)
		if uc.pii.Classifier == nil {
			uc.pii.Classifier = h.classifier
		}
	}
	if h.services == nil {
		return uc, nil
	}
	svc, err := h.services(id)
	if err != nil {
		code := governanceCodeOf(err)
		if code == action.CodeActionNotFound {
			return uc, nil // no action catalog: nothing to list or call
		}
		return nil, actionResponse(reqID, code, "the AI use case's actions could not be resolved", nil, uc)
	}
	uc.svc = svc
	return uc, nil
}

// governanceCodeOf extracts a registered governance code from a resolver or
// service error.
func governanceCodeOf(err error) string {
	var coded interface{ GovernanceCode() string }
	if errors.As(err, &coded) {
		return coded.GovernanceCode()
	}
	if c := action.CodeOf(err); c != "" {
		return c
	}
	return govcode.StoreUnavailable
}

// governedDefinitions are the use case's MCP-sourced actions a client may
// discover: every definition whose destination is an MCP source, minus the
// ones a forbidden_tools rule denies outright (preventive filtering). A
// listed tool is never authorized by being listed, and a hidden one called
// directly is still decided — and denied — by the Action Gateway.
func (u *useCase) governedDefinitions() []*action.Definition {
	if u.svc == nil || u.svc.Catalog == nil {
		return nil
	}
	var out []*action.Definition
	for _, name := range u.svc.Catalog.Names() {
		def, ok := u.svc.Catalog.Lookup(name)
		if !ok || def.Destination.Type != action.DestinationTypeMCP {
			continue
		}
		if u.svc.Policy != nil && u.svc.Policy.Evaluate(def.Name).Outcome == action.VerdictDeny {
			continue
		}
		out = append(out, def)
	}
	return out
}

// lookup resolves a callable governed definition by its canonical name. A
// forbidden one resolves (the gateway denies it with evidence); a non-MCP
// or unknown one does not.
func (u *useCase) lookup(name string) (*action.Definition, bool) {
	if u.svc == nil || u.svc.Catalog == nil {
		return nil, false
	}
	def, ok := u.svc.Catalog.Lookup(name)
	if !ok || def.Destination.Type != action.DestinationTypeMCP {
		return nil, false
	}
	return def, true
}

func (h *Handler) handleToolsList(ctx context.Context, w http.ResponseWriter, req *wire.Request) *jsonrpcResponse {
	ctx, span := tracer.Start(ctx, "mcp.tools.list")
	defer span.End()
	if req.Cursor != "" {
		return writeInvalidParams(w, req.ID, "this server returns a single page; no cursor is valid")
	}
	uc, resp := h.resolveUseCase(req.ID, ctx)
	if resp != nil {
		return resp
	}
	defs := uc.governedDefinitions()
	entries := make([]map[string]interface{}, 0, len(defs)+1)
	for _, def := range defs {
		entries = append(entries, presentedTool(def))
	}
	if len(entries) > 0 {
		entries = append(entries, executeToolDefinition())
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i]["name"].(string) < entries[j]["name"].(string) })
	span.SetAttributes(attribute.Int("tools.count", len(entries)))
	result := wire.Cacheable(wire.Complete(nativeServer(), map[string]interface{}{"tools": entries}), wire.TTL(listTTLMs), wire.CacheScopePrivate)
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID, Result: result}
}

// presentedTool is a governed action as an MCP tool: its canonical name, the
// closed schema Talon validates against, and how a call is handled.
func presentedTool(def *action.Definition) map[string]interface{} {
	desc := strings.TrimSpace(def.Description)
	mode := "prepare_then_execute"
	if def.ReadOnly {
		mode = "single_call"
	} else {
		note := "Governed by Talon: this call only PREPARES the action and returns an operation id; nothing is executed until " + ExecuteToolName + " is called with that operation id (after approval, when one is required)."
		if desc == "" {
			desc = note
		} else {
			desc += "\n\n" + note
		}
	}
	tool := map[string]interface{}{
		"name":        def.Name,
		"description": desc,
		"inputSchema": json.RawMessage(def.Schema),
		"annotations": map[string]interface{}{"readOnlyHint": def.ReadOnly},
		"_meta":       map[string]interface{}{govcode.ExtensionID: map[string]interface{}{"execution": mode}},
	}
	if def.Title != "" {
		tool["title"] = def.Title
	}
	return tool
}

// executeToolSchema is the closed input schema of talon_execute_operation.
var executeToolSchema = json.RawMessage(`{"type":"object","properties":{"operation_id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","description":"The operation id a prepared governed tool call returned."}},"required":["operation_id"],"additionalProperties":false}`)

func executeToolDefinition() map[string]interface{} {
	return map[string]interface{}{
		"name":        ExecuteToolName,
		"description": "Execute a governed action that a previous tool call prepared, by its operation id. Talon re-checks policy and approval and calls the business system at most once for that operation; repeating the call never executes it twice. If the action still awaits approval, call again after a reviewer approved it.",
		"inputSchema": executeToolSchema,
		"annotations": map[string]interface{}{"readOnlyHint": false},
	}
}

// handleToolsCall serves both the governed tools and talon_execute_operation.
//
//nolint:gocyclo // protocol gate, resolution, PII, establish, prepare-or-execute: each a distinct governed outcome
func (h *Handler) handleToolsCall(ctx context.Context, w http.ResponseWriter, req *wire.Request) *jsonrpcResponse {
	ctx, span := tracer.Start(ctx, "mcp.tools.call")
	defer span.End()
	if req.Name == "" {
		return writeInvalidParams(w, req.ID, "tool name is required")
	}
	span.SetAttributes(attribute.String("tool.name", req.Name))
	uc, resp := h.resolveUseCase(req.ID, ctx)
	if resp != nil {
		return resp
	}
	if req.Name == ExecuteToolName {
		return h.executePrepared(ctx, w, req, uc)
	}
	// Canonical resolution precedes governance: a name Talon cannot
	// resolve is the spec's invalid-params protocol error — no governance
	// extension, no evidence, zero execution.
	def, ok := uc.lookup(req.Name)
	if !ok {
		return writeInvalidParams(w, req.ID, "Unknown tool: "+sanitizeDiagnostic(req.Name))
	}
	// Mcp-Param-* integrity (#447) against the schema tools/list presents.
	decl, derr := wire.HeaderParamsFromSchema(def.Schema)
	if derr != nil {
		return writeInvalidParams(w, req.ID, "tool definition is invalid: "+sanitizeDiagnostic(derr.Error()))
	}
	if perr := wire.ValidateHeaderParams(decl, req.Arguments, req.HeaderParams); perr != nil {
		span.SetAttributes(attribute.String("mcp.protocol_reason", perr.Reason))
		wire.WriteError(w, req.ID, perr)
		return nil
	}
	opID, callerProvided, err := operationIDFromMeta(req.Meta)
	if err != nil {
		return writeInvalidParams(w, req.ID, err.Error())
	}
	args := req.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	args, resp = h.applyRequestPII(ctx, span, req.ID, uc, def.Name, args, &serverFlowState{})
	if resp != nil {
		return resp
	}
	identitySource := action.IdentityCallerProvided
	if !callerProvided {
		// A durable Talon-generated id: never model-generated, never
		// derived from the arguments. Retries reference it explicitly.
		opID = "mcp-" + uuid.NewString()
		identitySource = action.IdentityAdapterGenerated
	}
	est, err := uc.svc.Establish(ctx, action.EstablishRequest{OperationID: opID, Action: def.Name, Arguments: args, IdentitySource: identitySource, Attribution: uc.attr})
	if err != nil {
		return h.actionFailure(ctx, w, req.ID, err, uc)
	}
	op := est.Operation
	span.SetAttributes(attribute.String("action.operation_id", op.OperationID), attribute.String("action.status", op.Status))
	if op.Status == action.OpDenied {
		return h.withSignedReason(ctx, actionResponse(req.ID, govcode.PolicyDenied, publicPolicyDenied, op, uc))
	}
	if !callerProvided && (!def.ReadOnly || op.Status != action.OpAuthorized) {
		return h.preparedResult(ctx, req.ID, op, uc)
	}
	return h.execute(ctx, w, req.ID, uc, op.OperationID)
}

// operationIDFromMeta reads the optional caller-provided operation id.
func operationIDFromMeta(meta wire.Meta) (id string, provided bool, err error) {
	raw, ok := meta.Extra[MetaOperationID]
	if !ok {
		return "", false, nil
	}
	if uerr := json.Unmarshal(raw, &id); uerr != nil || strings.TrimSpace(id) == "" {
		return "", false, fmt.Errorf("_meta %s must be a non-empty string", MetaOperationID)
	}
	return id, true, nil
}

// executePrepared is talon_execute_operation: resume one prepared operation
// of this use case through the canonical claim.
func (h *Handler) executePrepared(ctx context.Context, w http.ResponseWriter, req *wire.Request, uc *useCase) *jsonrpcResponse {
	var args struct {
		OperationID string `json:"operation_id"`
	}
	dec := json.NewDecoder(strings.NewReader(string(req.Arguments)))
	dec.DisallowUnknownFields()
	if len(req.Arguments) == 0 || dec.Decode(&args) != nil || strings.TrimSpace(args.OperationID) == "" {
		return writeInvalidParams(w, req.ID, ExecuteToolName+" takes exactly one argument, operation_id (string)")
	}
	if uc.svc == nil {
		return actionResponse(req.ID, govcode.NotFound, "operation not found in this AI use case", nil, uc)
	}
	return h.execute(ctx, w, req.ID, uc, args.OperationID)
}

// execute claims and dispatches one operation through the service: at most
// one dispatch, an ambiguous outcome is unknown, never a replay.
func (h *Handler) execute(ctx context.Context, w http.ResponseWriter, reqID json.RawMessage, uc *useCase, operationID string) *jsonrpcResponse {
	res, err := uc.svc.Execute(ctx, operationID)
	if err != nil {
		return h.actionFailure(ctx, w, reqID, err, uc)
	}
	op := res.Operation
	switch op.Status {
	case action.OpSucceeded:
		return h.relayResult(ctx, reqID, uc, op, res)
	case action.OpUnknown:
		h.logUnknown(op, res)
		return h.withSignedReason(ctx, actionResponse(reqID, govcode.UpstreamOutcomeUnknown, publicOutcomeUnknown, op, uc))
	default:
		code := govcode.UpstreamToolFailed
		if res.Attempt != nil && res.Attempt.OutcomeCode == "dispatch_credential_unavailable" {
			code = govcode.UpstreamAuthUnavailable
		}
		return h.withSignedReason(ctx, actionResponse(reqID, code, "Nothing was sent to the business system; the operation can be executed again with "+ExecuteToolName, op, uc))
	}
}

// logUnknown keeps the source's own error text for the operator: in the
// process log, sanitized and bounded, never in a signed record (which keeps
// the outcome code and the JSON-RPC category only) and never relayed.
func (h *Handler) logUnknown(op *action.Projection, res *action.ExecuteResult) {
	code := ""
	if res.Attempt != nil {
		code = res.Attempt.OutcomeCode
	}
	detail := ""
	if len(res.Result) > 0 {
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(res.Result, &e) == nil && e.Message != "" {
			detail = sanitizeDiagnostic(e.Message)
		}
	}
	log.Warn().Str("operation_id", op.OperationID).Str("action", op.Action).Str("outcome_code", code).Str("detail", detail).Msg("mcp_action_outcome_unknown")
}

// actionFailure maps a service error to the wire: request faults the
// service refuses before binding anything are protocol errors (no
// evidence, nothing evaluated), everything else a governed outcome with the
// service's own code and the evidence it committed.
func (h *Handler) actionFailure(ctx context.Context, w http.ResponseWriter, reqID json.RawMessage, err error, uc *useCase) *jsonrpcResponse {
	code := action.CodeOf(err)
	var aerr *action.Error
	_ = errors.As(err, &aerr)
	switch code {
	case action.CodeActionSchemaInvalid, action.CodeInvalidRequest, action.CodeOperationIDRequired:
		msg := "arguments violate the tool's schema"
		if code != action.CodeActionSchemaInvalid && aerr != nil {
			msg = aerr.Message
		}
		return writeInvalidParams(w, reqID, msg)
	case "":
		code = govcode.StoreUnavailable
	}
	msg := "the operation could not proceed"
	var state *action.Projection
	if aerr != nil {
		msg, state = aerr.Message, aerr.State
	}
	return h.withSignedReason(ctx, actionResponse(reqID, code, msg, state, uc))
}

// preparedResult answers the first call of the two-call flow: the operation
// exists, is bound to this use case, tool and canonical arguments, and
// NOTHING was executed. It is a normal tool result so an unmodified client
// shows it to the model, which then calls talon_execute_operation.
func (h *Handler) preparedResult(ctx context.Context, reqID json.RawMessage, op *action.Projection, uc *useCase) *jsonrpcResponse {
	code := govcode.OperationPrepared
	approvalID := ""
	if op.Approval != nil {
		approvalID = op.Approval.ID
	}
	text := fmt.Sprintf("Talon prepared operation %s (%s). Nothing was executed. To execute it, call %s with operation_id %q.", op.OperationID, op.Action, ExecuteToolName, op.OperationID)
	if op.Status == action.OpAwaitingApproval {
		code = govcode.ApprovalPending
		text = fmt.Sprintf("Talon prepared operation %s (%s). It needs approval by a reviewer (approval %s). Nothing was executed. After the approval, call %s with operation_id %q.", op.OperationID, op.Action, approvalID, ExecuteToolName, op.OperationID)
	}
	structured := map[string]interface{}{
		"operationId": op.OperationID,
		"status":      op.Status,
		"action":      op.Action,
		"next":        map[string]interface{}{"tool": ExecuteToolName, "arguments": map[string]string{"operation_id": op.OperationID}},
	}
	if approvalID != "" {
		structured["approvalId"] = approvalID
	}
	result := wire.Complete(nativeServer(), map[string]interface{}{
		"content":           []map[string]interface{}{{"type": "text", "text": text}},
		"structuredContent": structured,
		"isError":           false,
	})
	ext := extensionFor(code, op, uc)
	ext.Provenance = "not_dispatched"
	ext = h.signed(ctx, ext, op)
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: reqID, Result: withExtension(result, ext)}
}

// relayResult returns the source's observed result after the use case's
// response PII handling, with the allowed-outcome extension.
func (h *Handler) relayResult(ctx context.Context, reqID json.RawMessage, uc *useCase, op *action.Projection, res *action.ExecuteResult) *jsonrpcResponse {
	ctx, span := tracer.Start(ctx, "mcp.tools.result")
	defer span.End()
	var result map[string]interface{}
	if err := json.Unmarshal(res.Result, &result); err != nil || result == nil {
		// The dispatcher only reports success for a validated object; an
		// unreadable relay is reported, never invented.
		return h.withSignedReason(ctx, actionResponse(reqID, govcode.UpstreamOutcomeUnknown, publicOutcomeUnknown, op, uc))
	}
	result, resp := h.applyResponsePII(ctx, span, reqID, uc, op, result)
	if resp != nil {
		return resp
	}
	ext := govcode.Allowed(nil)
	fillLocators(&ext, op, uc)
	ext.Provenance = "observed"
	ext = h.signed(ctx, ext, op)
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: reqID, Result: withExtension(result, ext)}
}

// ---- governance extension for action outcomes ----------------------------

// publicOutcomeUnknown is the fixed message of an unknown action outcome.
const publicOutcomeUnknown = "The business system may or may not have performed the action; Talon recorded the outcome as unknown and will not execute this operation again. Reconcile it with the business system."

// extensionFor builds the extension of an action outcome with the scoped
// locators of its operation.
func extensionFor(code string, op *action.Projection, uc *useCase) govcode.Extension {
	ext, err := govcode.New(code)
	if err != nil {
		ext = govcode.Must(govcode.StoreUnavailable)
	}
	fillLocators(&ext, op, uc)
	switch {
	case ext.Decision == govcode.DecisionUnknown:
		ext.Provenance = "unknown"
	case op != nil && op.LatestAttempt != nil && op.LatestAttempt.RequestWritten:
		ext.Provenance = "observed"
	default:
		ext.Provenance = "not_dispatched"
	}
	if code == govcode.ApprovalPending {
		ext.RetryAfterMs = 30_000
	}
	return ext
}

func fillLocators(ext *govcode.Extension, op *action.Projection, uc *useCase) {
	if uc != nil {
		ext.Generation = uc.generation()
	}
	if op == nil {
		return
	}
	ext.OperationID, ext.OperationRef = op.OperationID, op.OperationRef
	if op.Approval != nil {
		ext.ApprovalID = op.Approval.ID
	}
	if op.LatestAttempt != nil {
		ext.AttemptID = op.LatestAttempt.ID
	}
	ext.Evidence = op.Evidence
}

// actionResponse is the JSON-RPC error of an action outcome. The Action
// Gateway owns its evidence: a refusal it did not record (a poll of a
// pending approval, an unknown operation id) carries no evidence reference
// and is NOT turned into evidence_commit_failed.
func actionResponse(reqID json.RawMessage, code, msg string, op *action.Projection, uc *useCase) *jsonrpcResponse {
	ext := extensionFor(code, op, uc)
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: reqID, Error: &rpcError{Code: codeServerError, Message: govcode.Bounded(msg), Data: governanceData(ext, "")}}
}

// withSignedReason replaces an error extension's reasonCode with the
// referenced lifecycle record's actual primary explanation.
func (h *Handler) withSignedReason(ctx context.Context, resp *jsonrpcResponse) *jsonrpcResponse {
	if resp == nil || resp.Error == nil {
		return resp
	}
	data, ok := resp.Error.Data.(map[string]any)
	if !ok {
		return resp
	}
	ext, ok := data[govcode.ExtensionID].(govcode.Extension)
	if !ok || ext.Evidence == nil || !ext.Evidence.Committed {
		return resp
	}
	data[govcode.ExtensionID] = ext.WithEvidence(ext.Evidence, h.recordReason(ctx, ext.Evidence.ID))
	return resp
}

// signed attaches the projection's evidence reference with the record's
// actual primary explanation.
func (h *Handler) signed(ctx context.Context, ext govcode.Extension, op *action.Projection) govcode.Extension {
	if op == nil || op.Evidence == nil {
		return ext
	}
	return ext.WithEvidence(op.Evidence, h.recordReason(ctx, op.Evidence.ID))
}

// recordReason reads the committed record's primary explanation code so the
// in-band reason never disagrees with what was signed.
func (h *Handler) recordReason(ctx context.Context, id string) string {
	if h.evidenceStore == nil || id == "" {
		return ""
	}
	ev, err := h.evidenceStore.Get(ctx, id)
	if err != nil {
		return ""
	}
	return primaryExplanation(ev)
}

// withExtension attaches ext to a result's _meta, keeping every existing
// _meta key (serverInfo, upstreamServerInfo, vendor keys).
func withExtension(result map[string]interface{}, ext govcode.Extension) map[string]interface{} {
	meta, _ := result["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta[govcode.ExtensionID] = ext
	result["_meta"] = meta
	return result
}

// ---- PII: the use case's effective policy, before binding and on results --

// applyRequestPII applies the use case's effective pii_action to the tool
// arguments BEFORE they are bound: block refuses with zero dispatch,
// redact binds (and approval covers, and Talon dispatches) the redacted
// arguments, warn and allow pass them unchanged. A scanner failure fails
// closed.
//
//nolint:gocyclo // one decision per PII outcome, each evidenced
func (h *Handler) applyRequestPII(ctx context.Context, span trace.Span, reqID json.RawMessage, uc *useCase, toolName string, args json.RawMessage, flow *serverFlowState) (json.RawMessage, *jsonrpcResponse) {
	mode, cls := uc.pii.Request, uc.pii.Classifier
	if cls == nil || mode == "" || mode == "allow" || uc.svc == nil {
		return args, nil
	}
	hc := h.forCall(cls, uc.attr)
	policyVersion := uc.svc.Policy.Digest
	tenantID, agentID := uc.svc.TenantID, uc.svc.AgentID
	argStr := string(args)
	res, scanErr := cls.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
	if scanErr != nil {
		flow.argBlocked = true
		return nil, hc.scannerBlockedResponse(ctx, span, reqID, tenantID, agentID, toolName, policyVersion,
			scanErr, "scanner_unavailable", "scanner unavailable", "Tool arguments blocked: PII scanner unavailable (fail-closed)", explanation.StagePolicyEvaluation, 0, flow)
	}
	flow.argTier = res.Tier
	if !res.HasPII {
		return args, nil
	}
	flow.argEntities = applyServerFlowFieldPath(classifier.MergeEntitySpans(argStr, res.Entities), "arguments")
	switch mode {
	case "warn":
		log.Info().Str("tool", toolName).Str("agent", agentID).Msg("mcp_arguments_pii_warn")
		return args, nil
	case "block":
		flow.argBlocked = true
		return nil, hc.piiRefusal(ctx, span, reqID, piiSubject{tenantID, agentID, toolName, policyVersion}, "request_pii_blocked", explanation.CodePolicyDeniedPIIInput,
			"Tool arguments blocked: the AI use case's PII policy blocks recognized personal data", flow, true)
	}
	redacted, redactErr := cls.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), argStr)
	if redactErr != nil {
		flow.argBlocked = true
		return nil, hc.scannerBlockedResponse(ctx, span, reqID, tenantID, agentID, toolName, policyVersion,
			redactErr, "scanner_unavailable", "redaction failed: scanner unavailable", "Tool arguments blocked: PII redaction failed (fail-closed)", explanation.StagePolicyEvaluation, 0, flow)
	}
	if verifyErr := cls.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionRequest), redacted); verifyErr != nil {
		flow.argBlocked = true
		if !errors.Is(verifyErr, classifier.ErrPIIDetected) {
			return nil, hc.scannerBlockedResponse(ctx, span, reqID, tenantID, agentID, toolName, policyVersion,
				verifyErr, "request_redaction_verification_scanner_unavailable", "request redaction verification failed: scanner unavailable",
				"Tool arguments blocked: redaction could not be verified (fail-closed)", explanation.StagePolicyEvaluation, 0, flow)
		}
		return nil, hc.piiRefusal(ctx, span, reqID, piiSubject{tenantID, agentID, toolName, policyVersion}, "request_residual_pii_after_redaction", explanation.CodePolicyDeniedPIIInput,
			mcpResidualBlockMessage("Tool arguments blocked: recognized PII remains after redaction", classifier.ResidualTypes(verifyErr)), flow, true)
	}
	if !json.Valid([]byte(redacted)) {
		flow.argBlocked = true
		return nil, hc.piiRefusal(ctx, span, reqID, piiSubject{tenantID, agentID, toolName, policyVersion}, "request_redaction_invalid_json", explanation.CodeExecutionFailed,
			"PII redaction produced invalid JSON (fail-closed)", flow, true)
	}
	flow.argRedacted = redacted != argStr
	if flow.argRedacted {
		// The redaction is a governed transformation of what will be bound
		// and sent: record it (digests only, never values) before binding.
		ev := hc.newServerEvidence(tenantID, agentID, "mcp_"+uuid.New().String()[:8], toolName, evidence.PolicyDecision{
			Allowed: true, Action: "allow", Reasons: []string{"request_pii_redacted"}, PolicyVersion: policyVersion,
		}, "", 0, flow)
		ev.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
			Code: explanation.CodePolicyAllowed, Decision: explanation.DecisionAllow, Stage: explanation.StagePolicyEvaluation,
			Trigger: "request_pii_redacted", PolicyRef: explanation.PolicyRef(policyVersion), VersionIdentity: policyVersion,
		}})
		if out := commitEvidence(ctx, h.evidenceStore, span, ev); !out.committed() {
			return nil, governedError(reqID, govcode.EvidenceCommitFailed, publicEvidenceCommitFailed, out, "", true)
		}
	}
	return json.RawMessage(redacted), nil
}

// applyResponsePII applies the use case's effective response_pii_action to
// the source's result. The effect already happened: a block withholds the
// result from the client and is reported with observed provenance; it
// never relabels the operation.
//
//nolint:gocyclo // one decision per PII outcome, each evidenced
func (h *Handler) applyResponsePII(ctx context.Context, span trace.Span, reqID json.RawMessage, uc *useCase, op *action.Projection, result map[string]interface{}) (map[string]interface{}, *jsonrpcResponse) {
	mode, cls := uc.pii.Response, uc.pii.Classifier
	if cls == nil || mode == "" || mode == "allow" {
		return result, nil
	}
	hc := h.forCall(cls, uc.attr)
	flow := &serverFlowState{}
	subject := piiSubject{uc.svc.TenantID, uc.svc.AgentID, op.Action, uc.svc.Policy.Digest}
	meta := result["_meta"]
	delete(result, "_meta")
	body, _ := json.Marshal(result)
	restore := func(m map[string]interface{}) map[string]interface{} {
		if meta != nil {
			m["_meta"] = meta
		}
		return m
	}
	blocked := func(trigger, msg string) (map[string]interface{}, *jsonrpcResponse) {
		flow.resultBlocked = true
		return nil, hc.piiRefusal(ctx, span, reqID, subject, trigger, explanation.CodePolicyDeniedPIIOutput, msg, flow, false).withOperation(op, uc)
	}
	scanFailed := func(err error, evReason, msg string) (map[string]interface{}, *jsonrpcResponse) {
		flow.resultBlocked = true
		return nil, hc.scannerBlockedResponse(ctx, span, reqID, subject.tenantID, subject.agentID, subject.toolName, subject.policyVersion,
			err, "output_scanner_unavailable", evReason, msg, explanation.StageOutputValidation, 0, flow).withOperation(op, uc)
	}
	res, scanErr := cls.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), string(body))
	if scanErr != nil {
		return scanFailed(scanErr, "output scanner unavailable", "Tool result withheld: PII scanner unavailable (fail-closed); the action itself was executed")
	}
	flow.resultTier = res.Tier
	if !res.HasPII {
		return restore(result), nil
	}
	flow.resultEntities = applyServerFlowFieldPath(classifier.MergeEntitySpans(string(body), res.Entities), "result")
	switch mode {
	case "warn":
		log.Info().Str("tool", subject.toolName).Str("agent", subject.agentID).Msg("mcp_result_pii_warn")
		return restore(result), nil
	case "block":
		return blocked("output_pii_blocked", "Tool result withheld: the AI use case's PII policy blocks recognized personal data; the action itself was executed")
	}
	redacted, redactErr := cls.RedactText(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), string(body))
	if redactErr != nil {
		return scanFailed(redactErr, "output redaction failed: scanner unavailable", "Tool result withheld: PII redaction failed (fail-closed); the action itself was executed")
	}
	if verifyErr := cls.VerifyEgress(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), redacted); verifyErr != nil {
		return blocked("output_pii_blocked_residual", mcpResidualBlockMessage("Tool result withheld: recognized PII remains after redaction", classifier.ResidualTypes(verifyErr)))
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(redacted), &out); err != nil || out == nil {
		return blocked("output_redaction_invalid_json", "Tool result withheld: PII redaction produced invalid JSON; the action itself was executed")
	}
	flow.resultRedacted = true
	ev := hc.newServerEvidence(subject.tenantID, subject.agentID, op.OperationRef, subject.toolName, evidence.PolicyDecision{
		Allowed: true, Action: "allow", Reasons: []string{"output_pii_redacted"}, PolicyVersion: subject.policyVersion,
	}, "", 0, flow)
	ev.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
		Code: explanation.CodePolicyAllowed, Decision: explanation.DecisionAllow, Stage: explanation.StageOutputValidation,
		Trigger: "output_pii_redacted", PolicyRef: explanation.PolicyRef(subject.policyVersion), VersionIdentity: subject.policyVersion,
	}})
	_ = commitEvidence(ctx, h.evidenceStore, span, ev) // post-effect: a failed commit is logged, never relabelled
	return restore(out), nil
}

// piiSubject is who and what a PII record is about.
type piiSubject struct {
	tenantID, agentID, toolName, policyVersion string
}

// piiRefusal records and answers a PII refusal of the adapter.
func (h *Handler) piiRefusal(ctx context.Context, span trace.Span, reqID json.RawMessage, s piiSubject, trigger, explCode, msg string, flow *serverFlowState, preDispatch bool) *jsonrpcResponse {
	stage := explanation.StagePolicyEvaluation
	if !preDispatch {
		stage = explanation.StageOutputValidation
	}
	ev := h.newServerEvidence(s.tenantID, s.agentID, "mcp_"+uuid.New().String()[:8], s.toolName, evidence.PolicyDecision{
		Allowed: false, Action: "deny", Reasons: []string{trigger}, PolicyVersion: s.policyVersion,
	}, trigger, 0, flow)
	decision := explanation.DecisionDeny
	if explCode == explanation.CodeExecutionFailed {
		decision = explanation.DecisionFailure
	}
	ev.Explanations = explanation.BuildFromFacts([]explanation.Fact{{
		Code: explCode, Decision: decision, Stage: stage, Trigger: trigger,
		PolicyRef: explanation.PolicyRef(s.policyVersion), VersionIdentity: s.policyVersion,
	}})
	return governedError(reqID, govcode.PIIPolicyViolation, msg, commitEvidence(ctx, h.evidenceStore, span, ev), "", preDispatch)
}

// withOperation adds the operation's locators to a post-effect refusal so
// the client can still reconcile it (the operation succeeded).
func (r *jsonrpcResponse) withOperation(op *action.Projection, uc *useCase) *jsonrpcResponse {
	if r == nil || r.Error == nil || op == nil {
		return r
	}
	data, ok := r.Error.Data.(map[string]any)
	if !ok {
		return r
	}
	ext, ok := data[govcode.ExtensionID].(govcode.Extension)
	if !ok {
		return r
	}
	ev := ext.Evidence
	fillLocators(&ext, op, uc)
	ext.Evidence = ev
	ext.Provenance = "observed"
	data[govcode.ExtensionID] = ext
	return r
}

// forCall is the handler for one request: the use case's scanner and the
// request's attribution for the evidence and data-flow helpers.
func (h *Handler) forCall(cls classifier.Facade, attr *action.Attribution) *Handler {
	c := *h
	c.classifier, c.attr = cls, attr
	return &c
}

// evidenceTime is the clock of the adapter's own records.
var evidenceTime = time.Now

func mcpResidualBlockMessage(prefix string, types []string) string {
	remediation := " Remediation required: use approval workflow to adjust policy or content, re-run redaction, then re-scan."
	if len(types) == 0 {
		return prefix + "." + remediation
	}
	return prefix + " (types: " + strings.Join(types, ", ") + ")." + remediation
}

// serverFlowState and buildServerDataFlow describe what the adapter's own
// PII records saw: the tool arguments that would reach the governed tool and
// the classified result surfaced back to the MCP client. Digests only, never
// raw values.
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
			Kind: evidence.FlowDestMCPTool,
			Name: toolName,
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
	// A scan failure before execution is pre-dispatch (an uncommitted
	// record refuses the call as evidence_commit_failed); after execution
	// the effect happened and the code must stay scanner_unavailable.
	preDispatch := stage == explanation.StagePolicyEvaluation
	return governedError(reqID, govcode.ScannerUnavailable, clientMsg, commitEvidence(ctx, h.evidenceStore, span, blockEv), "", preDispatch)
}

func (h *Handler) newServerEvidence(
	tenantID, agentID, correlationID, toolName string,
	decision evidence.PolicyDecision,
	execErr string,
	durationMS int64,
	flow *serverFlowState,
) *evidence.Evidence {
	if h.attr != nil && h.attr.CorrelationID != "" && strings.HasPrefix(correlationID, "mcp_") {
		correlationID = h.attr.CorrelationID // the client's own reference for an adapter record
	}
	ev := &evidence.Evidence{
		ID:              "req_" + uuid.New().String()[:8],
		CorrelationID:   correlationID,
		Timestamp:       evidenceTime(),
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
	if h.attr != nil {
		ev.SessionID = h.attr.SessionID
		if h.attr.Orchestration != nil {
			o := *h.attr.Orchestration
			ev.Orchestration = &o
		}
	}
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

// scannerFailureKind is the typed scan-engine failure a record keeps.
func scannerFailureKind(err error) string {
	if kind := adapter.FailureKind(err); kind != "" {
		return kind
	}
	return "scanner_unavailable"
}

// entityTypeSet is the sorted set of detected PII types (types only).
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

// attributionHeaders are the client-asserted attribution headers the
// governed route validates and links to an operation (#431): the same
// neutral X-Talon-* set and hygiene (128-byte cap, token charset, reject
// rather than truncate) as the gateway.
var attributionHeaders = []string{"X-Talon-Session-ID", "X-Correlation-ID", "X-Talon-Agent-ID", "X-Talon-Parent-Agent-ID", "X-Talon-Client"}

// attributionFrom validates the request's attribution headers. nil when the
// client asserted none. Attribution is never authentication.
func attributionFrom(r *http.Request) (*action.Attribution, error) {
	vals := make(map[string]string, len(attributionHeaders))
	asserted := false
	for _, name := range attributionHeaders {
		v, err := evidence.ValidateOrchValue(name, r.Header.Get(name))
		if err != nil {
			return nil, err
		}
		vals[name] = v
		asserted = asserted || v != ""
	}
	if !asserted {
		return nil, nil
	}
	a := &action.Attribution{SessionID: vals["X-Talon-Session-ID"], CorrelationID: vals["X-Correlation-ID"]}
	sub, parent, client := vals["X-Talon-Agent-ID"], vals["X-Talon-Parent-Agent-ID"], vals["X-Talon-Client"]
	if sub != "" || parent != "" || client != "" {
		if client == "" {
			client = "generic"
		}
		source := ""
		if a.SessionID != "" {
			source = "client_asserted"
		}
		a.Orchestration = &evidence.OrchestrationContext{SessionID: a.SessionID, AgentID: sub, ParentAgentID: parent, Client: client, SessionSource: source, Provenance: "client_asserted"}
	}
	return a, nil
}

// echoAttribution returns the asserted session and correlation ids, so a
// client can join its own log to Talon's records.
func echoAttribution(w http.ResponseWriter, a *action.Attribution) {
	if a == nil {
		return
	}
	if a.SessionID != "" {
		w.Header().Set("X-Talon-Session-ID", a.SessionID)
	}
	if a.CorrelationID != "" {
		w.Header().Set("X-Correlation-ID", a.CorrelationID)
	}
}

type attributionKey struct{}

func withAttribution(ctx context.Context, a *action.Attribution) context.Context {
	if a == nil {
		return ctx
	}
	return context.WithValue(ctx, attributionKey{}, a)
}

func attributionOf(ctx context.Context) *action.Attribution {
	a, _ := ctx.Value(attributionKey{}).(*action.Attribution)
	return a
}

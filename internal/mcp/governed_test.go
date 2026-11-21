package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/action/mcpsource"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/govcode"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
)

// The governed MCP route (#431) end to end inside one process: a real MCP
// server (the official Go SDK, 2026-07-28) is the trusted source; its tools
// are discovered into the use case's action catalog; every tools/call on
// POST /mcp is an operation of the canonical Action Gateway service; the
// source counts every tools/call it actually receives.

const (
	govSigningKey = "governed-mcp-test-signing-key-0123456789"
	govVaultKey   = "0123456789abcdef0123456789abcdef"
)

type toolBehaviour func(args map[string]any) (*sdk.CallToolResult, error)

type govSource struct {
	srv    *httptest.Server
	calls  map[string]*atomic.Int64
	args   map[string]*atomic.Value
	behave map[string]*atomic.Value // toolBehaviour
}

func okText(text string) toolBehaviour {
	return func(map[string]any) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: text}}}, nil
	}
}

func newGovSource(t *testing.T) *govSource {
	t.Helper()
	g := &govSource{calls: map[string]*atomic.Int64{}, args: map[string]*atomic.Value{}, behave: map[string]*atomic.Value{}}
	srv := sdk.NewServer(&sdk.Implementation{Name: "crm", Version: "1.0.0"}, &sdk.ServerOptions{
		SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs, c.CacheScope = 60000, "public" },
	})
	str := map[string]any{"type": "string"}
	tools := map[string]map[string]any{
		"refund.create":   {"ticket_id": str, "amount": map[string]any{"type": "number"}},
		"voucher.send":    {"ticket_id": str, "amount": map[string]any{"type": "number"}, "note": str},
		"ticket.lookup":   {"ticket_id": str},
		"customer.delete": {"customer_id": str},
	}
	for name, props := range tools {
		name := name
		g.calls[name], g.args[name], g.behave[name] = &atomic.Int64{}, &atomic.Value{}, &atomic.Value{}
		g.behave[name].Store(okText(name + " done"))
		srv.AddTool(&sdk.Tool{Name: name, InputSchema: map[string]any{"type": "object", "properties": props}}, func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			g.calls[name].Add(1)
			var args map[string]any
			_ = json.Unmarshal(req.Params.Arguments, &args)
			g.args[name].Store(args)
			return g.behave[name].Load().(toolBehaviour)(args)
		})
	}
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, &sdk.StreamableHTTPOptions{Stateless: true})
	g.srv = httptest.NewServer(h)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *govSource) count(tool string) int64 { return g.calls[tool].Load() }

type govFixture struct {
	src     *govSource
	svc     *action.Service
	store   *evidence.Store
	handler *Handler
	pii     UseCasePII
	id      requestctx.AgentIdentity
	seq     atomic.Int64
}

func newGovFixture(t *testing.T) *govFixture {
	t.Helper()
	ctx := context.Background()
	f := &govFixture{src: newGovSource(t), id: requestctx.AgentIdentity{AgentID: "support-bot", TenantID: "acme", Generation: "gen-test-0123456789"}}
	field := func(fields ...string) *policy.ActionReviewConfig { return &policy.ActionReviewConfig{Fields: fields} }
	actions := &policy.ActionsConfig{
		Sources: map[string]policy.ActionSourceConfig{"crm": {Type: "mcp", URL: f.src.srv.URL}},
		Definitions: map[string]policy.ActionDefinitionConfig{
			"create_refund":   {Source: "crm", UpstreamName: "refund.create", Review: field("amount", "ticket_id")},
			"send_voucher":    {Source: "crm", UpstreamName: "voucher.send", Review: &policy.ActionReviewConfig{Fields: []string{"amount", "ticket_id"}, NonMaterial: []string{"note"}}},
			"lookup_ticket":   {Source: "crm", UpstreamName: "ticket.lookup", ReadOnly: true, Review: field("ticket_id")},
			"delete_customer": {Source: "crm", UpstreamName: "customer.delete", Review: field("customer_id")},
		},
	}
	snap, err := mcpsource.New(nil).Discover(ctx, "acme", "support-bot", "crm", actions.Sources["crm"])
	require.NoError(t, err)
	cat, err := action.CompileCatalog(actions, map[string]*action.SourceSnapshot{"crm": snap})
	require.NoError(t, err)
	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "support-bot", TenantID: "acme"},
		Capabilities: &policy.CapabilitiesConfig{ForbiddenTools: []string{"delete_customer"}},
		Actions:      actions,
		Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{ExpiresAfter: "30m", Rules: map[string]policy.ApprovalRuleConfig{
			"refunds": {Actions: []string{"create_refund"}, ApproverGroups: []string{"support-leads"}},
		}}},
	}
	ap, err := action.CompileApprovalPolicy(pol)
	require.NoError(t, err)
	f.store, err = evidence.NewStore(filepath.Join(t.TempDir(), "evidence.db"), govSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.store.Close() })
	repo, err := action.NewRepository(ctx, f.store.DB())
	require.NoError(t, err)
	cryptor, err := action.NewPayloadCryptor(govVaultKey)
	require.NoError(t, err)
	disp := action.NewMCPDispatcher(nil, nil, "test")
	disp.Timeout = 2 * time.Second
	f.svc, err = action.NewService("acme", "support-bot", cat, ap, repo, f.store, action.Dispatchers{action.DestinationTypeMCP: disp}, cryptor)
	require.NoError(t, err)
	f.handler = NewHandler(Config{
		Services: func(id requestctx.AgentIdentity) (*action.Service, error) { return f.svc, nil },
		PII:      func(requestctx.AgentIdentity) UseCasePII { return f.pii },
		Evidence: f.store,
	})
	return f
}

// rpc sends one JSON-RPC request to POST /mcp as the use case and decodes
// the answer.
func (f *govFixture) rpc(t *testing.T, method string, params map[string]any) (status int, out map[string]any) {
	t.Helper()
	body := mcpBody(t, f.seq.Add(1), method, params)
	req := stamp(httptest.NewRequestWithContext(requestctx.SetAgentIdentity(context.Background(), f.id), http.MethodPost, "/mcp", bytes.NewReader(body)))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	return rec.Code, out
}

func (f *govFixture) call(t *testing.T, tool string, args map[string]any, meta ...map[string]any) (status int, out map[string]any) {
	t.Helper()
	params := map[string]any{"name": tool, "arguments": args}
	if len(meta) > 0 {
		m := testMeta()
		for k, v := range meta[0] {
			m[k] = v
		}
		params["_meta"] = m
	}
	return f.rpc(t, wire.MethodToolsCall, params)
}

func (f *govFixture) execute(t *testing.T, opID string) (status int, out map[string]any) {
	t.Helper()
	return f.call(t, ExecuteToolName, map[string]any{"operation_id": opID})
}

// verified checks the operation's signed lifecycle cryptographically and
// semantically, as `talon audit verify --operation` does.
func (f *govFixture) verified(t *testing.T, opID string) action.Finding {
	t.Helper()
	recs, err := f.svc.ListLifecycle(context.Background(), opID)
	require.NoError(t, err)
	return action.VerifyLifecycle(recs, f.store.VerifyRecord)
}

// ext returns the governance extension of a result or an error.
func ext(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	if e, ok := out["error"].(map[string]any); ok {
		data, _ := e["data"].(map[string]any)
		x, _ := data[govcode.ExtensionID].(map[string]any)
		require.NotNil(t, x, "error without governance extension: %v", out)
		return x
	}
	res, _ := out["result"].(map[string]any)
	meta, _ := res["_meta"].(map[string]any)
	x, _ := meta[govcode.ExtensionID].(map[string]any)
	require.NotNil(t, x, "result without governance extension: %v", out)
	return x
}

func result(out map[string]any) map[string]any { r, _ := out["result"].(map[string]any); return r }

func TestGoverned_ListProjectsTheUseCaseCatalog(t *testing.T) {
	f := newGovFixture(t)
	code, out := f.rpc(t, wire.MethodToolsList, nil)
	require.Equal(t, http.StatusOK, code)
	tools, _ := result(out)["tools"].([]any)
	byName := map[string]map[string]any{}
	for _, raw := range tools {
		tool := raw.(map[string]any)
		byName[tool["name"].(string)] = tool
	}
	assert.ElementsMatch(t, []string{"create_refund", "lookup_ticket", "send_voucher", ExecuteToolName}, keys(byName),
		"canonical names; the forbidden tool is hidden; approval-required stays discoverable")
	assert.Equal(t, true, byName["lookup_ticket"]["annotations"].(map[string]any)["readOnlyHint"])
	assert.Contains(t, byName["send_voucher"]["description"], "only PREPARES")
	schema := byName["send_voucher"]["inputSchema"].(map[string]any)
	assert.Equal(t, false, schema["additionalProperties"], "the closed schema Talon validates against")
	for _, tool := range f.src.calls {
		assert.Zero(t, tool.Load(), "listing calls nothing")
	}
}

func keys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The two-call flow of an unmodified client: the first call prepares, the
// second executes once, a repeat never executes again.
func TestGoverned_PrepareThenExecuteOnce(t *testing.T) {
	f := newGovFixture(t)
	code, out := f.call(t, "send_voucher", map[string]any{"ticket_id": "T-1", "amount": 20})
	require.Equal(t, http.StatusOK, code, out)
	res := result(out)
	require.NotNil(t, res, out)
	assert.Equal(t, false, res["isError"])
	sc := res["structuredContent"].(map[string]any)
	opID := sc["operationId"].(string)
	assert.True(t, strings.HasPrefix(opID, "mcp-"), "a durable Talon-generated operation id")
	assert.Equal(t, action.OpAuthorized, sc["status"])
	x := ext(t, out)
	assert.Equal(t, govcode.OperationPrepared, x["code"])
	assert.Equal(t, "not_dispatched", x["provenance"])
	assert.Equal(t, opID, x["operationId"])
	assert.Equal(t, true, x["evidence"].(map[string]any)["committed"])
	assert.Zero(t, f.src.count("voucher.send"), "preparation never dispatches")

	code, out = f.execute(t, opID)
	require.Equal(t, http.StatusOK, code)
	res = result(out)
	require.NotNil(t, res, out)
	assert.Contains(t, mustJSON(t, res["content"]), "voucher.send done")
	x = ext(t, out)
	assert.Equal(t, govcode.Allowed(nil).Code, x["code"])
	assert.Equal(t, "observed", x["provenance"])
	assert.Equal(t, opID, x["operationId"])
	assert.NotEmpty(t, x["attemptId"])
	assert.Equal(t, "ACTION_ATTEMPT_SUCCEEDED", x["reasonCode"], "the in-band reason is the signed record's")
	assert.EqualValues(t, 1, f.src.count("voucher.send"))

	_, out = f.execute(t, opID)
	assert.Equal(t, govcode.OperationAlreadySucceeded, ext(t, out)["code"])
	_, out = f.call(t, "send_voucher", map[string]any{"ticket_id": "T-1", "amount": 20})
	assert.Equal(t, govcode.OperationPrepared, ext(t, out)["code"], "the same call again only prepares a new operation")
	assert.EqualValues(t, 1, f.src.count("voucher.send"), "nothing was executed twice")
	assert.Equal(t, action.LifecycleValid, f.verified(t, opID).Verdict)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// A read-only action (trusted `read_only: true`) that policy allows runs in
// one call, still as an Action Gateway operation.
func TestGoverned_ReadOnlyToolIsOneCall(t *testing.T) {
	f := newGovFixture(t)
	code, out := f.call(t, "lookup_ticket", map[string]any{"ticket_id": "T-9"})
	require.Equal(t, http.StatusOK, code)
	assert.Contains(t, mustJSON(t, result(out)["content"]), "ticket.lookup done")
	x := ext(t, out)
	assert.Equal(t, "observed", x["provenance"])
	assert.EqualValues(t, 1, f.src.count("ticket.lookup"))
	assert.Equal(t, action.LifecycleValid, f.verified(t, x["operationId"].(string)).Verdict)
}

// An advanced client sends its own stable operation id: one call executes;
// a retry resolves the same operation; changed arguments conflict.
func TestGoverned_CallerProvidedOperationID(t *testing.T) {
	f := newGovFixture(t)
	meta := map[string]any{MetaOperationID: "voucher-T-1"}
	_, out := f.call(t, "send_voucher", map[string]any{"ticket_id": "T-1", "amount": 20}, meta)
	require.NotNil(t, result(out), out)
	assert.Equal(t, "voucher-T-1", ext(t, out)["operationId"])
	assert.EqualValues(t, 1, f.src.count("voucher.send"))

	_, out = f.call(t, "send_voucher", map[string]any{"ticket_id": "T-1", "amount": 20}, meta)
	assert.Equal(t, govcode.OperationAlreadySucceeded, ext(t, out)["code"], "a retry never executes twice")
	_, out = f.call(t, "send_voucher", map[string]any{"ticket_id": "T-1", "amount": 900}, meta)
	assert.Equal(t, govcode.OperationConflict, ext(t, out)["code"], "changed arguments under the same id")
	assert.EqualValues(t, 1, f.src.count("voucher.send"))
	assert.Equal(t, action.LifecycleValid, f.verified(t, "voucher-T-1").Verdict)

	code, _ := f.call(t, "send_voucher", map[string]any{"ticket_id": "T-1", "amount": 20}, map[string]any{MetaOperationID: 7})
	assert.Equal(t, http.StatusBadRequest, code, "a malformed id is a protocol error")
}

// A hidden (forbidden) tool called directly is decided — and denied — by the
// Action Gateway, with evidence and zero upstream calls.
func TestGoverned_ForbiddenToolCalledDirectlyIsDeniedWithZeroCalls(t *testing.T) {
	f := newGovFixture(t)
	code, out := f.call(t, "delete_customer", map[string]any{"customer_id": "c-1"})
	require.Equal(t, http.StatusOK, code)
	x := ext(t, out)
	assert.Equal(t, govcode.PolicyDenied, x["code"])
	assert.Equal(t, "deny", x["decision"])
	assert.Equal(t, "not_dispatched", x["provenance"])
	assert.Equal(t, true, x["evidence"].(map[string]any)["committed"])
	assert.Zero(t, f.src.count("customer.delete"))
	assert.NotContains(t, mustJSON(t, out), "c-1", "argument values never appear in the denial")
	assert.Equal(t, action.LifecycleValid, f.verified(t, x["operationId"].(string)).Verdict)
}

// Approval-required: the prepared operation waits for a reviewer; executing
// before the approval dispatches nothing; the decision itself dispatches
// nothing; the next execute dispatches exactly once.
func TestGoverned_ApprovalContinuation(t *testing.T) {
	f := newGovFixture(t)
	_, out := f.call(t, "create_refund", map[string]any{"ticket_id": "T-2", "amount": 75})
	x := ext(t, out)
	require.Equal(t, govcode.ApprovalPending, x["code"], out)
	opID, approvalID := x["operationId"].(string), x["approvalId"].(string)
	assert.NotEmpty(t, approvalID)
	assert.Equal(t, false, result(out)["isError"], "a prepared operation is a normal result an unmodified client shows")

	_, out = f.execute(t, opID)
	x = ext(t, out)
	assert.Equal(t, govcode.ApprovalPending, x["code"])
	assert.Equal(t, true, x["retryable"])
	assert.Zero(t, f.src.count("refund.create"))

	_, err := f.svc.Decide(context.Background(), action.DecideRequest{ApprovalID: approvalID, Approve: true, Reason: "ok", Reviewer: action.ReviewerPrincipal{
		PrincipalID: "apr_ann", TenantScope: "acme", Subject: "ann", Groups: []string{"support-leads"}, CredentialID: "cred_ann", CredentialVersion: 1,
		Revalidate: func(context.Context) (bool, error) { return true, nil },
	}})
	require.NoError(t, err)
	assert.Zero(t, f.src.count("refund.create"), "the approval does not execute")

	_, out = f.execute(t, opID)
	require.NotNil(t, result(out), out)
	assert.EqualValues(t, 1, f.src.count("refund.create"))
	assert.Equal(t, action.LifecycleValid, f.verified(t, opID).Verdict)
}

func TestGoverned_ConcurrentExecutesDispatchOnce(t *testing.T) {
	f := newGovFixture(t)
	_, out := f.call(t, "send_voucher", map[string]any{"ticket_id": "T-3", "amount": 10})
	opID := ext(t, out)["operationId"].(string)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-gate; _, _ = f.execute(t, opID) }()
	}
	close(gate)
	wg.Wait()
	assert.EqualValues(t, 1, f.src.count("voucher.send"))
	assert.Equal(t, action.LifecycleValid, f.verified(t, opID).Verdict)
}

// An application error reported by the source after dispatch is unknown:
// the vendor's text is never relayed, nothing is retried, and a repeated
// execute is refused.
func TestGoverned_UpstreamErrorAfterDispatchIsUnknownAndNeverRetried(t *testing.T) {
	for name, b := range map[string]toolBehaviour{
		"tool error": func(map[string]any) (*sdk.CallToolResult, error) {
			return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "customer cust-77 jan@example.com locked"}}}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGovFixture(t)
			f.src.behave["voucher.send"].Store(b)
			_, out := f.call(t, "send_voucher", map[string]any{"ticket_id": "T-4", "amount": 10})
			opID := ext(t, out)["operationId"].(string)
			_, out = f.execute(t, opID)
			x := ext(t, out)
			assert.Equal(t, govcode.UpstreamOutcomeUnknown, x["code"])
			assert.Equal(t, "unknown", x["decision"])
			assert.Equal(t, "unknown", x["provenance"])
			assert.Equal(t, false, x["retryable"])
			assert.NotContains(t, mustJSON(t, out), "cust-77", "the vendor's text is never relayed")
			assert.EqualValues(t, 1, f.src.count("voucher.send"))
			_, out = f.execute(t, opID)
			assert.Equal(t, govcode.OperationOutcomeUnknown, ext(t, out)["code"])
			assert.EqualValues(t, 1, f.src.count("voucher.send"), "never re-sent")
			fd := f.verified(t, opID)
			assert.Equal(t, action.LifecycleValid, fd.Verdict, fd.Details)
			assert.Equal(t, action.OpUnknown, fd.FinalStatus)
		})
	}
}

func TestGoverned_RecoveryHoldRefusesDispatch(t *testing.T) {
	f := newGovFixture(t)
	_, out := f.call(t, "send_voucher", map[string]any{"ticket_id": "T-5", "amount": 10})
	opID := ext(t, out)["operationId"].(string)
	require.NoError(t, action.StampRecoveryHold(context.Background(), f.store.DB(), "bk_1", time.Now().Add(-time.Hour), "cfg"))
	_, out = f.execute(t, opID)
	assert.Equal(t, govcode.RecoveryHold, ext(t, out)["code"])
	assert.Zero(t, f.src.count("voucher.send"))
}

// PII under the use case's effective policy: block refuses before anything
// is bound (zero calls); redact binds — and dispatches — the redacted
// arguments; response_pii_action redacts the source's result.
func TestGoverned_PIIFollowsTheUseCasePolicy(t *testing.T) {
	email := "jan.kowalski@example.com"
	t.Run("block", func(t *testing.T) {
		f := newGovFixture(t)
		f.pii = UseCasePII{Request: "block", Classifier: classifier.MustNewScanner()}
		_, out := f.call(t, "send_voucher", map[string]any{"ticket_id": "T-6", "amount": 10, "note": "contact " + email})
		x := ext(t, out)
		assert.Equal(t, govcode.PIIPolicyViolation, x["code"])
		assert.Equal(t, true, x["evidence"].(map[string]any)["committed"])
		assert.Empty(t, x["operationId"], "nothing was bound")
		assert.Zero(t, f.src.count("voucher.send"))
	})
	t.Run("redact", func(t *testing.T) {
		f := newGovFixture(t)
		f.pii = UseCasePII{Request: "redact", Classifier: classifier.MustNewScanner()}
		_, out := f.call(t, "send_voucher", map[string]any{"ticket_id": "T-7", "amount": 10, "note": "contact " + email})
		opID := ext(t, out)["operationId"].(string)
		_, out = f.execute(t, opID)
		require.NotNil(t, result(out), out)
		sent, _ := f.src.args["voucher.send"].Load().(map[string]any)
		require.NotNil(t, sent)
		assert.NotContains(t, sent["note"], email, "the source receives what was bound: the redacted arguments")
		assert.EqualValues(t, 10, sent["amount"])
	})
	t.Run("response redact", func(t *testing.T) {
		f := newGovFixture(t)
		f.pii = UseCasePII{Response: "redact", Classifier: classifier.MustNewScanner()}
		f.src.behave["ticket.lookup"].Store(okText("owner " + email))
		_, out := f.call(t, "lookup_ticket", map[string]any{"ticket_id": "T-8"})
		require.NotNil(t, result(out), out)
		assert.NotContains(t, mustJSON(t, out), email)
		assert.EqualValues(t, 1, f.src.count("ticket.lookup"))
	})
	t.Run("response block withholds the result, not the effect", func(t *testing.T) {
		f := newGovFixture(t)
		f.pii = UseCasePII{Response: "block", Classifier: classifier.MustNewScanner()}
		f.src.behave["ticket.lookup"].Store(okText("owner " + email))
		_, out := f.call(t, "lookup_ticket", map[string]any{"ticket_id": "T-8"})
		x := ext(t, out)
		assert.Equal(t, govcode.PIIPolicyViolation, x["code"])
		assert.Equal(t, "observed", x["provenance"], "the action was executed")
		assert.NotEmpty(t, x["operationId"], "the client can still reconcile it")
		assert.NotContains(t, mustJSON(t, out), email)
	})
}

func TestGoverned_RequestFaults(t *testing.T) {
	f := newGovFixture(t)
	code, out := f.call(t, "no_such_tool", map[string]any{})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, float64(wire.CodeInvalidParams), out["error"].(map[string]any)["code"])

	code, _ = f.call(t, "send_voucher", map[string]any{"ticket_id": "T-1", "amount": "twenty"})
	assert.Equal(t, http.StatusBadRequest, code, "arguments that violate the schema bind nothing")

	code, _ = f.call(t, ExecuteToolName, map[string]any{"operation_id": "x", "extra": true})
	assert.Equal(t, http.StatusBadRequest, code)
	_, out = f.execute(t, "never-prepared")
	assert.Equal(t, govcode.NotFound, ext(t, out)["code"])

	// Without the use case's identity nothing is resolved.
	f.id = requestctx.AgentIdentity{}
	_, out = f.call(t, "send_voucher", map[string]any{"ticket_id": "T-1", "amount": 1})
	assert.Equal(t, govcode.AgentIdentityRequired, ext(t, out)["code"])
	for _, tool := range f.src.calls {
		assert.Zero(t, tool.Load())
	}
}

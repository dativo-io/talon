package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Stable business identity and restart recovery (mission §2.2): the agent
// addresses the same Talon operation for the same intent across restarts,
// resumes from the operation's real status, never creates a second refund,
// and reports unknown downstream outcomes as unresolved instead of
// retrying them. The Talon Action Gateway is stubbed with the documented
// HTTP contract; the model is a scripted provider on the OpenAI wire.

func TestOperationIDFor_StableAndCanonical(t *testing.T) {
	a := operationIDFor("run-1", "create_refund_request", json.RawMessage(`{"ticket_id":"T-1842","amount":50,"currency":"EUR"}`))
	b := operationIDFor("run-1", "create_refund_request", json.RawMessage(`{ "currency":"EUR", "amount": 50.0, "ticket_id": "T-1842" }`))
	if a != b {
		t.Fatalf("key order and spacing must not change the identity: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, "run-1-create_refund_request-") || len(a) != len("run-1-create_refund_request-")+12 {
		t.Fatalf("unexpected id shape: %s", a)
	}
	if operationIDFor("run-1", "create_refund_request", json.RawMessage(`{"ticket_id":"T-1842","amount":60,"currency":"EUR"}`)) == a {
		t.Fatal("a different amount is a different business intent")
	}
	if operationIDFor("run-2", "create_refund_request", json.RawMessage(`{"ticket_id":"T-1842","amount":50,"currency":"EUR"}`)) == a {
		t.Fatal("a different run prefix is a different intent")
	}
	long := operationIDFor(strings.Repeat("p", 200), "lookup_ticket", json.RawMessage(`{}`))
	if len(long) != 128 {
		t.Fatalf("ids are bounded to Talon's 128 characters, got %d", len(long))
	}
}

// stubGateway is the Action Gateway contract as the agent sees it through
// the hop: operations keyed by id, approvals, at-most-once dispatch
// counting, and a switch to make the next claim return "unknown".
type stubGateway struct {
	mu          sync.Mutex
	ops         map[string]*stubOp
	dispatches  map[string]int
	nextUnknown bool
	establishes int
	srv         *httptest.Server
}

type stubOp struct {
	id, action, status, approvalID, approvalStatus string
	args                                           json.RawMessage
}

func newStubGateway(t *testing.T) *stubGateway {
	t.Helper()
	g := &stubGateway{ops: map[string]*stubOp{}, dispatches: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/action-operations", g.establish)
	mux.HandleFunc("GET /v1/action-operations/{id}", g.get)
	mux.HandleFunc("POST /v1/action-operations/{id}/attempts", g.attempt)
	mux.HandleFunc("GET /v1/approvals/{id}", g.approval)
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *stubGateway) projection(op *stubOp) map[string]any {
	p := map[string]any{"operation_id": op.id, "operation_ref": "op_" + op.id, "action": op.action, "operation_status": op.status, "verdict": "ALLOW"}
	switch op.action {
	case "delete_customer":
		p["verdict"] = "DENY"
	case "create_refund_request":
		p["verdict"] = "REQUIRE_APPROVAL"
		p["approval"] = map[string]any{"id": op.approvalID, "status": op.approvalStatus}
	}
	return p
}

func (g *stubGateway) establish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OperationID string          `json:"operation_id"`
		Action      string          `json:"action"`
		Arguments   json.RawMessage `json:"arguments"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.establishes++
	if op, ok := g.ops[body.OperationID]; ok {
		if !bytes.Equal(canonicalJSON(op.args), canonicalJSON(body.Arguments)) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "operation_conflict"}})
			return
		}
		status := http.StatusOK
		if op.status == "denied" {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]any{"created": false, "operation": g.projection(op)})
		return
	}
	op := &stubOp{id: body.OperationID, action: body.Action, args: body.Arguments}
	switch body.Action {
	case "lookup_ticket":
		op.status = "authorized"
	case "delete_customer":
		op.status = "denied"
	case "create_refund_request":
		op.status, op.approvalID, op.approvalStatus = "awaiting_approval", "apr_"+body.OperationID[len(body.OperationID)-6:], "pending"
	}
	g.ops[op.id] = op
	switch op.status {
	case "denied":
		writeJSON(w, http.StatusForbidden, map[string]any{"created": true, "operation": g.projection(op)})
	case "awaiting_approval":
		writeJSON(w, http.StatusAccepted, map[string]any{"created": true, "operation": g.projection(op)})
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"created": true, "operation": g.projection(op)})
	}
}

func (g *stubGateway) get(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	op, ok := g.ops[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "operation_not_found"}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"operation": g.projection(op)})
}

func (g *stubGateway) attempt(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	op, ok := g.ops[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "operation_not_found"}})
		return
	}
	switch op.status {
	case "succeeded":
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "operation_already_succeeded"}})
	case "awaiting_approval":
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "approval_pending"}})
	case "denied":
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{"code": "policy_denied"}})
	case "unknown":
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "operation_outcome_unknown"}})
	case "authorized":
		g.dispatches[op.id]++ // the one downstream effect
		if g.nextUnknown && op.action == "create_refund_request" {
			g.nextUnknown = false
			op.status = "unknown"
			writeJSON(w, http.StatusOK, map[string]any{"attempt": map[string]any{"status": "unknown"}})
			return
		}
		op.status = "succeeded"
		writeJSON(w, http.StatusOK, map[string]any{"attempt": map[string]any{"status": "succeeded", "result": map[string]any{"ok": true}}})
	default:
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "operation_not_claimable"}})
	}
}

func (g *stubGateway) approval(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, op := range g.ops {
		if op.approvalID == r.PathValue("id") {
			writeJSON(w, http.StatusOK, map[string]any{"approval": map[string]any{"id": op.approvalID, "status": op.approvalStatus}})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "approval_not_found"}})
}

// decide is the reviewer acting from outside the sandbox.
func (g *stubGateway) decide(approve bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, op := range g.ops {
		if op.approvalStatus == "pending" {
			if approve {
				op.approvalStatus, op.status = "approved", "authorized"
			} else {
				op.approvalStatus, op.status = "rejected", "cancelled"
			}
		}
	}
}

func (g *stubGateway) refundDispatches() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for id, c := range g.dispatches {
		if strings.Contains(id, "create_refund_request") {
			n += c
		}
	}
	return n
}

func (g *stubGateway) refundOps() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, op := range g.ops {
		if op.action == "create_refund_request" {
			n++
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// stubModel is the scripted provider: lookup → delete → refund → answer,
// keyed by how many tool results the conversation already carries.
func stubModel(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []map[string]any `json:"messages"`
		}
		_ = json.Unmarshal(raw, &req)
		n := 0
		for _, m := range req.Messages {
			if m["role"] == "tool" {
				n++
			}
		}
		var msg string
		switch n {
		case 0:
			msg = `{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"lookup_ticket","arguments":"{\"ticket_id\":\"T-1842\"}"}}]}`
		case 1:
			msg = `{"role":"assistant","content":null,"tool_calls":[{"id":"c2","type":"function","function":{"name":"delete_customer","arguments":"{\"customer_id\":\"c-9\"}"}}]}`
		case 2:
			msg = `{"role":"assistant","content":null,"tool_calls":[{"id":"c3","type":"function","function":{"name":"create_refund_request","arguments":"{\"ticket_id\":\"T-1842\",\"amount\":50,\"currency\":\"EUR\"}"}}]}`
		default:
			msg = `{"role":"assistant","content":"Done."}`
		}
		finish := "tool_calls"
		if n >= 3 {
			finish = "stop"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"c","object":"chat.completion","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"message":%s,"finish_reason":"%s"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`, msg, finish)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testConfig(t *testing.T, gw *stubGateway, model *httptest.Server, wait time.Duration) config {
	t.Helper()
	return config{
		talonBase: gw.srv.URL, providerBase: model.URL, session: "sess-test", opPrefix: "run-7", ticketID: "T-1842",
		model: "gpt-4o-mini", apiKey: "placeholder", wait: wait, maxTurns: 8, stateDir: filepath.Join(t.TempDir(), "state"),
		adversarial: true, pollInterval: 20 * time.Millisecond,
	}
}

// approveWhenAsked approves the pending approval once the agent has
// reported it (the reviewer acts from outside, after the request exists).
func approveWhenAsked(t *testing.T, gw *stubGateway, out *syncBuffer, approve bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "APPROVAL_ID=") {
			gw.decide(approve)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the agent never asked for approval:\n%s", out.String())
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestRun_HappyPathAndAdversarialProbe(t *testing.T) {
	gw, model := newStubGateway(t), stubModel(t)
	cfg := testConfig(t, gw, model, 5*time.Second)
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(context.Background(), cfg, out) }()
	approveWhenAsked(t, gw, out, true)
	if code := <-done; code != exitOK {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	for _, want := range []string{"ATTEMPT=succeeded TOOL=lookup_ticket", "DENIED=delete_customer", "APPROVAL=approved", "ATTEMPT=succeeded TOOL=create_refund_request", "REPLAY=operation_already_succeeded", "ADVERSARIAL=denied TOOL=delete_customer", "RESULT=succeeded"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q:\n%s", want, out.String())
		}
	}
	if gw.refundDispatches() != 1 || gw.refundOps() != 1 {
		t.Fatalf("refund dispatches=%d ops=%d", gw.refundDispatches(), gw.refundOps())
	}
}

// Restart while awaiting approval: the first process times out, the
// reviewer approves, the second process addresses the SAME operation,
// resumes from "authorized" and claims once. No second refund exists.
func TestRun_RestartWhileAwaitingApproval(t *testing.T) {
	gw, model := newStubGateway(t), stubModel(t)
	cfg := testConfig(t, gw, model, 100*time.Millisecond)
	out := &syncBuffer{}
	if code := run(context.Background(), cfg, out); code != exitTimeout {
		t.Fatalf("first run: exit %d:\n%s", code, out.String())
	}
	if gw.refundDispatches() != 0 {
		t.Fatal("nothing may be dispatched before approval")
	}
	gw.decide(true)
	out2 := &syncBuffer{}
	cfg.wait = 5 * time.Second
	if code := run(context.Background(), cfg, out2); code != exitOK {
		t.Fatalf("second run: exit %d:\n%s", code, out2.String())
	}
	if !strings.Contains(out2.String(), "RESUMED=create_refund_request") || !strings.Contains(out2.String(), "STATUS=authorized") {
		t.Fatalf("the restarted agent must resume the existing operation:\n%s", out2.String())
	}
	if !strings.Contains(out2.String(), "RESUMED=lookup_ticket") || !strings.Contains(out2.String(), "ATTEMPT=already_succeeded TOOL=lookup_ticket") {
		t.Fatalf("the read already happened and must not be dispatched again:\n%s", out2.String())
	}
	if gw.refundOps() != 1 || gw.refundDispatches() != 1 {
		t.Fatalf("refund ops=%d dispatches=%d, want 1/1", gw.refundOps(), gw.refundDispatches())
	}
	if !strings.Contains(out2.String(), "RESUME=") {
		t.Fatalf("the journal should announce the earlier operations:\n%s", out2.String())
	}
	// Restart after completion: the operation is found succeeded; nothing
	// is dispatched; the run still completes.
	out3 := &syncBuffer{}
	if code := run(context.Background(), cfg, out3); code != exitOK {
		t.Fatalf("third run: exit %d:\n%s", code, out3.String())
	}
	if !strings.Contains(out3.String(), "ATTEMPT=already_succeeded TOOL=create_refund_request") || gw.refundDispatches() != 1 {
		t.Fatalf("a completed refund must never be dispatched again:\n%s", out3.String())
	}
}

// Restart after dispatch but before the outcome was observed: Talon
// reports the attempt as unknown; the agent reports unresolved and a
// restarted agent does NOT retry into a second effect.
func TestRun_UnknownOutcomeIsUnresolvedNeverRetried(t *testing.T) {
	gw, model := newStubGateway(t), stubModel(t)
	gw.nextUnknown = true
	cfg := testConfig(t, gw, model, 5*time.Second)
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(context.Background(), cfg, out) }()
	approveWhenAsked(t, gw, out, true)
	if code := <-done; code != exitUnresolved {
		t.Fatalf("exit %d, want unresolved:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "ATTEMPT=unknown") || !strings.Contains(out.String(), "RESULT=unresolved") {
		t.Fatalf("unknown outcome not reported:\n%s", out.String())
	}
	out2 := &syncBuffer{}
	if code := run(context.Background(), cfg, out2); code != exitUnresolved {
		t.Fatalf("restart: exit %d, want unresolved:\n%s", code, out2.String())
	}
	if gw.refundDispatches() != 1 {
		t.Fatalf("an unknown outcome was retried: dispatches=%d", gw.refundDispatches())
	}
}

// A rejected approval ends the run as refused with zero dispatch and no
// retry; a restart finds the cancelled operation and still dispatches nothing.
func TestRun_RejectedApprovalDispatchesNothing(t *testing.T) {
	gw, model := newStubGateway(t), stubModel(t)
	cfg := testConfig(t, gw, model, 5*time.Second)
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(context.Background(), cfg, out) }()
	approveWhenAsked(t, gw, out, false)
	if code := <-done; code != exitRejected {
		t.Fatalf("exit %d, want rejected:\n%s", code, out.String())
	}
	out2 := &syncBuffer{}
	if code := run(context.Background(), cfg, out2); code != exitRefused {
		t.Fatalf("restart after rejection: exit %d:\n%s", code, out2.String())
	}
	if gw.refundDispatches() != 0 || gw.refundOps() != 1 {
		t.Fatalf("rejection must leave zero dispatches and one operation: %d/%d", gw.refundDispatches(), gw.refundOps())
	}
}

// A changed intent under the same prefix is a conflict, never a silent
// second operation.
func TestRun_ChangedIntentIsAConflictNotASecondRefund(t *testing.T) {
	gw := newStubGateway(t)
	a := &agent{cfg: config{talonBase: gw.srv.URL, session: "s", opPrefix: "run-9", wait: time.Second, pollInterval: time.Millisecond}, out: io.Discard, http: &http.Client{Timeout: 5 * time.Second}}
	id := operationIDFor("run-9", "create_refund_request", json.RawMessage(`{"ticket_id":"T-1","amount":50,"currency":"EUR"}`))
	gw.mu.Lock()
	gw.ops[id] = &stubOp{id: id, action: "create_refund_request", status: "awaiting_approval", approvalID: "apr_x", approvalStatus: "pending", args: json.RawMessage(`{"ticket_id":"T-1","amount":60,"currency":"EUR"}`)}
	gw.mu.Unlock()
	buf := &syncBuffer{}
	a.out = buf
	_, code := a.runTool(context.Background(), "create_refund_request", `{"ticket_id":"T-1","amount":50,"currency":"EUR"}`, "model")
	if code != exitRefused || !strings.Contains(buf.String(), "operation_conflict") {
		t.Fatalf("exit %d:\n%s", code, buf.String())
	}
}

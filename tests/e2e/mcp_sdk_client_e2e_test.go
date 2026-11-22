//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// An UNMODIFIED standard MCP client — the official Go SDK's own client, its
// own transport, protocol 2026-07-28 — against the authenticated governed
// POST /mcp of the built (or released, TALON_E2E_BINARY) binary (#431). The
// only client configuration is the HTTP Authorization header carrying the
// use case's key, as every MCP client supports for remote servers. Every
// dispatch claim is the trusted source's own call counter.

// bearer adds the use case's key to every request of the SDK transport.
type bearer struct{ key string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.key)
	return http.DefaultTransport.RoundTrip(r)
}

func sdkSession(t *testing.T, base, key string) *sdk.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "go-sdk-standard-client", Version: "1.8.0"}, nil)
	cs, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:   base + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{key: key}, Timeout: 20 * time.Second},
		MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("the standard SDK client must connect (server/discover) to the governed /mcp: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// govOf returns the governance extension of a successful SDK result or of
// the JSON-RPC error the SDK returned.
func govOf(t *testing.T, res *sdk.CallToolResult, err error) map[string]any {
	t.Helper()
	if err != nil {
		var werr *jsonrpc.Error
		if !errors.As(err, &werr) {
			t.Fatalf("not a JSON-RPC error: %v", err)
		}
		var data map[string]any
		_ = json.Unmarshal(werr.Data, &data)
		g, _ := data["io.dativo.talon/governance"].(map[string]any)
		if g == nil {
			t.Fatalf("JSON-RPC error without a governance extension: %d %s %s", werr.Code, werr.Message, werr.Data)
		}
		return g
	}
	g, _ := res.Meta["io.dativo.talon/governance"].(map[string]any)
	if g == nil {
		t.Fatalf("result without a governance extension: %+v", res)
	}
	return g
}

// govCall calls a tool and returns the governance extension of the answer.
func govCall(t *testing.T, cs *sdk.ClientSession, name string, args map[string]any, meta sdk.Meta) map[string]any {
	t.Helper()
	res, err := callTool(cs, name, args, meta)
	return govOf(t, res, err)
}

func callTool(cs *sdk.ClientSession, name string, args map[string]any, meta sdk.Meta) (*sdk.CallToolResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args, Meta: meta})
}

func text(res *sdk.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// TestE2E_MCP_StandardSDKClient is the adoption proof: discover, list, a
// read-only call, prepare → execute by the Talon-generated id, approval and
// resume, duplicate and concurrent executes, two identical prepared
// operations, changed arguments, an expired approval, a denial, an unknown
// outcome, the recovery hold after a real restore, and signed lifecycle
// verification — all from the unmodified SDK client.
//
//nolint:gocyclo // one scenario per governed property, each checked at the source
func TestE2E_MCP_StandardSDKClient(t *testing.T) {
	f := startGovernedMCPWith(t, mgOpts{expiry: "3s"})
	cs := sdkSession(t, f.mcp.base, mgAgentKey)

	// Discover and list: the use case's governed catalog plus
	// talon_execute_operation; the forbidden tool is hidden.
	if info := cs.InitializeResult(); info == nil || info.ServerInfo == nil || info.ServerInfo.Name != "talon" {
		t.Fatalf("server/discover must identify Talon: %+v", info)
	}
	ctx := context.Background()
	list, err := cs.ListTools(ctx, &sdk.ListToolsParams{})
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := map[string]bool{}
	for _, tl := range list.Tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"send_voucher", "create_refund", "lookup_ticket", "talon_execute_operation"} {
		if !names[want] {
			t.Fatalf("tools/list must offer %s: %v", want, names)
		}
	}
	if names["delete_customer"] {
		t.Fatal("a forbidden tool is never listed")
	}

	// Read-only: one call, executed once at the source.
	res, err := callTool(cs, "lookup_ticket", map[string]any{"ticket_id": "T-1"}, nil)
	if err != nil || res.IsError || !strings.Contains(text(res), "ticket.lookup done") {
		t.Fatalf("read-only call: %v %+v", err, res)
	}
	if g := govOf(t, res, nil); g["code"] != "allowed" || g["provenance"] != "observed" {
		t.Fatalf("read-only governance: %v", g)
	}
	if n := f.src.count("ticket.lookup"); n != 1 {
		t.Fatalf("read-only dispatch count %d", n)
	}
	f.verify(t, govOf(t, res, nil)["operationId"].(string))

	// Consequential, no custom metadata: prepared, nothing sent.
	res, err = callTool(cs, "send_voucher", map[string]any{"ticket_id": "T-2", "amount": 20}, nil)
	if err != nil || res.IsError {
		t.Fatalf("prepare: %v %+v", err, res)
	}
	g := govOf(t, res, nil)
	opID, _ := g["operationId"].(string)
	sc, _ := res.StructuredContent.(map[string]any)
	if g["code"] != "operation_prepared" || opID == "" || sc["operationId"] != opID || !strings.Contains(text(res), "talon_execute_operation") {
		t.Fatalf("a prepared operation is a normal result naming the next call: %v %+v", g, res)
	}
	if n := f.src.count("voucher.send"); n != 0 {
		t.Fatalf("preparing dispatched %d", n)
	}
	// Execute by the Talon-generated id: exactly once.
	res, err = callTool(cs, "talon_execute_operation", map[string]any{"operation_id": opID}, nil)
	if err != nil || res.IsError || !strings.Contains(text(res), "voucher.send done") {
		t.Fatalf("execute: %v %+v", err, res)
	}
	if f.src.count("voucher.send") != 1 {
		t.Fatalf("execute dispatch count %d", f.src.count("voucher.send"))
	}
	// Duplicate execute: refused, nothing sent.
	if g := govCall(t, cs, "talon_execute_operation", map[string]any{"operation_id": opID}, nil); g["code"] != "operation_already_succeeded" {
		t.Fatalf("duplicate execute: %v", g)
	}
	if f.src.count("voucher.send") != 1 {
		t.Fatal("a duplicate execute dispatched")
	}
	f.verify(t, opID)

	// Two prepared operations with IDENTICAL arguments are two legitimate
	// operations: distinct ids, one dispatch each.
	var twins []string
	for i := 0; i < 2; i++ {
		r, e := callTool(cs, "send_voucher", map[string]any{"ticket_id": "T-3", "amount": 5}, nil)
		if e != nil {
			t.Fatal(e)
		}
		twins = append(twins, govOf(t, r, nil)["operationId"].(string))
	}
	if twins[0] == twins[1] {
		t.Fatal("identical arguments must not collapse two prepared operations")
	}
	for _, id := range twins {
		if _, e := callTool(cs, "talon_execute_operation", map[string]any{"operation_id": id}, nil); e != nil {
			t.Fatal(e)
		}
	}
	if f.src.count("voucher.send") != 3 {
		t.Fatalf("two identical operations: count %d, want 3", f.src.count("voucher.send"))
	}

	// Concurrent executes of one prepared operation: one dispatch.
	r, _ := callTool(cs, "send_voucher", map[string]any{"ticket_id": "T-4", "amount": 7}, nil)
	cc := govOf(t, r, nil)["operationId"].(string)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			_, _ = callTool(cs, "talon_execute_operation", map[string]any{"operation_id": cc}, nil)
		}()
	}
	close(gate)
	wg.Wait()
	if f.src.count("voucher.send") != 4 {
		t.Fatalf("eight concurrent executes: count %d, want 4", f.src.count("voucher.send"))
	}
	f.verify(t, cc)

	// Changed arguments under the same (client-provided) operation id.
	meta := sdk.Meta{"io.dativo.talon/operationId": "sdk-voucher-T-5"}
	if _, e := callTool(cs, "send_voucher", map[string]any{"ticket_id": "T-5", "amount": 9}, meta); e != nil {
		t.Fatal(e)
	}
	if g := govCall(t, cs, "send_voucher", map[string]any{"ticket_id": "T-5", "amount": 900}, meta); g["code"] != "operation_conflict" {
		t.Fatalf("changed arguments: %v", g)
	}
	if f.src.count("voucher.send") != 5 {
		t.Fatalf("changed arguments dispatched: %d", f.src.count("voucher.send"))
	}

	// Approval required: pending until an independent reviewer decides;
	// resumed by the same operation id; exactly one dispatch.
	r, err = callTool(cs, "create_refund", map[string]any{"ticket_id": "T-6", "amount": 75}, nil)
	if err != nil {
		t.Fatal(err)
	}
	g = govOf(t, r, nil)
	refundOp, approvalID := g["operationId"].(string), g["approvalId"].(string)
	if g["code"] != "approval_pending" || approvalID == "" {
		t.Fatalf("approval-required prepare: %v", g)
	}
	if g := govCall(t, cs, "talon_execute_operation", map[string]any{"operation_id": refundOp}, nil); g["code"] != "approval_pending" {
		t.Fatalf("execute before approval: %v", g)
	}
	if st, res := f.gw.do("POST", "/v1/approvals/"+approvalID+"/decisions", f.leadKey, `{"decision":"approve","reason":"verified"}`); st != 200 {
		t.Fatalf("reviewer approval: %d %v", st, res)
	}
	if f.src.count("refund.create") != 0 {
		t.Fatal("an approval dispatched")
	}
	if r, e := callTool(cs, "talon_execute_operation", map[string]any{"operation_id": refundOp}, nil); e != nil || r.IsError {
		t.Fatalf("execute after approval: %v %+v", e, r)
	}
	if f.src.count("refund.create") != 1 {
		t.Fatalf("approved execute count %d", f.src.count("refund.create"))
	}
	f.verify(t, refundOp)

	// Stale approval: the approval expires before the execute → refused.
	r, _ = callTool(cs, "create_refund", map[string]any{"ticket_id": "T-7", "amount": 80}, nil)
	g = govOf(t, r, nil)
	staleOp, staleApproval := g["operationId"].(string), g["approvalId"].(string)
	if st, _ := f.gw.do("POST", "/v1/approvals/"+staleApproval+"/decisions", f.leadKey, `{"decision":"approve","reason":"ok"}`); st != 200 {
		t.Fatalf("approve: %d", st)
	}
	time.Sleep(3500 * time.Millisecond)
	if g := govCall(t, cs, "talon_execute_operation", map[string]any{"operation_id": staleOp}, nil); g["code"] != "approval_expired" {
		t.Fatalf("an expired approval must refuse: %v", g)
	}
	if f.src.count("refund.create") != 1 {
		t.Fatal("an expired approval dispatched")
	}

	// DENY: the hidden tool called by name.
	if g := govCall(t, cs, "delete_customer", map[string]any{"customer_id": "c-1"}, nil); g["code"] != "policy_denied" || g["provenance"] != "not_dispatched" {
		t.Fatalf("deny: %v", g)
	}
	if f.src.count("customer.delete") != 0 {
		t.Fatal("a denied call dispatched")
	}

	// UNKNOWN: the source reports a tool error after dispatch; never re-sent.
	f.src.failing.Store(true)
	r, _ = callTool(cs, "send_voucher", map[string]any{"ticket_id": "T-8", "amount": 3}, nil)
	unk := govOf(t, r, nil)["operationId"].(string)
	if g := govCall(t, cs, "talon_execute_operation", map[string]any{"operation_id": unk}, nil); g["code"] != "upstream_outcome_unknown" || g["provenance"] != "unknown" {
		t.Fatalf("unknown: %v", g)
	}
	if g := govCall(t, cs, "talon_execute_operation", map[string]any{"operation_id": unk}, nil); g["code"] != "operation_outcome_unknown" {
		t.Fatalf("a retry of an unknown operation: %v", g)
	}
	if f.src.count("voucher.send") != 6 {
		t.Fatalf("unknown dispatch count %d, want 6", f.src.count("voucher.send"))
	}
	f.src.failing.Store(false)
	f.verify(t, unk)

	// Recovery hold: prepare, take a backup, lose the stores, restore them
	// (stop, copy back, start) — the restored installation holds dispatch
	// until the operator resumes; the same operation then executes once.
	r, _ = callTool(cs, "send_voucher", map[string]any{"ticket_id": "T-9", "amount": 4}, nil)
	held := govOf(t, r, nil)["operationId"].(string)
	backup := filepath.Join(t.TempDir(), "backup")
	if out, stderr, code := RunTalon(t, f.dir, nil, "backup", "create", backup); code != 0 {
		t.Fatalf("backup create: %d\n%s\n%s", code, out, stderr)
	}
	f.stop()
	for _, name := range []string{"evidence.db", "evidence.db-wal", "evidence.db-shm", "secrets.db", "secrets.db-wal", "secrets.db-shm"} {
		_ = os.Remove(filepath.Join(f.dir, name))
	}
	entries, _ := os.ReadDir(backup)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			b, err := os.ReadFile(filepath.Join(backup, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.dir, e.Name()), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.stop = startServeWithEnv(t, f.dir, f.port, f.env)
	cs = sdkSession(t, f.mcp.base, mgAgentKey)
	before := f.src.count("voucher.send")
	if g := govCall(t, cs, "talon_execute_operation", map[string]any{"operation_id": held}, nil); g["code"] != "recovery_hold" {
		t.Fatalf("a restored installation must hold dispatch: %v", g)
	}
	if f.src.count("voucher.send") != before {
		t.Fatal("a held installation dispatched")
	}
	if out, stderr, code := RunTalon(t, f.dir, nil, "backup", "resume", "--reconciled"); code != 0 {
		t.Fatalf("backup resume: %d\n%s\n%s", code, out, stderr)
	}
	if r, e := callTool(cs, "talon_execute_operation", map[string]any{"operation_id": held}, nil); e != nil || r.IsError {
		t.Fatalf("execute after resume: %v %+v", e, r)
	}
	if f.src.count("voucher.send") != before+1 {
		t.Fatalf("after resume: count %d, want %d", f.src.count("voucher.send"), before+1)
	}
	f.verify(t, held)
}

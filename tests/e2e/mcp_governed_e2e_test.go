//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Governed MCP over the built (or released, TALON_E2E_BINARY) binary
// (#431): a real MCP server — the official Go SDK, 2026-07-28 — is the
// trusted source of the use case's actions; an MCP client talks to
// POST /mcp with the use case's key; every tools/call is an Action Gateway
// operation. The source counts every tools/call it actually receives, so
// "zero dispatch" and "exactly one dispatch" are the source's own numbers.

const (
	mgAgent    = "support-bot"
	mgAgentKey = "talon-gw-mcp-governed-e2e-0001"
	mgAdminKey = "admin-e2e-key-mcp-governed"
)

const mcpMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"talon-e2e","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}`

type mcpClient struct {
	t    *testing.T
	base string
	key  string
}

func (c *mcpClient) post(path, method, name, body string, extra map[string]string) (int, http.Header, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	if method != "" {
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", method)
	}
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp.StatusCode, resp.Header, out
}

func mcpErrCode(m map[string]any) float64 {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return c
}

// call sends one tools/call; args is a JSON object; meta adds _meta keys.
func (c *mcpClient) call(id int, tool, args string, meta string) (int, map[string]any) {
	c.t.Helper()
	m := mcpMeta
	if meta != "" {
		m = strings.Replace(mcpMeta, `"io.modelcontextprotocol/clientCapabilities":{}}`, `"io.modelcontextprotocol/clientCapabilities":{},`+meta+`}`, 1)
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{%s,"name":%q,"arguments":%s}}`, id, m, tool, args)
	st, _, out := c.post("/mcp", "tools/call", tool, body, nil)
	return st, out
}

func (c *mcpClient) execute(id int, opID string) (int, map[string]any) {
	return c.call(id, "talon_execute_operation", fmt.Sprintf(`{"operation_id":%q}`, opID), "")
}

// govExt returns the governance extension of a result or a JSON-RPC error.
func govExt(m map[string]any) map[string]any {
	if e, ok := m["error"].(map[string]any); ok {
		d, _ := e["data"].(map[string]any)
		x, _ := d["io.dativo.talon/governance"].(map[string]any)
		return x
	}
	r, _ := m["result"].(map[string]any)
	meta, _ := r["_meta"].(map[string]any)
	x, _ := meta["io.dativo.talon/governance"].(map[string]any)
	return x
}

type mgSource struct {
	srv     *httptest.Server
	calls   map[string]*atomic.Int64
	failing atomic.Bool // voucher.send reports a tool error
}

func startMGSource(t *testing.T) *mgSource {
	t.Helper()
	s := &mgSource{calls: map[string]*atomic.Int64{}}
	srv := sdk.NewServer(&sdk.Implementation{Name: "crm", Version: "1.0.0"}, &sdk.ServerOptions{
		SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs, c.CacheScope = 600000, "public" },
	})
	str := map[string]any{"type": "string"}
	for name, props := range map[string]map[string]any{
		"voucher.send":    {"ticket_id": str, "amount": map[string]any{"type": "number"}, "note": str},
		"refund.create":   {"ticket_id": str, "amount": map[string]any{"type": "number"}},
		"ticket.lookup":   {"ticket_id": str},
		"customer.delete": {"customer_id": str},
	} {
		name := name
		s.calls[name] = &atomic.Int64{}
		srv.AddTool(&sdk.Tool{Name: name, InputSchema: map[string]any{"type": "object", "properties": props}}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			s.calls[name].Add(1)
			if name == "voucher.send" && s.failing.Load() {
				return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "ledger cust-77 locked"}}}, nil
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: name + " done"}}}, nil
		})
	}
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, &sdk.StreamableHTTPOptions{Stateless: true})
	s.srv = httptest.NewServer(h)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *mgSource) count(tool string) int64 { return s.calls[tool].Load() }

type mgFixture struct {
	dir     string
	src     *mgSource
	mcp     *mcpClient
	gw      *agClient
	leadKey string
}

func startGovernedMCP(t *testing.T) *mgFixture {
	return startGovernedMCPWith(t, mgOpts{})
}

// mgOpts varies the governed fixture: extra serve environment and an extra
// policies fragment of the use case.
type mgOpts struct {
	env      map[string]string
	policies string // appended under the agent file's policies:
}

func mgAgentYAML(srcURL, policiesExtra, extraDefinitions string) string {
	return `agent:
  name: ` + mgAgent + `
  version: "1.0.0"
  key:
    secret_name: "` + mgAgent + `-talon-key"
capabilities:
  forbidden_tools: [delete_customer]
actions:
  sources:
    crm:
      type: mcp
      url: "` + srcURL + `"
  definitions:
    send_voucher:
      source: crm
      upstream_name: voucher.send
      review: {fields: [ticket_id, amount], non_material: [note]}
    create_refund:
      source: crm
      upstream_name: refund.create
      review: {fields: [ticket_id, amount]}
    lookup_ticket:
      source: crm
      upstream_name: ticket.lookup
      read_only: true
      review: {fields: [ticket_id]}
    delete_customer:
      source: crm
      upstream_name: customer.delete
      review: {fields: [customer_id]}
` + extraDefinitions + `
policies:
  cost_limits:
    daily: 10
    monthly: 100
  approvals:
    expires_after: 30m
    rules:
      refunds:
        actions: [create_refund]
        approver_groups: [support-leads]
` + policiesExtra
}

func startGovernedMCPWith(t *testing.T, o mgOpts) *mgFixture {
	t.Helper()
	f := &mgFixture{dir: t.TempDir(), src: startMGSource(t)}
	if _, stderr, code := RunTalon(t, f.dir, nil, "init", "--scaffold", "--name", mgAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(f.dir, "agent.talon.yaml")
	yaml := mgAgentYAML(f.src.srv.URL, o.policies, "")
	if err := os.WriteFile(agentPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, f.dir, nil, "secrets", "set", mgAgent+"-talon-key", mgAgentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	out, stderr, code := RunTalon(t, f.dir, nil, "approver", "add", "--name", "lead-1", "--tenant", "default", "--groups", "support-leads")
	if code != 0 {
		t.Fatalf("approver add: %d\n%s", code, stderr)
	}
	f.leadKey = regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(out)
	port := freePort(t)
	env := map[string]string{"TALON_ADMIN_KEY": mgAdminKey}
	for k, v := range o.env {
		env[k] = v
	}
	stop := startServeWithEnv(t, f.dir, port, env)
	t.Cleanup(stop)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	f.mcp = &mcpClient{t: t, base: base, key: mgAgentKey}
	f.gw = &agClient{t: t, base: base}
	return f
}

func (f *mgFixture) verify(t *testing.T, opID string) {
	t.Helper()
	if out, stderr, code := RunTalon(t, f.dir, nil, "audit", "verify", "--operation", opID); code != 0 || !strings.Contains(out, "Lifecycle: VALID") {
		t.Fatalf("signed lifecycle of %s must verify: %d\n%s\n%s", opID, code, out, stderr)
	}
}

// The protocol surface of the governed route: discovery, the projected
// catalog, protocol rejections that never reach governance, and identity.
func TestE2E_MCP_Protocol2026_07_28(t *testing.T) {
	f := startGovernedMCP(t)
	st, _, out := f.mcp.post("/mcp", "server/discover", "", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+mcpMeta+`}}`, nil)
	if st != 200 || !strings.Contains(fmt.Sprint(out["result"]), "2026-07-28") {
		t.Fatalf("discover: %d %v", st, out)
	}
	st, _, out = f.mcp.post("/mcp", "tools/list", "", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+mcpMeta+`}}`, nil)
	if st != 200 {
		t.Fatalf("tools/list: %d %v", st, out)
	}
	names := []string{}
	for _, tool := range dig(out, "result", "tools").([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "create_refund,lookup_ticket,send_voucher,talon_execute_operation" {
		t.Fatalf("the projected catalog (canonical names; the forbidden tool hidden): %v", names)
	}
	// Protocol failures: no governance, nothing evaluated, nothing sent.
	legacy := `{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`
	if st, _, _ = f.mcp.post("/mcp", "", "", legacy, nil); st != 400 {
		t.Fatalf("legacy initialize: %d", st)
	}
	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{` + mcpMeta + `,"name":"send_voucher","arguments":{"ticket_id":"T-1","amount":1}}}`
	if st, _, out = f.mcp.post("/mcp", "tools/call", "delete_customer", body, nil); st != 400 || mcpErrCode(out) != -32020 {
		t.Fatalf("Mcp-Name mismatch: %d %v", st, out)
	}
	if st, out = f.mcp.call(5, "no_such_tool", `{}`, ""); st != 400 || mcpErrCode(out) != -32602 {
		t.Fatalf("unknown tool: %d %v", st, out)
	}
	if st, out = f.mcp.call(6, "send_voucher", `{"ticket_id":"T-1","amount":"twenty"}`, ""); st != 400 {
		t.Fatalf("schema violation is a protocol error: %d %v", st, out)
	}
	// Identity: no key, a wrong key and the admin key are refused; the MCP
	// proxy route no longer exists.
	for _, key := range []string{"", "wrong-key", mgAdminKey} {
		c := &mcpClient{t: t, base: f.mcp.base, key: key}
		if st, _, _ = c.post("/mcp", "tools/list", "", `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{`+mcpMeta+`}}`, nil); st != 401 {
			t.Fatalf("key %q must be refused: %d", key, st)
		}
	}
	if st, _, _ = f.mcp.post("/mcp/proxy", "server/discover", "", `{"jsonrpc":"2.0","id":8,"method":"server/discover","params":{`+mcpMeta+`}}`, nil); st != 404 {
		t.Fatalf("/mcp/proxy is folded into /mcp: %d", st)
	}
	for tool, n := range f.src.calls {
		if n.Load() != 0 {
			t.Fatalf("nothing above may call a tool: %s %d", tool, n.Load())
		}
	}
}

// The governance contract: zero dispatch on deny and before execution or
// approval, exactly one dispatch on execution, at most one under replay and
// concurrency, unknown never retried, and every lifecycle verifies.
func TestE2E_MCP_GovernanceContract(t *testing.T) {
	f := startGovernedMCP(t)

	// A forbidden tool called directly: denied by the gateway, zero calls.
	_, out := f.mcp.call(1, "delete_customer", `{"customer_id":"c-1"}`, "")
	x := govExt(out)
	if x["code"] != "policy_denied" || x["provenance"] != "not_dispatched" || f.src.count("customer.delete") != 0 {
		t.Fatalf("forbidden tool: %v (calls %d)", out, f.src.count("customer.delete"))
	}
	f.verify(t, x["operationId"].(string))

	// Read-only: one call.
	_, out = f.mcp.call(2, "lookup_ticket", `{"ticket_id":"T-9"}`, "")
	if !strings.Contains(fmt.Sprint(out["result"]), "ticket.lookup done") || f.src.count("ticket.lookup") != 1 {
		t.Fatalf("read-only tool: %v (calls %d)", out, f.src.count("ticket.lookup"))
	}
	f.verify(t, govExt(out)["operationId"].(string))

	// Consequential, unmodified client: prepare (zero), execute (one),
	// repeat and concurrent executes (still one).
	_, out = f.mcp.call(3, "send_voucher", `{"ticket_id":"T-1","amount":20}`, "")
	x = govExt(out)
	opID, _ := x["operationId"].(string)
	if x["code"] != "operation_prepared" || opID == "" || f.src.count("voucher.send") != 0 {
		t.Fatalf("prepare: %v (calls %d)", out, f.src.count("voucher.send"))
	}
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); <-gate; _, _ = f.mcp.execute(100+i, opID) }(i)
	}
	close(gate)
	wg.Wait()
	if n := f.src.count("voucher.send"); n != 1 {
		t.Fatalf("six concurrent executes: %d dispatches, want 1", n)
	}
	_, out = f.mcp.execute(4, opID)
	if govExt(out)["code"] != "operation_already_succeeded" || f.src.count("voucher.send") != 1 {
		t.Fatalf("repeat after success: %v", out)
	}
	f.verify(t, opID)

	// Advanced client with its own id: changed arguments conflict.
	if _, out = f.mcp.call(5, "send_voucher", `{"ticket_id":"T-2","amount":5}`, `"io.dativo.talon/operationId":"voucher-T-2"`); f.src.count("voucher.send") != 2 {
		t.Fatalf("caller id executes in one call: %v", out)
	}
	if _, out = f.mcp.call(6, "send_voucher", `{"ticket_id":"T-2","amount":500}`, `"io.dativo.talon/operationId":"voucher-T-2"`); govExt(out)["code"] != "operation_conflict" {
		t.Fatalf("changed arguments: %v", out)
	}
	if f.src.count("voucher.send") != 2 {
		t.Fatalf("a conflict dispatches nothing")
	}

	// Approval: pending, the decision dispatches nothing, execute once.
	_, out = f.mcp.call(7, "create_refund", `{"ticket_id":"T-3","amount":75}`, "")
	x = govExt(out)
	refundOp, approvalID := x["operationId"].(string), fmt.Sprint(x["approvalId"])
	if x["code"] != "approval_pending" || approvalID == "" {
		t.Fatalf("approval-required prepare: %v", out)
	}
	if _, out = f.mcp.execute(8, refundOp); govExt(out)["code"] != "approval_pending" {
		t.Fatalf("execute before the approval: %v", out)
	}
	if st, res := f.gw.do("POST", "/v1/approvals/"+approvalID+"/decisions", mgAgentKey, `{"decision":"approve","reason":"self"}`); st < 400 {
		t.Fatalf("the use-case key must not approve: %d %v", st, res)
	}
	if st, res := f.gw.do("POST", "/v1/approvals/"+approvalID+"/decisions", f.leadKey, `{"decision":"approve","reason":"verified"}`); st != 200 {
		t.Fatalf("reviewer approval: %d %v", st, res)
	}
	if f.src.count("refund.create") != 0 {
		t.Fatalf("the approval itself dispatched")
	}
	if _, out = f.mcp.execute(9, refundOp); !strings.Contains(fmt.Sprint(out["result"]), "refund.create done") || f.src.count("refund.create") != 1 {
		t.Fatalf("execute after the approval: %v (calls %d)", out, f.src.count("refund.create"))
	}
	f.verify(t, refundOp)

	// An application error after dispatch is unknown and never retried.
	f.src.failing.Store(true)
	_, out = f.mcp.call(10, "send_voucher", `{"ticket_id":"T-4","amount":9}`, "")
	unknownOp := govExt(out)["operationId"].(string)
	_, out = f.mcp.execute(11, unknownOp)
	x = govExt(out)
	if x["code"] != "upstream_outcome_unknown" || x["provenance"] != "unknown" || strings.Contains(fmt.Sprint(out), "cust-77") {
		t.Fatalf("unknown outcome: %v", out)
	}
	if _, out = f.mcp.execute(12, unknownOp); govExt(out)["code"] != "operation_outcome_unknown" || f.src.count("voucher.send") != 3 {
		t.Fatalf("unknown is never retried: %v (calls %d)", out, f.src.count("voucher.send"))
	}
	f.verify(t, unknownOp)
}

// countRecords is the number of evidence records in a store.
// P1-C: a native (MCP-only) talon serve applies the organization's PII
// baseline from the gateway config file, exactly as a gateway serve does,
// and a use case cannot weaken it — not with its own data_classification,
// and not by changing that file while the server runs (hot reload). The
// source's own counter proves nothing was sent.
func TestE2E_MCP_OrganizationPIIBaseline_NativeServe(t *testing.T) {
	const email = "jan.kowalski@example.com"
	dir := t.TempDir()
	company := filepath.Join(dir, "company.yaml")
	if err := os.WriteFile(company, []byte("gateway:\n  organization_policy:\n    defaults:\n      pii_action: block\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The use case asks for the WEAKER redact (input scanning with
	// redaction): under a company block it must still be blocked.
	weaker := "  data_classification:\n    input_scan: true\n    redact_input: true\n"
	f := startGovernedMCPWith(t, mgOpts{
		env:      map[string]string{"TALON_GATEWAY_CONFIG": company, "TALON_AGENTS_RELOAD_INTERVAL": "1s"},
		policies: weaker,
	})
	pii := func(id int, opID string) map[string]any {
		_, out := f.mcp.call(id, "send_voucher", `{"ticket_id":"T-1","amount":10,"note":"contact `+email+`"}`,
			`"io.dativo.talon/operationId":"`+opID+`"`)
		return out
	}
	out := pii(1, "pii-1")
	if x := govExt(out); x["code"] != "pii_policy_violation" {
		t.Fatalf("native serve must apply the company PII block over the use case's redact: %v", out)
	}
	if n := f.src.count("voucher.send"); n != 0 {
		t.Fatalf("a blocked call reached the source %d times", n)
	}
	// Without PII the same tool works: the baseline blocks personal data,
	// not the route.
	_, out = f.mcp.call(2, "send_voucher", `{"ticket_id":"T-2","amount":10,"note":"no personal data"}`,
		`"io.dativo.talon/operationId":"clean-1"`)
	if govExt(out)["code"] != "allowed" || f.src.count("voucher.send") != 1 {
		t.Fatalf("a call without PII must execute once: %v (source %d)", out, f.src.count("voucher.send"))
	}

	// Hot reload: the use case rewrites its own file (still asking for
	// redact); the new generation must be ACTIVE before the next call.
	fleet := func() fleetReply {
		req, _ := http.NewRequest(http.MethodGet, f.mcp.base+"/v1/agents/fleet", nil)
		req.Header.Set("X-Talon-Admin-Key", mgAdminKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var fr fleetReply
		if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("fleet: %d %v", resp.StatusCode, err)
		}
		return fr
	}
	gen0 := fleet().Generation
	if err := os.WriteFile(filepath.Join(f.dir, "agent.talon.yaml"), []byte(mgAgentYAML(f.src.srv.URL, weaker+"  # reloaded: still asks for redact\n", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	var fr fleetReply
	for i := 0; i < 80; i++ {
		if fr = fleet(); fr.Generation != gen0 || (fr.Reload != nil && fr.Reload.Rejected) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if fr.Reload != nil && fr.Reload.Rejected {
		t.Fatalf("the reload was rejected: %v", fr.Reload.RejectedCauses)
	}
	if fr.Generation == gen0 {
		t.Fatal("the reloaded generation never became active")
	}
	out = pii(3, "pii-2")
	if x := govExt(out); x["code"] != "pii_policy_violation" {
		t.Fatalf("after a reload the company PII block must still apply: %v", out)
	}
	if n := f.src.count("voucher.send"); n != 1 {
		t.Fatalf("after the reload a blocked call reached the source (count %d, want 1 from the clean call)", n)
	}
}

func countRecords(t *testing.T, dbPath string) int {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM evidence`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

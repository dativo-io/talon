//go:build e2e

package e2e

import (
	"bytes"
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

	_ "github.com/mattn/go-sqlite3"
)

// Exact governed-action proof (#458) through the public Action Gateway.
//
// One deterministic, no-key run of the built binary proves:
//   DENY                       → downstream count 0
//   REQUIRE_APPROVAL           → count 0; claim refused
//   admin/agent key decision   → refused; count 0
//   wrong-group approver       → refused; count 0
//   authorized approver        → approved; count STILL 0
//   controlled resume (claim)  → count 1, exact canonical payload, stable idempotency key
//   exact replay               → same state; count still 1
//   changed payload, same id   → operation_conflict; count still 1
//   lost response after send   → UNKNOWN; second claim refused; count 1
//   restart                    → state and evidence survive
//   talon audit verify --operation → VALID; DB tamper → INVALID (non-zero exit)

const (
	agAgent      = "support-bot"
	agAgentKey   = "talon-gw-action-e2e-0001"
	agAdminKey   = "admin-e2e-key-not-an-approver"
	agRefundArgs = `{"ticket_id":"T-1842","amount":50.00,"currency":"EUR"}`
)

type refundService struct {
	srv         *httptest.Server
	refundCalls atomic.Int64
	lossyCalls  atomic.Int64
	mu          sync.Mutex
	bodies      []string
	idemKeys    []string
}

func startRefundService(t *testing.T) *refundService {
	t.Helper()
	s := &refundService{}
	mux := http.NewServeMux()
	mux.HandleFunc("/refunds", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, string(b))
		s.idemKeys = append(s.idemKeys, r.Header.Get("Idempotency-Key"))
		s.mu.Unlock()
		s.refundCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"refund_id":"rf_0001"}`))
	})
	mux.HandleFunc("/lossy", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		s.lossyCalls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close() // request consumed, no response: ambiguous dispatch
		}
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

type agClient struct {
	t    *testing.T
	base string
}

func (c *agClient) do(method, path, bearer, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
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
	return resp.StatusCode, out
}

func (c *agClient) adminDo(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, strings.NewReader(body))
	req.Header.Set("X-Talon-Admin-Key", agAdminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func errCode(m map[string]any) string {
	c, _ := dig(m, "error", "code").(string)
	return c
}

func startActionServe(t *testing.T, dir string, port int) func() {
	t.Helper()
	return startServeWithEnv(t, dir, port, map[string]string{"TALON_ADMIN_KEY": agAdminKey})
}

func TestE2E_ActionGateway_ExactActionProof(t *testing.T) {
	down := startRefundService(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", agAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	raw, _ := os.ReadFile(agentPath)
	yaml := string(raw)
	if !strings.Contains(yaml, "\npolicies:\n") {
		t.Fatalf("scaffold changed:\n%s", yaml)
	}
	if !strings.Contains(yaml, "\ncapabilities:\n") {
		t.Fatalf("scaffold has no capabilities block:\n%s", yaml)
	}
	yaml = strings.Replace(yaml, "\ncapabilities:\n", "\ncapabilities:\n  forbidden_tools: [delete_customer]\n", 1)
	yaml = strings.Replace(yaml, "\npolicies:\n", `
actions:
  definitions:
    create_refund_request:
      description: Create a refund request for a support ticket
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: number}
          currency: {type: string, enum: [EUR, USD]}
      review:
        fields: [ticket_id, amount, currency]
      destination: {type: http, url: "`+down.srv.URL+`/refunds", method: POST}
    notify_customer:
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id]
        properties:
          ticket_id: {type: string}
      destination: {type: http, url: "`+down.srv.URL+`/lossy"}
    delete_customer:
      input_schema:
        type: object
        properties:
          customer_id: {type: string}
      destination: {type: http, url: "`+down.srv.URL+`/refunds"}

policies:
  approvals:
    expires_after: 30m
    rules:
      refund-request:
        actions: [create_refund_request]
        approver_groups: [support-leads]
`, 1)
	if err := os.WriteFile(agentPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "validate"); code != 0 {
		t.Fatalf("talon validate rejected the catalog:\n%s", stderr)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", agAgent+"-talon-key", agAgentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	keyRe := regexp.MustCompile(`talon_appr_[0-9a-f]+`)
	out, stderr, code := RunTalon(t, dir, nil, "approver", "add", "--name", "lead-1", "--role", "support-leads")
	if code != 0 {
		t.Fatalf("approver add: %d\n%s", code, stderr)
	}
	leadKey := keyRe.FindString(out)
	out, _, _ = RunTalon(t, dir, nil, "approver", "add", "--name", "intern-1", "--role", "interns")
	internKey := keyRe.FindString(out)
	if leadKey == "" || internKey == "" {
		t.Fatalf("approver keys not printed: %q", out)
	}

	port := freePort(t)
	stop := startActionServe(t, dir, port)
	defer func() { stop() }()
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}

	// 1. DENY → zero dispatch.
	st, res := c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-del-1","action":"delete_customer","arguments":{"customer_id":"c-9"}}`)
	if st != 403 || dig(res, "operation", "verdict") != "DENY" || dig(res, "operation", "operation_status") != "denied" {
		t.Fatalf("deny: %d %v", st, res)
	}
	st, res = c.do("POST", "/v1/action-operations/op-del-1/attempts", agAgentKey, "")
	if st != 403 || errCode(res) != "policy_denied" {
		t.Fatalf("claim on denied: %d %v", st, res)
	}
	if down.refundCalls.Load() != 0 {
		t.Fatalf("DENY dispatched: %d", down.refundCalls.Load())
	}

	// 2. REQUIRE_APPROVAL → pending, zero dispatch, claim refused.
	st, res = c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-refund-1","action":"create_refund_request","arguments":`+agRefundArgs+`}`)
	if st != 202 || dig(res, "operation", "verdict") != "REQUIRE_APPROVAL" || dig(res, "operation", "approval", "status") != "pending" {
		t.Fatalf("require approval: %d %v", st, res)
	}
	approvalID, _ := dig(res, "operation", "approval", "id").(string)
	if dig(res, "operation", "review", "amount") != float64(50) || dig(res, "operation", "review", "ticket_id") != "T-1842" {
		t.Fatalf("review projection: %v", dig(res, "operation", "review"))
	}
	st, res = c.do("POST", "/v1/action-operations/op-refund-1/attempts", agAgentKey, "")
	if st != 409 || errCode(res) != "approval_pending" {
		t.Fatalf("claim before approval: %d %v", st, res)
	}

	// 3. Wrong authority never decides: admin key, agent key, wrong group.
	decision := `{"decision":"approve","reason":"looks fine"}`
	if st, res = c.adminDo("POST", "/v1/approvals/"+approvalID+"/decisions", decision); st != 401 || errCode(res) != "approval_not_authorized" {
		t.Fatalf("admin key must not approve: %d %v", st, res)
	}
	if st, res = c.do("POST", "/v1/approvals/"+approvalID+"/decisions", agAgentKey, decision); st != 401 {
		t.Fatalf("agent key must not approve: %d %v", st, res)
	}
	if st, res = c.do("POST", "/v1/approvals/"+approvalID+"/decisions", internKey, decision); st != 401 || errCode(res) != "approval_not_authorized" {
		t.Fatalf("wrong group must not approve: %d %v", st, res)
	}
	st, res = c.do("GET", "/v1/approvals/"+approvalID, agAgentKey, "")
	if st != 200 || dig(res, "approval", "status") != "pending" {
		t.Fatalf("approval still pending: %d %v", st, res)
	}
	if down.refundCalls.Load() != 0 {
		t.Fatalf("dispatch before approval: %d", down.refundCalls.Load())
	}

	// 4. Authorized approval: decision alone dispatches nothing.
	st, res = c.do("POST", "/v1/approvals/"+approvalID+"/decisions", leadKey, decision)
	if st != 200 || dig(res, "approval", "status") != "approved" || dig(res, "approval", "decided_by") != "lead-1" || dig(res, "operation", "operation_status") != "authorized" {
		t.Fatalf("approve: %d %v", st, res)
	}
	if down.refundCalls.Load() != 0 {
		t.Fatalf("reviewer decision dispatched: %d", down.refundCalls.Load())
	}
	if st, res = c.do("POST", "/v1/approvals/"+approvalID+"/decisions", leadKey, `{"decision":"reject","reason":"no"}`); st != 409 || errCode(res) != "approval_already_decided" {
		t.Fatalf("second decision must lose: %d %v", st, res)
	}

	// 5. Controlled resume: exactly one effect.
	st, res = c.do("POST", "/v1/action-operations/op-refund-1/attempts", agAgentKey, "")
	if st != 200 || dig(res, "operation", "operation_status") != "succeeded" || dig(res, "attempt", "status") != "succeeded" || dig(res, "attempt", "result_provenance") != "observed" {
		t.Fatalf("resume: %d %v", st, res)
	}
	if down.refundCalls.Load() != 1 {
		t.Fatalf("resume dispatch count = %d, want 1", down.refundCalls.Load())
	}
	down.mu.Lock()
	if down.bodies[0] != `{"amount":50.00,"currency":"EUR","ticket_id":"T-1842"}` || !strings.HasPrefix(down.idemKeys[0], "talon-op_") {
		t.Fatalf("downstream received %q with Idempotency-Key %q", down.bodies[0], down.idemKeys[0])
	}
	down.mu.Unlock()

	// 6. Exact replay: same state, still one effect.
	st, res = c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-refund-1","action":"create_refund_request","arguments":{"currency":"EUR","ticket_id":"T-1842","amount":50.00}}`)
	if st != 200 || res["created"] != false || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("replay: %d %v", st, res)
	}
	if st, res = c.do("POST", "/v1/action-operations/op-refund-1/attempts", agAgentKey, ""); st != 409 || errCode(res) != "operation_already_succeeded" {
		t.Fatalf("second claim after success: %d %v", st, res)
	}
	// 7. Changed material payload under the same id.
	if st, res = c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-refund-1","action":"create_refund_request","arguments":{"ticket_id":"T-1842","amount":500.00,"currency":"EUR"}}`); st != 409 || errCode(res) != "operation_conflict" {
		t.Fatalf("conflict: %d %v", st, res)
	}
	if down.refundCalls.Load() != 1 {
		t.Fatalf("replay/conflict dispatched: %d", down.refundCalls.Load())
	}

	// 8. Ambiguous dispatch → UNKNOWN, no automatic second call.
	if st, res = c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-notify-1","action":"notify_customer","arguments":{"ticket_id":"T-1842"}}`); st != 201 || dig(res, "operation", "verdict") != "ALLOW" {
		t.Fatalf("allow: %d %v", st, res)
	}
	st, res = c.do("POST", "/v1/action-operations/op-notify-1/attempts", agAgentKey, "")
	if st != 200 || dig(res, "operation", "operation_status") != "unknown" || dig(res, "attempt", "result_provenance") != "unknown" || dig(res, "attempt", "dispatch_observed") != true {
		t.Fatalf("unknown: %d %v", st, res)
	}
	if st, res = c.do("POST", "/v1/action-operations/op-notify-1/attempts", agAgentKey, ""); st != 409 || errCode(res) != "operation_outcome_unknown" {
		t.Fatalf("retry after unknown: %d %v", st, res)
	}
	if down.lossyCalls.Load() != 1 {
		t.Fatalf("lossy calls = %d, want exactly 1", down.lossyCalls.Load())
	}

	// 9. Restart: state and evidence survive; verification is offline-capable.
	stop()
	stop = startActionServe(t, dir, port)
	if st, res = c.do("GET", "/v1/action-operations/op-refund-1", agAgentKey, ""); st != 200 || dig(res, "operation", "operation_status") != "succeeded" || dig(res, "operation", "attempt_count") != float64(1) {
		t.Fatalf("after restart: %d %v", st, res)
	}
	if st, res = c.do("POST", "/v1/action-operations/op-refund-1/attempts", agAgentKey, ""); st != 409 {
		t.Fatalf("claim after restart on succeeded op: %d %v", st, res)
	}
	if down.refundCalls.Load() != 1 || down.lossyCalls.Load() != 1 {
		t.Fatalf("restart changed dispatch counts: %d/%d", down.refundCalls.Load(), down.lossyCalls.Load())
	}
	for _, opID := range []string{"op-del-1", "op-refund-1", "op-notify-1"} {
		out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", opID)
		if code != 0 || !strings.Contains(out, "Lifecycle: VALID") {
			t.Fatalf("verify %s: code=%d\n%s\n%s", opID, code, out, stderr)
		}
	}
	out, _, _ = RunTalon(t, dir, nil, "audit", "verify", "--operation", "op-refund-1")
	for _, want := range []string{"#1 operation_established", "#2 approval_requested", "approval=approved by lead-1 (support-leads)", "attempt_claimed", "attempt_dispatched", "status=succeeded result=observed dispatch_observed=true", "operation_conflict"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "50.00") || strings.Contains(out, "T-1842") {
		t.Errorf("verify output must not print raw arguments:\n%s", out)
	}

	// 10. Tamper: rewrite the stored decision record's reviewer → INVALID.
	stop()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	var id, js string
	if err := db.QueryRow(`SELECT id, evidence_json FROM evidence WHERE invocation_type='action_lifecycle' AND evidence_json LIKE '%"event":"approval_decided"%' LIMIT 1`).Scan(&id, &js); err != nil {
		t.Fatalf("find decision record: %v", err)
	}
	if !bytes.Contains([]byte(js), []byte(`"reviewer_principal":"lead-1"`)) {
		t.Fatalf("unexpected record: %s", js)
	}
	js = strings.Replace(js, `"reviewer_principal":"lead-1"`, `"reviewer_principal":"mallory"`, 1)
	if _, err := db.Exec(`UPDATE evidence SET evidence_json = ? WHERE id = ?`, js, id); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	out, _, code = RunTalon(t, dir, nil, "audit", "verify", "--operation", "op-refund-1")
	if code == 0 || !strings.Contains(out, "Lifecycle: INVALID") || !strings.Contains(out, "signature does not verify") {
		t.Fatalf("tampered lifecycle must fail verification: code=%d\n%s", code, out)
	}
}

//go:build e2e

package e2e

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// MCP governance-contract smoke (#372): offline, credential-free, against the
// BUILT talon binary over real HTTP, with a deterministic counting mock MCP
// upstream and a temporary evidence DB. It is the merge gate for the
// governance extension's truth semantics — `make test-mcp-governance-smoke`,
// smoke section 37, and a named PR CI step all run exactly this test.
//
//	1. discover (both routes)  → exactly io.dativo.talon/governance v1, no Tasks
//	2. allowed call            → result._meta decision=allow, committed evidence id,
//	                             effect counter 1; full record fetched, HMAC verified,
//	                             code/explanation/tenant/correlation agree
//	3. forbidden call          → error.data code=policy_denied, deny, retryable=false,
//	                             committed ref, deprecated alias; counter still 1;
//	                             record verified, reasonCode == signed explanation
//	4. protocol errors         → -32020 / -32602 / -32022 / -32601 intact, NO governance
//	                             object, no receipt, counter unchanged
//	5. ambiguous post-handoff  → mock registers the effect then severs the response:
//	                             upstream_outcome_unknown, non-retryable, exactly one
//	                             effect, record status unknown, no hidden retry
//	6. tamper                  → a corrupted copy of a recorded record fails
//	                             `talon audit verify`; untouched records verify
//	+  unknown native tool     → HTTP 400 / -32602, no governance object, no alias, no record
//	+  denial safe data        → fixed public message; a caller-supplied secret in the
//	                             arguments appears neither publicly nor in the record
//	+  signed UNKNOWN          → the unknown record's explanation is
//	                             EXECUTION_OUTCOME_UNKNOWN / unknown, equal to reasonCode
//	+  vendor error            → vendor code preserved, message/data NOT relayed, record
//	                             sanitized + verified, exactly one effect
//
// Coverage boundary (documented, not hidden): pre-dispatch evidence-commit
// outages and adversarial error sanitization cannot be injected into a
// running binary without privileged hooks; they are proven in-process by
// internal/mcp TestGovernance_NativePolicyEvaluationFailure_CommitOutage,
// TestGovernance_ProxyPolicyEvaluationFailure_EvidencedZeroUpstream,
// TestGovernance_EvidenceCommitFailure_NoIDZeroExecution and
// TestGovernance_NativeToolErrorIsSanitized.

const govExtID = "io.dativo.talon/governance"

// Protected strings a vendor might put into an error: a credential-shaped
// token and two non-credential-shaped values no regex would recognize.
const (
	vendorToken    = "sk-VENDOR-SECRET-0001"
	vendorCustomer = "CUST-7391-SECRET"
	vendorEmail    = "private.person@example.test"
)

// govUpstream is the deterministic mock: tools/list publishes three tools;
// tools/call on "ticket_lookup" answers complete and counts an effect;
// tools/call on "flaky_update" counts the effect and then severs the
// connection after a partial body (the business effect happened; the answer
// is unusable).
type govUpstream struct {
	srv     *httptest.Server
	effects atomic.Int64
}

func startGovUpstream(t *testing.T) *govUpstream {
	t.Helper()
	u := &govUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		switch req.Method {
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[{"name":"ticket_lookup","inputSchema":{"type":"object"}},{"name":"flaky_update","inputSchema":{"type":"object"}},{"name":"vendor_error_tool","inputSchema":{"type":"object"}},{"name":"delete_customer","inputSchema":{"type":"object"}}],"ttlMs":30000,"cacheScope":"public"}}`, req.ID)
		case "tools/call":
			u.effects.Add(1) // the business side effect happens here, before any answer
			if req.Params.Name == "vendor_error_tool" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32001,"message":"refund failed for %s token %s","data":{"customer":"%s","detail":{"email":"%s"}}}}`,
					req.ID, vendorCustomer, vendorToken, vendorCustomer, vendorEmail)
				return
			}
			if req.Params.Name == "flaky_update" {
				hj, ok := w.(http.Hijacker)
				if !ok {
					t.Error("mock upstream cannot hijack")
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n{\"jsonrpc\":\"2.0\","))
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				_ = conn.Close()
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":"ticket ok"}],"_meta":{"com.vendor/trace":"t-1"}}}`, req.ID)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"unknown"}}`, req.ID)
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// govExt extracts the governance extension from an error or a result.
func govExt(out map[string]any) map[string]any {
	if e, ok := out["error"].(map[string]any); ok {
		data, _ := e["data"].(map[string]any)
		ext, _ := data[govExtID].(map[string]any)
		return ext
	}
	res, _ := out["result"].(map[string]any)
	meta, _ := res["_meta"].(map[string]any)
	ext, _ := meta[govExtID].(map[string]any)
	return ext
}

// storedRecord is the subset of a signed evidence record the smoke compares
// against the in-band extension.
type storedRecord struct {
	ID            string `json:"id"`
	CorrelationID string `json:"correlation_id"`
	TenantID      string `json:"tenant_id"`
	Status        string `json:"status"`
	FailureReason string `json:"failure_reason"`
	PolicyDecison struct {
		Allowed bool     `json:"allowed"`
		Reasons []string `json:"reasons"`
	} `json:"policy_decision"`
	Explanations []struct {
		Code     string `json:"code"`
		Decision string `json:"decision"`
	} `json:"explanations"`
	Signature string `json:"signature"`
}

// countRecords counts every stored record (any tenant): a protocol outcome
// or an unresolvable tool must leave the count unchanged.
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

func rawRecordJSON(t *testing.T, dbPath, id string) string {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var js string
	if err := db.QueryRowContext(t.Context(), `SELECT evidence_json FROM evidence WHERE id = ?`, id).Scan(&js); err != nil {
		t.Fatalf("record %s not found in %s: %v", id, dbPath, err)
	}
	return js
}

func readRecord(t *testing.T, dbPath, id string) storedRecord {
	t.Helper()
	var rec storedRecord
	if err := json.Unmarshal([]byte(rawRecordJSON(t, dbPath, id)), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// checkGovernance is the ONE assertion set every governed outcome must pass;
// it returns an error so the negative fixture below can prove the smoke
// would fail on a missing id or an uncommitted reference.
func checkGovernance(ext map[string]any, wantCode, wantDecision string, wantRetryable bool) error {
	if ext == nil {
		return errors.New("governance extension absent")
	}
	if ext["schemaVersion"] != float64(1) {
		return fmt.Errorf("schemaVersion = %v", ext["schemaVersion"])
	}
	if ext["code"] != wantCode || ext["decision"] != wantDecision || ext["retryable"] != wantRetryable {
		return fmt.Errorf("code/decision/retryable = %v/%v/%v, want %s/%s/%v", ext["code"], ext["decision"], ext["retryable"], wantCode, wantDecision, wantRetryable)
	}
	ev, _ := ext["evidence"].(map[string]any)
	if ev == nil {
		return errors.New("evidence reference absent")
	}
	id, _ := ev["id"].(string)
	if ev["committed"] != true || id == "" {
		return fmt.Errorf("evidence must be committed with an id: %v", ev)
	}
	if rc, _ := ext["reasonCode"].(string); rc == "" {
		return errors.New("reasonCode absent")
	}
	for _, k := range []string{"signature", "hmac", "arguments"} {
		if _, has := ext[k]; has {
			return fmt.Errorf("extension carries %q", k)
		}
	}
	return nil
}

//nolint:gocyclo // one sequential black-box scenario: each numbered step depends on the state the previous one left in the running binary
func TestE2E_MCP_GovernanceContract(t *testing.T) {
	up := startGovUpstream(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", "mcp-gov"); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	proxyCfg := filepath.Join(dir, "proxy.talon.yaml")
	if err := os.WriteFile(proxyCfg, []byte(`proxy:
  upstream:
    vendor: ticketing
    url: "`+up.srv.URL+`/mcp"
  allowed_tools:
    - name: ticket_lookup
    - name: flaky_update
    - name: vendor_error_tool
  forbidden_tools:
    - delete_customer
`), 0o600); err != nil {
		t.Fatal(err)
	}
	const agentKey = "talon-mcp-gov-key-0001"
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "mcp-gov-talon-key", agentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	port := freePort(t)
	stop := startServeWithEnv(t, dir, port, nil, "--proxy-config", proxyCfg)
	defer stop()
	c := &mcpClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port), key: agentKey}
	dbPath := filepath.Join(dir, "evidence.db")

	// 1. discover: exactly the governance extension, no Tasks, both routes.
	for _, path := range []string{"/mcp", "/mcp/proxy"} {
		st, _, out := c.post(path, "server/discover", "", `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+mcpMeta+`}}`, nil)
		res, _ := out["result"].(map[string]any)
		if st != 200 || res == nil {
			t.Fatalf("%s discover: %d %v", path, st, out)
		}
		exts, _ := res["capabilities"].(map[string]any)["extensions"].(map[string]any)
		if len(exts) != 1 {
			t.Fatalf("%s: exactly one extension expected: %v", path, exts)
		}
		if settings, _ := exts[govExtID].(map[string]any); settings["schemaVersion"] != float64(1) {
			t.Fatalf("%s: governance extension v1 not advertised: %v", path, exts)
		}
		if _, ok := exts["io.modelcontextprotocol/tasks"]; ok {
			t.Fatalf("%s: Tasks must not be advertised", path)
		}
	}

	// 2. allowed call: decision allow + committed evidence; effect 1; record verifies.
	allow := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{` + mcpMeta + `,"name":"ticket_lookup","arguments":{"ticket":"T-1"}}}`
	st, _, out := c.post("/mcp/proxy", "tools/call", "ticket_lookup", allow, nil)
	if st != 200 || out["result"] == nil {
		t.Fatalf("allowed call: %d %v", st, out)
	}
	if up.effects.Load() != 1 {
		t.Fatalf("effects = %d, want 1", up.effects.Load())
	}
	ext := govExt(out)
	if err := checkGovernance(ext, "allowed", "allow", false); err != nil {
		t.Fatalf("allowed extension: %v (%v)", err, ext)
	}
	meta := out["result"].(map[string]any)["_meta"].(map[string]any)
	if meta["com.vendor/trace"] != "t-1" || meta["io.modelcontextprotocol/serverInfo"] == nil {
		t.Fatalf("upstream _meta must be preserved next to the extension: %v", meta)
	}
	allowID := ext["evidence"].(map[string]any)["id"].(string)
	rec := readRecord(t, dbPath, allowID)
	if !rec.PolicyDecison.Allowed || rec.TenantID == "" || rec.CorrelationID == "" || len(rec.Explanations) == 0 {
		t.Fatalf("allowed record: %+v", rec)
	}
	if rec.Explanations[0].Code != ext["reasonCode"] {
		t.Fatalf("reasonCode %v != signed explanation %s", ext["reasonCode"], rec.Explanations[0].Code)
	}
	if o, stderr, code := RunTalon(t, dir, nil, "audit", "verify", allowID); code != 0 || !strings.Contains(o, "VALID") {
		t.Fatalf("audit verify %s: code=%d\n%s\n%s", allowID, code, o, stderr)
	}

	// 3. forbidden call: policy_denied, deny, non-retryable, alias; effect still 1.
	const sentinel = "sk-SMOKE-SENTINEL-SECRET-0001"
	deny := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{` + mcpMeta + `,"name":"delete_customer","arguments":{"token":"` + sentinel + `","reason":"line1\nline2"}}}`
	recordsBefore := countRecords(t, dbPath)
	st, _, out = c.post("/mcp/proxy", "tools/call", "delete_customer", deny, nil)
	if st != 200 || mcpErrCode(out) != -32000 {
		t.Fatalf("forbidden call: %d %v", st, out)
	}
	if msg := out["error"].(map[string]any)["message"].(string); msg != "tool not allowed by policy" {
		t.Fatalf("denial message must be the fixed public string, got %q", msg)
	}
	if raw, _ := json.Marshal(out); strings.Contains(string(raw), sentinel) {
		t.Fatalf("caller-supplied argument value echoed in the public denial: %s", raw)
	}
	if countRecords(t, dbPath) != recordsBefore+1 {
		t.Fatalf("a governed denial writes exactly one record")
	}
	ext = govExt(out)
	if err := checkGovernance(ext, "policy_denied", "deny", false); err != nil {
		t.Fatalf("denied extension: %v (%v)", err, ext)
	}
	if ext["provenance"] != "not_dispatched" {
		t.Fatalf("denial provenance = %v, want not_dispatched", ext["provenance"])
	}
	if data := out["error"].(map[string]any)["data"].(map[string]any); data["talon_code"] != "TALON_TOOL_FORBIDDEN" {
		t.Fatalf("deprecated alias: %v", data)
	}
	if up.effects.Load() != 1 {
		t.Fatalf("forbidden tool dispatched: effects = %d", up.effects.Load())
	}
	denyID := ext["evidence"].(map[string]any)["id"].(string)
	rec = readRecord(t, dbPath, denyID)
	if rec.PolicyDecison.Allowed || len(rec.Explanations) == 0 || rec.Explanations[0].Code != ext["reasonCode"] || rec.Explanations[0].Decision != "deny" {
		t.Fatalf("denied record disagrees with the extension: %+v vs %v", rec, ext)
	}
	if js := rawRecordJSON(t, dbPath, denyID); strings.Contains(js, sentinel) {
		t.Fatal("caller-supplied argument value stored in the signed denial record")
	}
	if o, _, code := RunTalon(t, dir, nil, "audit", "verify", denyID); code != 0 || !strings.Contains(o, "VALID") {
		t.Fatalf("audit verify %s: %d %s", denyID, code, o)
	}

	// 4. protocol errors: intact codes, no governance object, no effect.
	for name, tc := range map[string]struct {
		mcpName, body string
		extra         map[string]string
		status        int
		code          float64
	}{
		"header/body mismatch": {"ticket_lookup", strings.Replace(allow, `"name":"ticket_lookup"`, `"name":"delete_customer"`, 1), nil, 400, -32020},
		"unsupported version":  {"ticket_lookup", strings.Replace(allow, `"io.modelcontextprotocol/protocolVersion":"2026-07-28"`, `"io.modelcontextprotocol/protocolVersion":"2025-06-18"`, 1), map[string]string{"MCP-Protocol-Version": "2025-06-18"}, 400, -32022},
		"missing _meta":        {"ticket_lookup", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ticket_lookup","arguments":{}}}`, nil, 400, -32602},
		"invalid JSON":         {"ticket_lookup", `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{`, nil, 400, -32700},
	} {
		st, _, out := c.post("/mcp/proxy", "tools/call", tc.mcpName, tc.body, tc.extra)
		if st != tc.status || mcpErrCode(out) != tc.code {
			t.Fatalf("%s: %d %v", name, st, out)
		}
		if govExt(out) != nil {
			t.Fatalf("%s: a protocol error must not carry the governance extension: %v", name, out)
		}
		if data, _ := out["error"].(map[string]any)["data"].(map[string]any); data["talon_code"] != nil {
			t.Fatalf("%s: a protocol error must not carry the legacy alias: %v", name, data)
		}
	}
	// Unknown native tool: canonical resolution precedes governance — the
	// spec's invalid-params error, no governance object, no alias, no record.
	recordsBefore = countRecords(t, dbPath)
	st, _, out = c.post("/mcp", "tools/call", "no_such_tool", `{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{`+mcpMeta+`,"name":"no_such_tool","arguments":{}}}`, nil)
	if st != 400 || mcpErrCode(out) != -32602 || govExt(out) != nil {
		t.Fatalf("unknown native tool must be a protocol invalid-params error (HTTP 400, -32602) without a governance object: %d %v", st, out)
	}
	if data, _ := out["error"].(map[string]any)["data"].(map[string]any); data["talon_code"] != nil {
		t.Fatalf("unknown tool must not carry the legacy alias: %v", data)
	}
	if countRecords(t, dbPath) != recordsBefore {
		t.Fatal("an unresolvable tool must not leave a governance receipt")
	}
	if st, _, out := c.post("/mcp/proxy", "resources/read", "doc-1", `{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{`+mcpMeta+`,"uri":"doc-1"}}`, nil); st != 404 || mcpErrCode(out) != -32601 || govExt(out) != nil {
		t.Fatalf("unknown method: %d %v", st, out)
	}
	if up.effects.Load() != 1 {
		t.Fatalf("protocol errors dispatched: effects = %d", up.effects.Load())
	}

	// 5. ambiguous post-handoff outcome: effect happens, answer is severed.
	flaky := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{` + mcpMeta + `,"name":"flaky_update","arguments":{"id":"42"}}}`
	st, _, out = c.post("/mcp/proxy", "tools/call", "flaky_update", flaky, nil)
	if st != 200 || mcpErrCode(out) != -32000 {
		t.Fatalf("flaky call: %d %v", st, out)
	}
	ext = govExt(out)
	if err := checkGovernance(ext, "upstream_outcome_unknown", "unknown", false); err != nil {
		t.Fatalf("unknown extension: %v (%v)", err, ext)
	}
	if ext["provenance"] != "unknown" {
		t.Fatalf("provenance = %v, want unknown", ext["provenance"])
	}
	if msg := out["error"].(map[string]any)["message"].(string); strings.Contains(msg, "EOF") || strings.Contains(msg, "127.0.0.1") {
		t.Fatalf("raw transport detail crossed the public boundary: %q", msg)
	}
	if up.effects.Load() != 2 {
		t.Fatalf("effects = %d, want exactly 2 (one for the ambiguous call, no hidden retry)", up.effects.Load())
	}
	unknownID := ext["evidence"].(map[string]any)["id"].(string)
	rec = readRecord(t, dbPath, unknownID)
	if rec.Status != "unknown" || rec.FailureReason != "upstream_outcome_unknown" {
		t.Fatalf("unknown record status/failure_reason = %s/%s", rec.Status, rec.FailureReason)
	}
	if len(rec.Explanations) == 0 || rec.Explanations[0].Code != "EXECUTION_OUTCOME_UNKNOWN" || rec.Explanations[0].Decision != "unknown" || rec.Explanations[0].Code != ext["reasonCode"] {
		t.Fatalf("the signed explanation of an unknown outcome must say unknown, not failure: %+v (reasonCode %v)", rec.Explanations, ext["reasonCode"])
	}
	if o, _, code := RunTalon(t, dir, nil, "audit", "verify", unknownID); code != 0 || !strings.Contains(o, "VALID") {
		t.Fatalf("audit verify %s: %d %s", unknownID, code, o)
	}

	// 5b. vendor JSON-RPC error carrying protected data: the vendor's code
	// is preserved, its message/data are not relayed, Talon's record is
	// sanitized and verifies, exactly one effect.
	vendorErr := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{` + mcpMeta + `,"name":"vendor_error_tool","arguments":{"id":"7"}}}`
	st, _, out = c.post("/mcp/proxy", "tools/call", "vendor_error_tool", vendorErr, nil)
	if st != 200 || mcpErrCode(out) != -32001 {
		t.Fatalf("vendor error: the vendor's numeric code must be preserved: %d %v", st, out)
	}
	if raw, _ := json.Marshal(out); strings.Contains(string(raw), vendorToken) || strings.Contains(string(raw), vendorCustomer) || strings.Contains(string(raw), vendorEmail) {
		t.Fatalf("vendor error text or data relayed to the client: %s", raw)
	}
	if data := out["error"].(map[string]any)["data"].(map[string]any); data["customer"] != nil || data["detail"] != nil {
		t.Fatalf("vendor error.data relayed: %v", data)
	}
	ext = govExt(out)
	if err := checkGovernance(ext, "upstream_tool_failed", "failed", false); err != nil {
		t.Fatalf("vendor error extension: %v (%v)", err, ext)
	}
	if up.effects.Load() != 3 {
		t.Fatalf("effects = %d, want 3 (one vendor-error call, no hidden retry)", up.effects.Load())
	}
	vendorID := ext["evidence"].(map[string]any)["id"].(string)
	if js := rawRecordJSON(t, dbPath, vendorID); strings.Contains(js, vendorToken) {
		t.Fatal("credential from the vendor error stored in the signed record")
	}
	rec = readRecord(t, dbPath, vendorID)
	if rec.Status != "failed" || len(rec.Explanations) == 0 || rec.Explanations[0].Code != "EXECUTION_FAILED" {
		t.Fatalf("vendor error must be a trustworthy failure: %+v", rec)
	}
	if o, _, code := RunTalon(t, dir, nil, "audit", "verify", vendorID); code != 0 || !strings.Contains(o, "VALID") {
		t.Fatalf("audit verify %s: %d %s", vendorID, code, o)
	}

	// 6. tamper: corrupt the denial record; verification must fail, the
	// untouched allowed record must still verify. The short in-band subset
	// is never claimed verifiable by itself.
	stop()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE evidence SET evidence_json = replace(evidence_json, '"allowed":false', '"allowed":true') WHERE id = ?`, denyID); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if o, _, code := RunTalon(t, dir, nil, "audit", "verify", denyID); code == 0 || strings.Contains(o, "signature VALID") {
		t.Fatalf("tampered record must fail verification: code=%d\n%s", code, o)
	}
	if o, _, code := RunTalon(t, dir, nil, "audit", "verify", allowID); code != 0 || !strings.Contains(o, "VALID") {
		t.Fatalf("untouched record must still verify: %d %s", code, o)
	}

	// Negative fixture: the smoke's own assertion set rejects the defects it
	// exists to catch (missing id, uncommitted ref, wrong decision).
	for name, bad := range map[string]map[string]any{
		"missing id":       {"schemaVersion": float64(1), "code": "policy_denied", "decision": "deny", "retryable": false, "reasonCode": "X", "evidence": map[string]any{"committed": true}},
		"uncommitted":      {"schemaVersion": float64(1), "code": "policy_denied", "decision": "deny", "retryable": false, "reasonCode": "X", "evidence": map[string]any{"id": "req_1", "committed": false}},
		"retryable denial": {"schemaVersion": float64(1), "code": "policy_denied", "decision": "deny", "retryable": true, "reasonCode": "X", "evidence": map[string]any{"id": "req_1", "committed": true}},
		"signature leaked": {"schemaVersion": float64(1), "code": "policy_denied", "decision": "deny", "retryable": false, "reasonCode": "X", "signature": "hmac", "evidence": map[string]any{"id": "req_1", "committed": true}},
	} {
		if err := checkGovernance(bad, "policy_denied", "deny", false); err == nil {
			t.Fatalf("negative fixture %q passed; the smoke would not catch this defect", name)
		}
	}
}

//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
)

// OpenShell composed ACTION channel (#457/#482, Workstream A+B).
//
//	agent in sandbox → OpenShell network admission → Talon middleware hop
//	(verifies the gateway-signed sandbox identity, binds it to the use case,
//	mints a request-bound workload assertion) → OpenShell forwards to Talon's
//	Action Gateway carrying the assertion → policy → approval → at-most-once
//	dispatch to the protected service → signed lifecycle evidence.
//
// As in TestE2E_OpenShell_ComposedModelChannel, OpenShell itself is replayed
// by a fixture supervisor that follows the pinned contract (gateway JWT,
// EvaluateHttpRequest over real gRPC, header mutations applied as
// documented, forwarding only on ALLOW). Everything asserted about Talon is
// real. The real-runtime proof is the live lane's CASE G–M.
//
// Proves: a sandbox holding NO Talon secret authenticates to exactly its
// bound use case; ALLOW executes once under that identity; DENY and
// REQUIRE_APPROVAL dispatch nothing; the reviewer decision alone dispatches
// nothing; the approved claim dispatches once; exact replay never
// duplicates; an unbound sandbox, a sandbox-forged assertion, a tampered
// assertion and an assertion replayed against another route are refused
// before any domain state exists; a sandbox can never reach the reviewer
// route through the hop; action and model records of one sandbox session
// share the session spine and the verified runtime identity; records
// verify offline; the channel survives a Talon restart.

const (
	osActSelfHost = "talon.fixture.internal"
	osActSession  = "sess-openshell-e2e-0001"
	osSandboxB    = "sb-smoke-0002"
	hopHeader     = "X-Talon-Workload-Assertion"
)

type protectedService struct {
	srv     *httptest.Server
	tickets atomic.Int64
	refunds atomic.Int64
	deletes atomic.Int64
	idem    []string
}

func startProtectedService(t *testing.T) *protectedService {
	t.Helper()
	p := &protectedService{}
	mux := http.NewServeMux()
	mux.HandleFunc("/tickets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		p.tickets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ticket_id":"T-1842","status":"open"}`))
	})
	mux.HandleFunc("/refunds", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		p.idem = append(p.idem, r.Header.Get("Idempotency-Key"))
		p.refunds.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"refund_id":"rf_0001"}`))
	})
	mux.HandleFunc("/customers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		p.deletes.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// hopResult is what the fixture supervisor observed for one sandbox request
// addressed to Talon: the middleware result and, when forwarded, Talon's
// HTTP answer.
type hopResult struct {
	res       *middlewarev1.HttpRequestResult
	forwarded bool
	status    int
	body      map[string]any
	assertion string
}

// hop replays the OpenShell supervisor for one request from a sandbox to a
// destination host: network policy (fixture: the self host and the provider
// host are allowed), EvaluateHttpRequest with the gateway-signed token, then
// forwarding ONLY on ALLOW with the header mutations applied exactly as the
// contract documents (write/overwrite|append|skip, remove). talonHTTP is
// where the fixture's network reaches Talon's HTTP API.
func (s *fixtureSupervisor) hop(t *testing.T, token, sandbox, host, method, path, body string, headers map[string]string, talonHTTP string) hopResult {
	t.Helper()
	c := connect.NewClient[middlewarev1.HttpRequestEvaluation, middlewarev1.HttpRequestResult](s.client, s.talonURL+"/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest", connect.WithGRPC())
	hdrs := []*middlewarev1.HttpHeader{{Name: "content-type", Value: "application/json"}}
	for k, v := range headers {
		hdrs = append(hdrs, &middlewarev1.HttpHeader{Name: strings.ToLower(k), Value: v})
	}
	req := connect.NewRequest(&middlewarev1.HttpRequestEvaluation{
		Phase:          middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Context:        &middlewarev1.RequestContext{RequestId: fmt.Sprintf("req-%d", time.Now().UnixNano()), SandboxId: sandbox, Sandbox: "support-sandbox"},
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "http", Host: host, Port: 8080, Method: method, Path: path},
		Headers:        hdrs,
		Body:           []byte(body),
		MiddlewareName: "talon-governance",
	})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.CallUnary(ctx, req)
	if err != nil {
		t.Logf("middleware call failed (fail-closed): %v", err)
		return hopResult{status: http.StatusForbidden}
	}
	out := hopResult{res: res.Msg}
	if res.Msg.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
		out.status = http.StatusForbidden
		return out
	}
	hreq, _ := http.NewRequest(method, talonHTTP+path, strings.NewReader(body))
	for k, v := range headers {
		hreq.Header.Set(k, v)
	}
	hreq.Header.Set("Content-Type", "application/json")
	for _, m := range res.Msg.GetHeaderMutations() {
		if w := m.GetWrite(); w != nil {
			switch w.GetOnExisting() {
			case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_APPEND:
				hreq.Header.Add(w.GetName(), w.GetValue())
			case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_SKIP:
				if hreq.Header.Get(w.GetName()) == "" {
					hreq.Header.Set(w.GetName(), w.GetValue())
				}
			default:
				hreq.Header.Set(w.GetName(), w.GetValue())
			}
		}
		if r := m.GetRemove(); r != nil {
			hreq.Header.Del(r.GetName())
		}
	}
	out.assertion = hreq.Header.Get(hopHeader)
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatalf("forward to talon: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out.forwarded, out.status = true, resp.StatusCode
	_ = json.Unmarshal(raw, &out.body)
	if out.body == nil {
		out.body = map[string]any{"_raw": string(raw)}
	}
	return out
}

func exportRecords(t *testing.T, dir string) []map[string]any {
	t.Helper()
	export, _, code := RunTalon(t, dir, nil, "audit", "export", "--format", "signed-json")
	if code != 0 {
		t.Fatalf("audit export: %d", code)
	}
	var doc struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal([]byte(export), &doc); err != nil {
		t.Fatalf("export is not JSON: %v", err)
	}
	return doc.Records
}

//nolint:gocyclo // one sequential black-box scenario: each step depends on the state the previous one left in the running binary
func TestE2E_OpenShell_ComposedActionChannel(t *testing.T) {
	down := startProtectedService(t)
	provider := startFixtureProvider(t)
	sup := newFixtureSupervisor(t, provider)
	priv := sup.priv

	// 1. One AI use case: bound to sandbox A, with a trusted action catalog
	// and an approval rule. Sandbox B is deliberately NOT bound.
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", osAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	raw, _ := os.ReadFile(agentPath)
	yaml := string(raw)
	keyLine := fmt.Sprintf("  key:\n    secret_name: \"%s-talon-key\"\n", osAgent)
	for _, want := range []string{keyLine, "\ncapabilities:\n", "\npolicies:\n"} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("scaffold changed; expected %q:\n%s", want, yaml)
		}
	}
	yaml = strings.Replace(yaml, keyLine, keyLine+"  workload_identity:\n    bindings:\n      - runtime: openshell\n        subject: \""+osSubject+"\"\n", 1)
	yaml = strings.Replace(yaml, "\ncapabilities:\n", "\ncapabilities:\n  forbidden_tools: [delete_customer]\n", 1)
	yaml = strings.Replace(yaml, "\npolicies:\n", `
actions:
  definitions:
    lookup_ticket:
      description: Read one support ticket
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id]
        properties:
          ticket_id: {type: string}
      destination: {type: http, url: "`+down.srv.URL+`/tickets", method: POST, success: {status_codes: [200]}}
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
      destination: {type: http, url: "`+down.srv.URL+`/refunds", method: POST, success: {status_codes: [201]}}
    delete_customer:
      input_schema:
        type: object
        additionalProperties: false
        properties:
          customer_id: {type: string}
      destination: {type: http, url: "`+down.srv.URL+`/customers"}

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
		t.Fatalf("talon validate rejected the agent:\n%s", stderr)
	}
	jwksPath := filepath.Join(dir, "openshell-jwks.json")
	if err := os.WriteFile(jwksPath, sup.jwks(), 0o600); err != nil {
		t.Fatal(err)
	}
	osPort, httpPort := freePort(t), freePort(t)
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	cfg, _ := os.ReadFile(cfgPath)
	cfg = append(cfg, []byte(fmt.Sprintf(`
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    defaults:
      pii_action: "redact"
      daily_cost: 100.00
  openshell:
    enabled: true
    listen: "127.0.0.1:%d"
    allow_insecure_transport: true
    middleware_name: "talon"
    identity:
      issuer: %q
      audience: %q
      jwks_file: %q
    self_destination:
      hosts: [%q]
      assertion_ttl: 30s
`, osPort, osIssuer, osAudience, jwksPath, osActSelfHost))...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][2]string{{"openai-api-key", "sk-talon-vault-value-never-used-on-delegated-path"}, {osAgent + "-talon-key", "talon-gw-openshell-action-e2e-0001"}} {
		if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", kv[0], kv[1]); code != 0 {
			t.Fatalf("secrets set: %d\n%s", code, stderr)
		}
	}
	keyRe := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`)
	out, stderr, code := RunTalon(t, dir, nil, "approver", "add", "--name", "lead-1", "--tenant", "default", "--groups", "support-leads")
	if code != 0 {
		t.Fatalf("approver add: %d\n%s", code, stderr)
	}
	leadKey := keyRe.FindString(out)
	if leadKey == "" {
		t.Fatalf("approver credential not printed: %q", out)
	}

	stop := startServe(t, dir, httpPort)
	defer func() { stop() }()
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", osPort))
	sup.talonURL = fmt.Sprintf("http://127.0.0.1:%d", osPort)
	talonHTTP := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	tokenA := func() string { return sup.token(osSandbox, priv) }
	sess := map[string]string{"X-Talon-Session-ID": osActSession}
	records := func() int { return len(exportRecords(t, dir)) }

	// 2. Model request on the SAME sandbox session (joins the action
	// records below through the session spine).
	mr := sup.hop(t, tokenA(), osSandbox, "api.openai.com", "POST", "/v1/chat/completions",
		`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"summarize ticket T-1842"}]}`, sess, provider.server.URL)
	if !mr.forwarded || mr.res.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
		t.Fatalf("model request not admitted: %+v", mr)
	}
	modelEvidenceID := mr.res.GetMetadata()["talon_evidence_id"]

	// 3. Allowed read action: hop ALLOW carries an assertion; Talon creates
	// the operation under the bound use case WITHOUT any agent key, and the
	// claim dispatches exactly once.
	est := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations",
		`{"operation_id":"op-read-1","action":"lookup_ticket","arguments":{"ticket_id":"T-1842"}}`, sess, talonHTTP)
	if !est.forwarded || est.status != 201 || dig(est.body, "operation", "verdict") != "ALLOW" {
		t.Fatalf("allowed read establish: %+v", est)
	}
	if est.assertion == "" || !strings.HasPrefix(est.assertion, "v1.") {
		t.Fatalf("no workload assertion carried to Talon: %+v", est.res.GetHeaderMutations())
	}
	if est.res.GetMetadata()["talon_kind"] != "workload_hop" || est.res.GetMetadata()["talon_agent"] != osAgent {
		t.Fatalf("hop metadata: %v", est.res.GetMetadata())
	}
	readAssertion := est.assertion
	cl := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations/op-read-1/attempts", "", sess, talonHTTP)
	if cl.status != 200 || dig(cl.body, "attempt", "status") != "succeeded" {
		t.Fatalf("allowed read claim: %+v", cl)
	}
	if down.tickets.Load() != 1 {
		t.Fatalf("tickets dispatched = %d, want 1", down.tickets.Load())
	}

	// 4. Forbidden action: DENY, evidenced, zero dispatch; a claim is refused.
	den := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations",
		`{"operation_id":"op-del-1","action":"delete_customer","arguments":{"customer_id":"c-9"}}`, sess, talonHTTP)
	if den.status != 403 || dig(den.body, "operation", "verdict") != "DENY" {
		t.Fatalf("forbidden action: %+v", den)
	}
	if r := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations/op-del-1/attempts", "", sess, talonHTTP); r.status != 403 || errCode(r.body) != "policy_denied" {
		t.Fatalf("claim on denied: %+v", r)
	}
	if down.deletes.Load() != 0 {
		t.Fatal("a forbidden action reached the protected service")
	}

	// 5. Consequential action requiring approval: 202, zero dispatch; the
	// claim waits; the reviewer (a human credential, never the sandbox)
	// approves; approval alone dispatches nothing; the sandbox's claim then
	// dispatches exactly once; exact replay never duplicates.
	refund := `{"operation_id":"op-refund-1","action":"create_refund_request","arguments":{"ticket_id":"T-1842","amount":50.00,"currency":"EUR"}}`
	ap := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations", refund, sess, talonHTTP)
	if ap.status != 202 || dig(ap.body, "operation", "operation_status") != "awaiting_approval" {
		t.Fatalf("approval-required establish: %+v", ap)
	}
	approvalID, _ := dig(ap.body, "operation", "approval", "id").(string)
	opRef, _ := dig(ap.body, "operation", "operation_ref").(string)
	if approvalID == "" || opRef == "" {
		t.Fatalf("no approval/operation reference: %v", ap.body)
	}
	if r := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations/op-refund-1/attempts", "", sess, talonHTTP); r.status != 409 || errCode(r.body) != "approval_pending" {
		t.Fatalf("claim before approval: %+v", r)
	}
	// The sandbox can read its own approval state through the hop…
	if r := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "GET", "/v1/approvals/"+approvalID, "", sess, talonHTTP); r.status != 200 || dig(r.body, "approval", "status") != "pending" {
		t.Fatalf("approval read via hop: %+v", r)
	}
	// …but can never DECIDE through it, whatever credential it holds.
	if r := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/approvals/"+approvalID+"/decisions", `{"decision":"approve"}`, map[string]string{"Authorization": "Bearer " + leadKey}, talonHTTP); r.forwarded || r.res.GetReasonCode() != "self_destination_path_not_governed" {
		t.Fatalf("reviewer route reachable through the hop: %+v", r)
	}
	if down.refunds.Load() != 0 {
		t.Fatal("refund dispatched before approval")
	}
	c := &agClient{t: t, base: talonHTTP}
	st, res := c.do("POST", "/v1/approvals/"+approvalID+"/decisions", leadKey, `{"decision":"approve","reason":"verified with customer"}`)
	if st != 200 || dig(res, "operation", "operation_status") != "authorized" {
		t.Fatalf("approve: %d %v", st, res)
	}
	if down.refunds.Load() != 0 {
		t.Fatal("the reviewer decision itself dispatched")
	}
	if r := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations/op-refund-1/attempts", "", sess, talonHTTP); r.status != 200 || dig(r.body, "attempt", "status") != "succeeded" {
		t.Fatalf("approved claim: %+v", r)
	}
	if down.refunds.Load() != 1 {
		t.Fatalf("refunds dispatched = %d, want 1", down.refunds.Load())
	}
	if r := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations", refund, sess, talonHTTP); r.status != 200 || r.body["created"] != false {
		t.Fatalf("exact replay: %+v", r)
	}
	if r := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "POST", "/v1/action-operations/op-refund-1/attempts", "", sess, talonHTTP); r.status != 409 || errCode(r.body) != "operation_already_succeeded" {
		t.Fatalf("second claim: %+v", r)
	}
	if down.refunds.Load() != 1 {
		t.Fatalf("replay duplicated the effect: %d", down.refunds.Load())
	}

	// 6. Negative identity paths. Each leaves the record count unchanged
	// and dispatches nothing.
	before := records()
	// a. Unbound sandbox: denied at the hop, Talon's HTTP API never reached.
	if r := sup.hop(t, sup.token(osSandboxB, priv), osSandboxB, osActSelfHost, "POST", "/v1/action-operations",
		`{"operation_id":"op-b-1","action":"lookup_ticket","arguments":{"ticket_id":"T-1"}}`, nil, talonHTTP); r.forwarded || r.res.GetReasonCode() != "workload_identity_unbound" {
		t.Fatalf("unbound sandbox: %+v", r)
	}
	// b. Forged gateway token: denied at the hop.
	_, forgedPriv := newFixtureKeypair(t)
	if r := sup.hop(t, sup.token(osSandbox, forgedPriv), osSandbox, osActSelfHost, "POST", "/v1/action-operations",
		`{"operation_id":"op-f-1","action":"lookup_ticket","arguments":{"ticket_id":"T-1"}}`, nil, talonHTTP); r.forwarded || r.res.GetReasonCode() != "workload_identity_required" {
		t.Fatalf("forged token: %+v", r)
	}
	// c. Bypassing the hop with a sandbox-forged assertion: refused at ingress.
	direct := func(assertion, method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, talonHTTP+path, strings.NewReader(body))
		req.Header.Set(hopHeader, assertion)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if st, out := direct("v1.eyJhZ2VudCI6InNhbmRib3hlZC1zdXBwb3J0In0.Zm9yZ2Vk", "POST", "/v1/action-operations", `{"operation_id":"op-x-1","action":"lookup_ticket","arguments":{"ticket_id":"T-1"}}`); st != 401 || errCode(out) != "workload_identity_invalid" {
		t.Fatalf("forged assertion: %d %v", st, out)
	}
	// d. A genuine assertion, tampered.
	if st, out := direct(readAssertion[:len(readAssertion)-3]+"xyz", "POST", "/v1/action-operations", `{"operation_id":"op-read-1","action":"lookup_ticket","arguments":{"ticket_id":"T-1842"}}`); st != 401 || errCode(out) != "workload_identity_invalid" {
		t.Fatalf("tampered assertion: %d %v", st, out)
	}
	// e. A genuine assertion replayed against another route / another body.
	if st, out := direct(readAssertion, "POST", "/v1/action-operations/op-read-1/attempts", ""); st != 401 || errCode(out) != "workload_identity_invalid" {
		t.Fatalf("assertion replayed on another route: %d %v", st, out)
	}
	if st, out := direct(readAssertion, "POST", "/v1/action-operations", `{"operation_id":"op-read-9","action":"delete_customer","arguments":{"customer_id":"c-1"}}`); st != 401 || errCode(out) != "workload_identity_invalid" {
		t.Fatalf("assertion replayed with another body: %d %v", st, out)
	}
	// f. No credential at all.
	if st, out := c.do("POST", "/v1/action-operations", "", `{"operation_id":"op-n-1","action":"lookup_ticket","arguments":{"ticket_id":"T-1"}}`); st != 401 {
		t.Fatalf("no credential: %d %v", st, out)
	}
	if after := records(); after != before {
		t.Fatalf("negative paths wrote %d record(s)", after-before)
	}
	if down.tickets.Load() != 1 || down.refunds.Load() != 1 || down.deletes.Load() != 0 {
		t.Fatalf("negative paths dispatched: tickets=%d refunds=%d deletes=%d", down.tickets.Load(), down.refunds.Load(), down.deletes.Load())
	}

	// 7. Evidence: the action lifecycle records carry the verified runtime
	// identity and the sandbox's session, join the model record through
	// that session, verify offline, and contain no credential material.
	recs := exportRecords(t, dir)
	var modelInSession, actionsInSession int
	for _, r := range recs {
		if r["session_id"] != osActSession {
			continue
		}
		switch r["invocation_type"] {
		case "gateway":
			modelInSession++
			if r["id"] != modelEvidenceID {
				t.Errorf("unexpected model record in session: %v", r["id"])
			}
		case "action_lifecycle":
			actionsInSession++
			wi, _ := r["workload_identity"].(map[string]any)
			if wi["status"] != "verified" || wi["runtime"] != "openshell" || wi["subject"] != osSubject || wi["auth_method"] != "workload_hop_assertion" {
				t.Errorf("action record %v identity: %v", r["id"], wi)
			}
			enf, _ := r["enforcement"].(map[string]any)
			rt, _ := enf["runtime"].(map[string]any)
			if enf["provenance"] != "talon_enforced" || rt["type"] != "openshell" || rt["reference"] != osSandbox || rt["request_id"] == "" {
				t.Errorf("action record %v enforcement: %v", r["id"], enf)
			}
			al, _ := r["action_lifecycle"].(map[string]any)
			if al["identity_source"] != "workload_asserted" {
				t.Errorf("action record %v identity_source: %v", r["id"], al["identity_source"])
			}
		}
	}
	if modelInSession != 1 || actionsInSession < 8 {
		t.Fatalf("session join: model=%d actions=%d (want 1 and ≥8)", modelInSession, actionsInSession)
	}
	exportJSON, _ := json.Marshal(recs)
	logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	for _, leak := range []string{readAssertion, leadKey, "talon-gw-openshell-action-e2e-0001", providerSecretOwnedByRuntime} {
		if strings.Contains(string(exportJSON), leak) {
			t.Errorf("evidence export leaks %q", leak[:12])
		}
		if strings.Contains(string(logs), leak) {
			t.Errorf("serve log leaks %q", leak[:12])
		}
	}
	if strings.Contains(string(logs), "eyJ") {
		t.Errorf("serve log appears to contain a JWT")
	}
	if out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", "op-refund-1"); code != 0 || !strings.Contains(strings.ToUpper(out), "VALID") {
		t.Fatalf("audit verify --operation op-refund-1: %d\n%s\n%s", code, out, stderr)
	}
	show, _, _ := RunTalon(t, dir, nil, "audit", "show", modelEvidenceID)
	if !strings.Contains(show, "Workload Identity: verified | runtime=openshell | subject="+osSubject) {
		t.Errorf("model record projection:\n%s", show)
	}

	// 8. Restart: the hop and the assertion key are configuration, so a new
	// sandbox request is governed again; prior records still verify.
	stop()
	stop = startServe(t, dir, httpPort)
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", osPort))
	if r := sup.hop(t, tokenA(), osSandbox, osActSelfHost, "GET", "/v1/action-operations/op-refund-1", "", sess, talonHTTP); r.status != 200 || dig(r.body, "operation", "operation_status") != "succeeded" {
		t.Fatalf("after restart: %+v", r)
	}
	if out, _, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", "op-refund-1"); code != 0 || !strings.Contains(strings.ToUpper(out), "VALID") {
		t.Errorf("pre-restart lifecycle no longer verifies: %s", out)
	}
}

// newFixtureKeypair returns a fresh Ed25519 keypair (a gateway Talon does
// NOT trust, when used to sign).
func newFixtureKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// newFixtureSupervisor is the fixture OpenShell supervisor with its own
// gateway signing key and an h2c gRPC client for Talon's middleware.
func newFixtureSupervisor(t *testing.T, provider *fixtureProvider) *fixtureSupervisor {
	t.Helper()
	pub, priv := newFixtureKeypair(t)
	sup := &fixtureSupervisor{priv: priv, pub: pub, kid: "gw-smoke-k1", provider: provider}
	sup.client = &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	return sup
}

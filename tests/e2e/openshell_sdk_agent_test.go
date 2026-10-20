//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
)

// The real tool-using agent (#482, customer-demonstration gate).
//
// examples/openshell/agent is a support assistant built on the official
// OpenAI Go SDK: the MODEL chooses tools (chat-completions tool calling) and
// the agent executes every tool through Talon's Action Gateway. This test
// runs that agent binary against the built Talon binary through a FIXTURE
// GATEWAY — two plain-HTTP listeners that replay OpenShell's supervisor
// for whatever the agent sends (EvaluateHttpRequest with the gateway-signed
// sandbox identity, forwarding only on ALLOW with the header mutations
// applied, credential injection after Talon, the PRE_RETURN exchange for
// provider responses) — and a scripted provider whose tool choices are
// deterministic (look up the ticket, try a forbidden deletion, request the
// refund, answer). Everything asserted about Talon is real; OpenShell's
// side is the documented contract replayed. The live lane's case N runs the
// shell fixture agent against the released runtime.
//
// Proves the required journey: the agent holds no Talon, reviewer or
// provider credential; model requests are governed and settled; the
// forbidden tool is removed from what the model sees and, when the model
// asks for it anyway, denied before dispatch; the refund needs a human who
// approves from outside the sandbox; approval alone dispatches nothing; the
// agent's claim dispatches at most once; replay is safe; model and action
// records share the session and the sandbox identity; the operator
// reconstructs and verifies it all.

const (
	sdkAgentSession = "sess-sdk-agent-0001"
	sdkAgentOpID    = "agent-e2e"
)

// toolFixtureProvider is the deterministic model: it reads the conversation
// and returns the next scripted tool call (or the final answer), recording
// the tool list Talon let through.
type toolFixtureProvider struct {
	srv          *httptest.Server
	calls        atomic.Int64
	mu           sync.Mutex
	toolsOffered [][]string
	authHdrs     []string
	rawFirst     []byte
}

func startToolFixtureProvider(t *testing.T) *toolFixtureProvider {
	t.Helper()
	p := &toolFixtureProvider{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []map[string]any `json:"messages"`
			Tools    []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		_ = json.Unmarshal(raw, &req)
		var offered []string
		for _, tl := range req.Tools {
			offered = append(offered, tl.Function.Name)
		}
		toolResults := 0
		for _, m := range req.Messages {
			if m["role"] == "tool" {
				toolResults++
			}
		}
		p.mu.Lock()
		if p.rawFirst == nil {
			p.rawFirst = raw
		}
		p.toolsOffered = append(p.toolsOffered, offered)
		p.authHdrs = append(p.authHdrs, r.Header.Get("Authorization"))
		p.mu.Unlock()
		n := p.calls.Add(1)
		var msg string
		switch toolResults {
		case 0:
			msg = `{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_ticket","arguments":"{\"ticket_id\":\"T-1842\"}"}}]}`
		case 1:
			// The model asks for a tool it was NOT offered (Talon removed it).
			msg = `{"role":"assistant","content":null,"tool_calls":[{"id":"call_2","type":"function","function":{"name":"delete_customer","arguments":"{\"customer_id\":\"c-9\"}"}}]}`
		case 2:
			msg = `{"role":"assistant","content":null,"tool_calls":[{"id":"call_3","type":"function","function":{"name":"create_refund_request","arguments":"{\"ticket_id\":\"T-1842\",\"amount\":50,\"currency\":\"EUR\"}"}}]}`
		default:
			msg = `{"role":"assistant","content":"Ticket T-1842 handled: the EUR 50 refund request was approved by a reviewer and submitted once."}`
		}
		finish := "tool_calls"
		if toolResults >= 3 {
			finish = "stop"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"cmpl-tool-%d","object":"chat.completion","created":%d,"model":"gpt-4o-mini","choices":[{"index":0,"message":%s,"finish_reason":"%s"}],"usage":{"prompt_tokens":%d,"completion_tokens":12,"total_tokens":%d}}`,
			n, time.Now().Unix(), msg, finish, 40+10*toolResults, 52+10*toolResults)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// fixtureGateway replays OpenShell's supervisor for a real client process:
// one listener per logical destination. The agent dials the listener as it
// would dial the destination through OpenShell's network namespace.
type fixtureGateway struct {
	t         *testing.T
	sup       *fixtureSupervisor
	sandbox   string
	token     func() string
	seq       atomic.Int64
	talonHTTP string
	provider  *toolFixtureProvider
}

// listen starts one destination listener. kind is "provider" (credential
// injection after Talon, PRE_RETURN for the response) or "talon" (relay).
//
//nolint:gocyclo // one request pipeline: admission, mutations, forwarding, response hook
func (g *fixtureGateway) listen(logicalHost string, port int, backend, kind string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestID := fmt.Sprintf("req-%d-%d", time.Now().UnixNano(), g.seq.Add(1))
		hdrs := []*middlewarev1.HttpHeader{}
		for k, vs := range r.Header {
			lk := strings.ToLower(k)
			if lk == "host" || lk == "content-length" || lk == "accept-encoding" {
				continue
			}
			for _, v := range vs {
				hdrs = append(hdrs, &middlewarev1.HttpHeader{Name: lk, Value: v})
			}
		}
		c := connect.NewClient[middlewarev1.HttpRequestEvaluation, middlewarev1.HttpRequestResult](g.sup.client, g.sup.talonURL+"/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest", connect.WithGRPC())
		req := connect.NewRequest(&middlewarev1.HttpRequestEvaluation{
			Phase:          middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
			Context:        &middlewarev1.RequestContext{RequestId: requestID, SandboxId: g.sandbox, Sandbox: "support-sandbox"},
			Target:         &middlewarev1.HttpRequestTarget{Scheme: "http", Host: logicalHost, Port: uint32(port), Method: r.Method, Path: r.URL.RequestURI()},
			Headers:        hdrs,
			Body:           body,
			MiddlewareName: "talon-governance",
		})
		req.Header().Set("Authorization", "Bearer "+g.token())
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		res, err := c.CallUnary(ctx, req)
		if err != nil {
			// Fail closed, as OpenShell's on_error default does.
			writeGatewayError(w, http.StatusServiceUnavailable, "middleware_failed", err.Error())
			return
		}
		if res.Msg.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
			writeGatewayError(w, http.StatusForbidden, "middleware_denied", res.Msg.GetReasonCode())
			return
		}
		forward := body
		if res.Msg.GetHasBody() {
			forward = res.Msg.GetBody()
		}
		if kind == "provider" {
			g.t.Logf("fixture gateway: provider request %d bytes in, has_body=%v, %d bytes forwarded, tool_governance=%v", len(body), res.Msg.GetHasBody(), len(forward), res.Msg.GetMetadata())
		}
		hreq, _ := http.NewRequestWithContext(r.Context(), r.Method, backend+r.URL.RequestURI(), strings.NewReader(string(forward)))
		for k, vs := range r.Header {
			if lk := strings.ToLower(k); lk == "host" || lk == "content-length" {
				continue
			}
			for _, v := range vs {
				hreq.Header.Add(k, v)
			}
		}
		for _, m := range res.Msg.GetHeaderMutations() {
			if wr := m.GetWrite(); wr != nil {
				switch wr.GetOnExisting() {
				case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_APPEND:
					hreq.Header.Add(wr.GetName(), wr.GetValue())
				case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_SKIP:
					if hreq.Header.Get(wr.GetName()) == "" {
						hreq.Header.Set(wr.GetName(), wr.GetValue())
					}
				default:
					hreq.Header.Set(wr.GetName(), wr.GetValue())
				}
			}
			if rm := m.GetRemove(); rm != nil {
				hreq.Header.Del(rm.GetName())
			}
		}
		if kind == "provider" {
			// Credential injection: OpenShell's, after Talon, never before.
			hreq.Header.Set("Authorization", "Bearer "+providerSecretOwnedByRuntime)
		}
		resp, err := http.DefaultClient.Do(hreq)
		if err != nil {
			writeGatewayError(w, http.StatusBadGateway, "upstream_unreachable", err.Error())
			return
		}
		upstream, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if kind != "provider" {
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(upstream)
			return
		}
		status, delivered, meta := g.sup.preReturn(g.t, g.token(), &upstreamExchange{requestID: requestID, status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), body: upstream})
		if meta["talon_decision"] == "block" {
			writeGatewayError(w, http.StatusForbidden, "middleware_denied", "response blocked by Talon")
			return
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(status)
		_, _ = w.Write(delivered)
	}))
	g.t.Cleanup(srv.Close)
	return srv
}

func writeGatewayError(w http.ResponseWriter, status int, code, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "reason_code": reason})
}

// supportCatalogYAML is the use case's trusted action catalog for the
// support scenario (identical to the composed action channel test).
func supportCatalogYAML(downURL string) string {
	return `
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
      destination: {type: http, url: "` + downURL + `/tickets", method: POST, success: {status_codes: [200]}}
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
      destination: {type: http, url: "` + downURL + `/refunds", method: POST, success: {status_codes: [201]}}
    delete_customer:
      input_schema:
        type: object
        additionalProperties: false
        properties:
          customer_id: {type: string}
      destination: {type: http, url: "` + downURL + `/customers"}

policies:
  approvals:
    expires_after: 30m
    rules:
      refund-request:
        actions: [create_refund_request]
        approver_groups: [support-leads]
`
}

// buildSupportAgent builds examples/openshell/agent (its own Go module, so
// Talon's core never depends on the SDK) into a temp binary.
func buildSupportAgent(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "support-agent")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, ".")
	cmd.Dir = filepath.Join("..", "..", "examples", "openshell", "agent")
	cmd.Env = os.Environ()
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the SDK agent: %v\n%s", err, b)
	}
	return out
}

//nolint:gocyclo // one sequential black-box scenario: each step depends on the state the previous one left in the running binary
func TestE2E_OpenShell_SDKAgent(t *testing.T) {
	agentBin := buildSupportAgent(t)
	down := startProtectedService(t)
	model := startToolFixtureProvider(t)
	sup := newFixtureSupervisor(t, nil)
	priv := sup.priv

	// 1. The AI use case: bound to the sandbox, forbidden tool, catalog, approval rule.
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
	// The scaffold's allowed_tools is a hard allowlist: the use case must
	// name the tools its agent may offer the model.
	yaml = regexp.MustCompile(`(?m)^  allowed_tools:\n(    - .*\n)+`).ReplaceAllString(yaml, "  allowed_tools: [lookup_ticket, create_refund_request]\n")
	if !strings.Contains(yaml, "allowed_tools: [lookup_ticket, create_refund_request]") {
		t.Fatalf("scaffold allowed_tools block not rewritten:\n%s", yaml)
	}
	yaml = strings.Replace(yaml, "\npolicies:\n", supportCatalogYAML(down.srv.URL), 1)
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
    response_governance:
      enabled: true
      settlement_timeout: 30s
`, osPort, osIssuer, osAudience, jwksPath, osActSelfHost))...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][2]string{{"openai-api-key", "sk-talon-vault-value-never-used-on-delegated-path"}, {osAgent + "-talon-key", "talon-gw-openshell-sdk-e2e-0001"}} {
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

	// 2. The fixture gateway: what the sandbox dials for the provider and for Talon.
	gw := &fixtureGateway{t: t, sup: sup, sandbox: osSandbox, token: func() string { return sup.token(osSandbox, priv) }, talonHTTP: talonHTTP, provider: model}
	providerEdge := gw.listen("api.openai.com", 443, model.srv.URL, "provider")
	talonEdge := gw.listen(osActSelfHost, 8080, talonHTTP, "talon")

	// 3. Run the agent. It holds no Talon key, no reviewer credential, no
	// provider credential. The journey is split across THREE processes to
	// prove stable business identity: the first waits for approval and
	// times out (a crash while awaiting approval); the reviewer approves
	// from the HOST; the second process addresses the same operation and
	// claims it once; the third finds everything already done.
	stateDir := filepath.Join(t.TempDir(), "agent-state")
	runAgent := func(waitSeconds int) (string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, agentBin)
		cmd.Env = append([]string{}, "PATH="+os.Getenv("PATH"), "HOME="+os.Getenv("HOME"),
			"TALON_BASE="+talonEdge.URL, "PROVIDER_BASE="+providerEdge.URL, "TALON_SESSION="+sdkAgentSession,
			"OPERATION_ID="+sdkAgentOpID, "TICKET_ID=T-1842", "APPROVAL_WAIT_S="+fmt.Sprint(waitSeconds), "MAX_TURNS=8",
			"AGENT_STATE_DIR="+stateDir, "AGENT_ADVERSARIAL_PROBE=1", "OPENAI_API_KEY=placeholder-only")
		var stdoutBuf, stderrBuf strings.Builder
		cmd.Stdout, cmd.Stderr = &stdoutBuf, &stderrBuf
		err := cmd.Run()
		out := stdoutBuf.String()
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			t.Logf("agent> %s", line)
		}
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("agent: %v\nstderr:\n%s", err, stderrBuf.String())
		}
		return out, code
	}
	// Process 1: times out while awaiting approval (exit 3). Nothing dispatched.
	out1, code1 := runAgent(2)
	if code1 != 3 || !strings.Contains(out1, "RESULT=timeout APPROVAL=pending") {
		t.Fatalf("first agent process: exit %d\n%s", code1, out1)
	}
	approvalID := ""
	for _, line := range strings.Split(out1, "\n") {
		if strings.HasPrefix(line, "APPROVAL_ID=") {
			approvalID = strings.Fields(strings.TrimPrefix(line, "APPROVAL_ID="))[0]
		}
	}
	if approvalID == "" || down.refunds.Load() != 0 {
		t.Fatalf("no approval id or a refund before approval: %q refunds=%d", approvalID, down.refunds.Load())
	}
	// The reviewer approves from the host. Approval alone dispatches nothing.
	reviewer := &agClient{t: t, base: talonHTTP}
	st, res := reviewer.do("POST", "/v1/approvals/"+approvalID+"/decisions", leadKey, `{"decision":"approve","reason":"verified with customer"}`)
	if st != 200 || dig(res, "operation", "operation_status") != "authorized" {
		t.Fatalf("approve: %d %v", st, res)
	}
	if down.refunds.Load() != 0 {
		t.Fatalf("the reviewer decision itself dispatched")
	}
	// Process 2: same session, same prefix → the same operations; the read
	// is found succeeded (not re-dispatched), the refund is found authorized
	// and claimed once.
	out2, code2 := runAgent(60)
	if code2 != 0 {
		t.Fatalf("second agent process: exit %d\n%s", code2, out2)
	}
	for _, want := range []string{
		"RESUME=", "RESUMED=lookup_ticket", "ATTEMPT=already_succeeded TOOL=lookup_ticket",
		"DENIED=delete_customer",
		"RESUMED=create_refund_request", "STATUS=authorized",
		"ATTEMPT=succeeded TOOL=create_refund_request",
		"REPLAY=operation_already_succeeded",
		"ADVERSARIAL=denied TOOL=delete_customer",
		"FINAL=", "RESULT=succeeded",
	} {
		if !strings.Contains(out2, want) {
			t.Errorf("second agent process lacks %q:\n%s", want, out2)
		}
	}
	// Process 3: everything is already done; nothing is dispatched again.
	out3, code3 := runAgent(60)
	if code3 != 0 || !strings.Contains(out3, "ATTEMPT=already_succeeded TOOL=create_refund_request") {
		t.Fatalf("third agent process: exit %d\n%s", code3, out3)
	}
	output := out1 + "\n" + out2 + "\n" + out3
	if !strings.Contains(output, "TOOLS_OFFERED=lookup_ticket,create_refund_request,delete_customer") {
		t.Errorf("tools offered line missing")
	}
	// Process 1 stops after three turns (it times out inside the refund's
	// approval wait); processes 2 and 3 run four turns each.
	if n := strings.Count(output, "MODEL=ok"); n != 11 {
		t.Errorf("expected 11 governed model turns across three processes, got %d:\n%s", n, output)
	}
	refundOp := ""
	for _, line := range strings.Split(out2, "\n") {
		if strings.HasPrefix(line, "ATTEMPT=succeeded TOOL=create_refund_request OPERATION=") {
			refundOp = strings.TrimPrefix(line, "ATTEMPT=succeeded TOOL=create_refund_request OPERATION=")
		}
	}
	if !strings.HasPrefix(refundOp, sdkAgentOpID+"-create_refund_request-") {
		t.Fatalf("refund operation id must derive from the run prefix and the intent: %q", refundOp)
	}
	if !strings.Contains(out1, "OPERATION="+refundOp) || !strings.Contains(out3, "OPERATION="+refundOp) {
		t.Fatalf("all three processes must address the same refund operation %s", refundOp)
	}

	// 4. Side effects at the protected service: exactly one read, exactly
	// one refund, zero deletions.
	if down.tickets.Load() != 1 || down.refunds.Load() != 1 || down.deletes.Load() != 0 {
		t.Fatalf("protected service: tickets=%d refunds=%d deletes=%d", down.tickets.Load(), down.refunds.Load(), down.deletes.Load())
	}
	// 5. The model saw Talon-governed requests: the forbidden tool was
	// removed before the model, the runtime's credential was injected.
	model.mu.Lock()
	offered, auths := model.toolsOffered, model.authHdrs
	model.mu.Unlock()
	if len(offered) != 11 {
		t.Fatalf("model calls = %d, want 11", len(offered))
	}
	t.Logf("first provider request body (%d bytes): %.600s", len(model.rawFirst), model.rawFirst)
	for i, tl := range offered {
		if strings.Contains(strings.Join(tl, ","), "delete_customer") {
			t.Errorf("model call %d still offered the forbidden tool: %v", i, tl)
		}
		if !strings.Contains(strings.Join(tl, ","), "lookup_ticket") || !strings.Contains(strings.Join(tl, ","), "create_refund_request") {
			t.Errorf("model call %d lost an allowed tool: %v", i, tl)
		}
		if auths[i] != "Bearer "+providerSecretOwnedByRuntime {
			t.Errorf("model call %d did not carry the runtime-injected credential", i)
		}
	}

	// 6. Evidence: model decisions and settlements, action lifecycle under
	// the verified sandbox identity, one session, tool governance recorded,
	// no credential anywhere, verification VALID.
	recs := exportRecords(t, dir)
	var decisions, settlements, actions, toolsFiltered int
	for _, r := range recs {
		if r["session_id"] != sdkAgentSession {
			continue
		}
		switch r["invocation_type"] {
		case "gateway":
			decisions++
			if tg, _ := r["tool_governance"].(map[string]any); tg != nil {
				if f, _ := json.Marshal(tg["tools_filtered"]); strings.Contains(string(f), "delete_customer") {
					toolsFiltered++
				}
			}
			if ex, _ := r["execution"].(map[string]any); ex["pricing_basis"] != "awaiting_settlement" {
				t.Errorf("decision %v books cost before settlement: %v", r["id"], ex)
			}
		case "gateway_response":
			settlements++
			if ex, _ := r["execution"].(map[string]any); ex["cost"] == 0.0 {
				t.Errorf("settlement %v carries no priced actual: %v", r["id"], ex)
			}
		case "action_lifecycle":
			actions++
			wi, _ := r["workload_identity"].(map[string]any)
			if wi["status"] != "verified" || wi["subject"] != osSubject || wi["auth_method"] != "workload_hop_assertion" {
				t.Errorf("action record %v identity: %v", r["id"], wi)
			}
			enf, _ := r["enforcement"].(map[string]any)
			rt, _ := enf["runtime"].(map[string]any)
			if enf["provenance"] != "talon_enforced" || rt["reference"] != osSandbox {
				t.Errorf("action record %v enforcement: %v", r["id"], enf)
			}
		}
	}
	if decisions != 11 || settlements != 11 || toolsFiltered != 11 || actions < 10 {
		t.Fatalf("session evidence: decisions=%d settlements=%d toolsFiltered=%d actions=%d", decisions, settlements, toolsFiltered, actions)
	}
	exportJSON, _ := json.Marshal(recs)
	logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	for _, leak := range []string{leadKey, "talon-gw-openshell-sdk-e2e-0001", providerSecretOwnedByRuntime} {
		if strings.Contains(string(exportJSON), leak) || strings.Contains(string(logs), leak) || strings.Contains(output, leak) {
			t.Errorf("leak of %q in evidence, logs or agent output", leak[:12])
		}
	}
	if out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", refundOp); code != 0 || !strings.Contains(strings.ToUpper(out), "VALID") {
		t.Fatalf("audit verify --operation %s: %d\n%s\n%s", refundOp, code, out, stderr)
	}
	// 7. The operator's reconstruction surface for this sandbox: one
	// complete, verified walkthrough — identity, every model exchange with
	// its settlement, every operation with the human decision and the
	// downstream result, verification status.
	report, _, code := RunTalon(t, dir, nil, "audit", "list", "--runtime-ref", osSandbox, "--limit", "200", "--report")
	if code != 0 {
		t.Fatalf("audit list --runtime-ref --report: %d\n%s", code, report)
	}
	for _, want := range []string{
		"Runtime reference " + osSandbox + ": showing",
		"IDENTITY", "runtime=openshell issuer=" + osIssuer + " subject=" + osSubject + " auth=jwt_eddsa (verified by Talon)",
		"MODEL REQUESTS (11)", "tools_removed=[delete_customer]", "pricing=awaiting_settlement", "settlement gw_",
		"ACTIONS (3 operations)", refundOp + " action=create_refund_request verdict=REQUIRE_APPROVAL",
		"approval_decided", "reviewer=apr_", "group=support-leads approval=approved", "attempt=succeeded", "provenance=talon_enforced",
		sdkAgentOpID + "-delete_customer-", "action=delete_customer verdict=DENY",
		"IMPORTED RUNTIME EVENTS (0)",
		"VERIFICATION: ",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "UNVERIFIED") || strings.Contains(report, "More records exist") {
		t.Errorf("report contains an unverified record or is paginated:\n%s", report)
	}
	if m := regexp.MustCompile(`VERIFICATION: (\d+) of (\d+) records`).FindStringSubmatch(report); len(m) != 3 || m[1] != m[2] {
		t.Errorf("every record on the page must verify: %v", m)
	}
}

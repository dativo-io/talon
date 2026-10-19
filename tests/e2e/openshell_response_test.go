//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	extensionv1 "github.com/dativo-io/talon/internal/openshell/proto/gen/extensionv1"
	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
)

// OpenShell composed RESPONSE channel (#482 response side).
//
//	provider response → OpenShell PRE_RETURN hook → Talon (usage, cost,
//	response PII policy, settlement record) → OpenShell delivers, transforms
//	or blocks → sandbox
//
// The fixture supervisor replays the pinned HttpResponsePreReturn exchange
// exactly as documented: preflight with status/headers/permitted modes,
// the whole body held until Talon answers, the answer applied, trailers and
// session end. Everything asserted about Talon is real. The live lane's
// evidence assertions cover the released runtime.
//
// Proves: the decision record books no cost while a settlement is pending;
// the settlement carries the provider's actual usage priced from the table
// under the same correlation id; a response containing PII is transformed
// (redact) before the sandbox sees it, and the sandbox receives exactly
// Talon's replacement bytes; a response with no usage keeps the estimate and
// says so; the sum of costs over the session equals the settled actuals, not
// estimate plus actual; the records verify offline.

const osRespSession = "sess-openshell-response-0001"

type responseFixtureProvider struct {
	srv   *httptest.Server
	calls atomic.Int64
	// next is the body the next call returns.
	next atomic.Value
	// status is the HTTP status of the next call (0 = 200).
	status atomic.Int64
}

func startResponseFixtureProvider(t *testing.T) *responseFixtureProvider {
	t.Helper()
	p := &responseFixtureProvider{}
	p.next.Store(`{"id":"cmpl-1","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":1}}`)
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		p.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if st := p.status.Load(); st != 0 {
			w.WriteHeader(int(st))
		}
		_, _ = w.Write([]byte(p.next.Load().(string)))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// forwardAndReturn is the fixture's full round trip for one sandbox model
// request: EvaluateHttpRequest (with the hop's header mutations applied to
// the forwarded request), the provider call, then the PRE_RETURN exchange
// with Talon for the provider's response. It returns what the sandbox would
// receive and the response-side middleware metadata.
//
//nolint:gocyclo // one sequential black-box scenario: each step depends on the state the previous one left in the running binary
func (s *fixtureSupervisor) forwardAndReturn(t *testing.T, token, body string, provider *responseFixtureProvider) (deliveredStatus int, delivered []byte, reqMeta, respMeta map[string]string) {
	t.Helper()
	up := s.forward(t, token, body, provider)
	deliveredStatus, delivered, respMeta = s.preReturn(t, token, up)
	return deliveredStatus, delivered, up.reqMeta, respMeta
}

// upstreamExchange is the request half of one sandbox exchange: the runtime
// request id Talon keyed its settlement on, and what the provider answered.
type upstreamExchange struct {
	requestID   string
	status      int
	contentType string
	body        []byte
	reqMeta     map[string]string
}

// forward runs EvaluateHttpRequest and the provider call.
func (s *fixtureSupervisor) forward(t *testing.T, token, body string, provider *responseFixtureProvider) *upstreamExchange {
	t.Helper()
	requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	c := connect.NewClient[middlewarev1.HttpRequestEvaluation, middlewarev1.HttpRequestResult](s.client, s.talonURL+"/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest", connect.WithGRPC())
	req := connect.NewRequest(&middlewarev1.HttpRequestEvaluation{
		Phase:          middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Context:        &middlewarev1.RequestContext{RequestId: requestID, SandboxId: osSandbox},
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "https", Host: "api.openai.com", Port: 443, Method: "POST", Path: "/v1/chat/completions"},
		Headers:        []*middlewarev1.HttpHeader{{Name: "content-type", Value: "application/json"}, {Name: "x-talon-session-id", Value: osRespSession}, {Name: "accept-encoding", Value: "gzip"}},
		Body:           []byte(body),
		MiddlewareName: "talon-governance",
	})
	req.Header().Set("Authorization", "Bearer "+token)
	res, err := c.CallUnary(context.Background(), req)
	if err != nil {
		t.Fatalf("request hook: %v", err)
	}
	if res.Msg.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
		t.Fatalf("request denied: %v", res.Msg)
	}
	reqMeta := res.Msg.GetMetadata()
	forward := body
	if res.Msg.GetHasBody() {
		forward = string(res.Msg.GetBody())
	}
	hreq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, provider.srv.URL+"/v1/chat/completions", strings.NewReader(forward))
	hreq.Header.Set("Authorization", "Bearer "+providerSecretOwnedByRuntime)
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept-Encoding", "gzip")
	for _, m := range res.Msg.GetHeaderMutations() {
		if w := m.GetWrite(); w != nil {
			hreq.Header.Set(w.GetName(), w.GetValue())
		}
	}
	if hreq.Header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("the hop must ask for an uncompressed response, got %q", hreq.Header.Get("Accept-Encoding"))
	}
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	upstreamBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return &upstreamExchange{requestID: requestID, status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), body: upstreamBody, reqMeta: reqMeta}
}

// preReturn runs the PRE_RETURN exchange for one upstream answer. Calling
// it twice for the same exchange is the runtime repeating a callback.
func (s *fixtureSupervisor) preReturn(t *testing.T, token string, up *upstreamExchange) (deliveredStatus int, delivered []byte, respMeta map[string]string) {
	t.Helper()
	requestID, upstreamBody := up.requestID, up.body
	resp := struct {
		StatusCode int
		Header     http.Header
	}{StatusCode: up.status, Header: http.Header{"Content-Type": []string{up.contentType}}}
	rc := connect.NewClient[middlewarev1.HttpResponseEvent, middlewarev1.HttpResponseEventResult](s.client, s.talonURL+"/openshell.middleware.v1.HttpResponsePreReturn/Evaluate", connect.WithGRPC())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st := rc.CallBidiStream(ctx)
	st.RequestHeader().Set("Authorization", "Bearer "+token)
	if err := st.Send(&middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Preflight{Preflight: &middlewarev1.HttpResponsePreflight{
		Context:        &middlewarev1.RequestContext{RequestId: requestID, SandboxId: osSandbox},
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "https", Host: "api.openai.com", Port: 443, Method: "POST", Path: "/v1/chat/completions"},
		StatusCode:     uint32(resp.StatusCode),
		Headers:        []*middlewarev1.HttpHeader{{Name: "content-type", Value: resp.Header.Get("Content-Type")}},
		MiddlewareName: "talon-governance",
		PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY,
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES,
		},
	}}}); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	pr, err := st.Receive()
	if err != nil {
		t.Fatalf("preflight result: %v", err)
	}
	pres := pr.GetPreflightResult()
	if pres == nil {
		t.Fatalf("no preflight result: %v", pr)
	}
	respMeta = pres.GetMetadata()
	switch {
	case pres.GetBlockDelivery() != nil:
		return http.StatusForbidden, nil, respMeta
	case pres.GetSkip() != nil:
		return resp.StatusCode, upstreamBody, respMeta
	}
	if pres.GetInspect().GetBodyMode() != middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES {
		t.Fatalf("expected whole-body inspection for a JSON response, got %v", pres.GetInspect().GetBodyMode())
	}
	if err := st.Send(&middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Body{Body: &middlewarev1.HttpResponseBodyUnit{Sequence: 1, Payload: &middlewarev1.HttpResponseBodyUnit_Data{Data: upstreamBody}, EndOfStream: true}}}); err != nil {
		t.Fatalf("body: %v", err)
	}
	br, err := st.Receive()
	if err != nil {
		t.Fatalf("body result: %v", err)
	}
	bres := br.GetBodyResult()
	if bres == nil {
		t.Fatalf("no body result: %v", br)
	}
	for k, v := range bres.GetMetadata() {
		respMeta[k] = v
	}
	_ = st.Send(&middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_SessionEnd{SessionEnd: &middlewarev1.MiddlewareSessionEnd{Reason: middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL}}})
	_ = st.CloseRequest()
	switch {
	case bres.GetBlockDelivery() != nil:
		return http.StatusForbidden, nil, respMeta
	case bres.GetTransform() != nil:
		return resp.StatusCode, bres.GetTransform().GetData(), respMeta
	default:
		return resp.StatusCode, upstreamBody, respMeta
	}
}

//nolint:gocyclo // one sequential black-box scenario: each step depends on the state the previous one left in the running binary
func TestE2E_OpenShell_ResponseGovernance(t *testing.T) {
	provider := startResponseFixtureProvider(t)
	sup := newFixtureSupervisor(t, nil)
	priv := sup.priv
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", osAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	agentYAML, _ := os.ReadFile(agentPath)
	keyLine := fmt.Sprintf("  key:\n    secret_name: \"%s-talon-key\"\n", osAgent)
	if !strings.Contains(string(agentYAML), keyLine) {
		t.Fatalf("scaffold changed:\n%s", agentYAML)
	}
	binding := keyLine + "  workload_identity:\n    bindings:\n      - runtime: openshell\n        subject: \"" + osSubject + "\"\n"
	if err := os.WriteFile(agentPath, []byte(strings.Replace(string(agentYAML), keyLine, binding, 1)), 0o600); err != nil {
		t.Fatal(err)
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
    response_governance:
      enabled: true
      settlement_timeout: 30s
`, osPort, osIssuer, osAudience, jwksPath))...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][2]string{{"openai-api-key", "sk-talon-vault-value-never-used-on-delegated-path"}, {osAgent + "-talon-key", "talon-gw-openshell-resp-e2e-0001"}} {
		if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", kv[0], kv[1]); code != 0 {
			t.Fatalf("secrets set: %d\n%s", code, stderr)
		}
	}
	stop := startServe(t, dir, httpPort)
	defer func() { stop() }()
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", osPort))
	sup.talonURL = fmt.Sprintf("http://127.0.0.1:%d", osPort)
	token := func() string { return sup.token(osSandbox, priv) }

	// 1. Manifest: both bindings.
	dc := connect.NewClient[middlewarev1.MiddlewareDescribeRequest, middlewarev1.MiddlewareManifest](sup.client, sup.talonURL+"/openshell.middleware.v1.SupervisorMiddleware/Describe", connect.WithGRPC())
	manifest, err := dc.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.MiddlewareDescribeRequest{Gateway: &extensionv1.PeerMetadata{
		ProtocolVersion: &extensionv1.ProtocolVersion{Major: 1, Minor: 0}, ImplementationName: "openshell/gateway", ImplementationVersion: "0.1.3",
		SupportedCapabilities: []string{"openshell.supervisor-middleware.contract"}, RequiredCapabilities: []string{"openshell.supervisor-middleware.contract"},
	}}))
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if n := len(manifest.Msg.GetBindings()); n != 2 {
		t.Fatalf("bindings = %d, want 2 (request + response)", n)
	}

	// 2. Clean response with usage: delivered unchanged; decision booked no
	// cost; settlement carries actual tokens priced from the table.
	status, delivered, reqMeta, respMeta := sup.forwardAndReturn(t, token(), `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`, provider)
	if status != 200 || !strings.Contains(string(delivered), `"content":"ok"`) {
		t.Fatalf("clean response: %d %s", status, delivered)
	}
	if reqMeta["talon_response_governance"] != "pending" || respMeta["talon_decision"] != "pass" || respMeta["talon_evidence_id"] == "" {
		t.Fatalf("metadata: req=%v resp=%v", reqMeta, respMeta)
	}
	decisionID, settlementID := reqMeta["talon_evidence_id"], respMeta["talon_evidence_id"]

	// 3. Response carrying PII under a redact policy: the sandbox receives
	// Talon's replacement, never the value; usage still settled.
	const email = "jane.doe@example.com"
	provider.next.Store(`{"id":"cmpl-2","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"please contact ` + email + ` about the refund"}}],"usage":{"prompt_tokens":9,"completion_tokens":12}}`)
	status, delivered, _, respMeta = sup.forwardAndReturn(t, token(), `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"who do I contact"}]}`, provider)
	if status != 200 || strings.Contains(string(delivered), email) || respMeta["talon_decision"] != "transform" {
		t.Fatalf("pii response: %d %s meta=%v", status, delivered, respMeta)
	}
	if !strings.Contains(string(delivered), "refund") || !strings.Contains(string(delivered), `"usage"`) {
		t.Fatalf("replacement body lost content or envelope: %s", delivered)
	}
	redactedSettlementID := respMeta["talon_evidence_id"]

	// 4. Response without usage: delivered; the estimate stands and the
	// record says so.
	provider.next.Store(`{"id":"cmpl-3","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"no usage here"}}]}`)
	status, _, _, respMeta = sup.forwardAndReturn(t, token(), `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"again"}]}`, provider)
	if status != 200 || respMeta["talon_pricing_basis"] != "estimate_no_usage" {
		t.Fatalf("no-usage response: %d meta=%v", status, respMeta)
	}

	// 4b. Talon restarts while a preventive response is in flight: the
	// decision is made, the provider has answered with PII, and only then
	// does the new process see the response. The ledger row (and the
	// redact policy in force at decision time) survived in the evidence
	// store: the body is still held, scanned and transformed, and the
	// settlement joins the pre-restart decision — never decision_unmatched,
	// never a skip.
	provider.next.Store(`{"id":"cmpl-4","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"after the restart mail ` + email + `"}}],"usage":{"prompt_tokens":4,"completion_tokens":8}}`)
	inflight := sup.forward(t, token(), `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"restart me"}]}`, provider)
	stop()
	stop = startServe(t, dir, httpPort)
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", osPort))
	status, delivered, respMeta = sup.preReturn(t, token(), inflight)
	if status != 200 || strings.Contains(string(delivered), email) || respMeta["talon_decision"] != "transform" {
		t.Fatalf("in-flight response after restart: %d %s meta=%v", status, delivered, respMeta)
	}
	restartDecisionID, restartSettlementID := inflight.reqMeta["talon_evidence_id"], respMeta["talon_evidence_id"]

	// 4c. The runtime repeats the callback for the same exchange: the
	// recorded verdict is reproduced (same replacement, same evidence id),
	// nothing is written and nothing is counted twice.
	status, deliveredAgain, respMetaAgain := sup.preReturn(t, token(), inflight)
	if status != 200 || !bytes.Equal(deliveredAgain, delivered) || respMetaAgain["talon_replayed"] != "true" || respMetaAgain["talon_evidence_id"] != restartSettlementID {
		t.Fatalf("duplicate callback: %d %s meta=%v (first evidence %s)", status, deliveredAgain, respMetaAgain, restartSettlementID)
	}

	// 4d. A provider error body that echoes PII is not exempt from the
	// response policy: under redact it is blocked (a vendor error envelope
	// is not rewritten), nothing is billed, and the record says so.
	provider.status.Store(http.StatusBadRequest)
	provider.next.Store(`{"error":{"message":"invalid request: the input mentions ` + email + `","type":"invalid_request_error"}}`)
	status, delivered, _, respMeta = sup.forwardAndReturn(t, token(), `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"trigger an error"}]}`, provider)
	provider.status.Store(0)
	if status != http.StatusForbidden || len(delivered) != 0 || respMeta["talon_decision"] != "block" {
		t.Fatalf("error body with PII must be blocked under redact: %d %s meta=%v", status, delivered, respMeta)
	}
	errorSettlementID := respMeta["talon_evidence_id"]

	// 5. Evidence.
	recs := exportRecords(t, dir)
	byID := map[string]map[string]any{}
	for _, r := range recs {
		if id, _ := r["id"].(string); id != "" {
			byID[id] = r
		}
	}
	dec, set := byID[decisionID], byID[settlementID]
	if dec == nil || set == nil {
		t.Fatalf("records missing: decision=%v settlement=%v", dec != nil, set != nil)
	}
	exec := func(r map[string]any) map[string]any { m, _ := r["execution"].(map[string]any); return m }
	if exec(dec)["cost"] != 0.0 || exec(dec)["pricing_basis"] != "awaiting_settlement" {
		t.Fatalf("decision record must book no cost while settling: %v", exec(dec))
	}
	if dec["correlation_id"] != set["correlation_id"] || set["invocation_type"] != "gateway_response" {
		t.Fatalf("settlement does not join its decision: %v / %v", dec["correlation_id"], set["correlation_id"])
	}
	tokens, _ := exec(set)["tokens"].(map[string]any)
	if tokens["input"] != 5.0 || tokens["output"] != 1.0 {
		t.Fatalf("settlement tokens: %v", tokens)
	}
	if cost, _ := exec(set)["cost"].(float64); cost <= 0 || exec(set)["pricing_basis"] == "awaiting_settlement" || exec(set)["pricing_basis"] == "estimate_no_usage" {
		t.Fatalf("settlement must carry a priced actual: %v", exec(set))
	}
	if est, _ := exec(set)["estimated_cost"].(float64); est <= 0 {
		t.Fatalf("settlement keeps the estimate visible: %v", exec(set))
	}
	rdec, rset := byID[restartDecisionID], byID[restartSettlementID]
	if rdec == nil || rset == nil || rdec["correlation_id"] != rset["correlation_id"] {
		t.Fatalf("the post-restart settlement must join its pre-restart decision: %v / %v", rdec, rset)
	}
	annotations := func(r map[string]any) string { a, _ := json.Marshal(r["gateway_annotations"]); return string(a) }
	if strings.Contains(annotations(rset), "decision_unmatched") || !strings.Contains(annotations(rset), "response_observed") {
		t.Fatalf("post-restart settlement annotations: %s", annotations(rset))
	}
	if rtokens, _ := exec(rset)["tokens"].(map[string]any); rtokens["input"] != 4.0 || rtokens["output"] != 8.0 {
		t.Fatalf("post-restart settlement tokens: %v", rtokens)
	}
	eset := byID[errorSettlementID]
	if eset == nil || eset["status"] != "failed" || exec(eset)["cost"] != 0.0 {
		t.Fatalf("error settlement: %v", eset)
	}
	if ecls, _ := eset["classification"].(map[string]any); ecls["output_pii_detected"] != true {
		t.Fatalf("error settlement must record the PII it blocked: %v", eset["classification"])
	}
	if !strings.Contains(annotations(eset), "provider_error_body_scanned") {
		t.Fatalf("error settlement annotations: %s", annotations(eset))
	}
	for _, r := range recs {
		if r["invocation_type"] == "gateway_response" && strings.Contains(annotations(r), "decision_unmatched") {
			t.Fatalf("no settlement may lose its request half: %v", r["id"])
		}
	}
	rs := byID[redactedSettlementID]
	cls, _ := rs["classification"].(map[string]any)
	if cls["output_pii_detected"] != true {
		t.Fatalf("redacted settlement classification: %v", cls)
	}
	scan, _ := cls["response_scan"].(map[string]any)
	if scan["enforcement"] != "preventive" {
		t.Fatalf("response scan enforcement: %v", scan)
	}
	var sessionCost, sessionDecisions, sessionSettlements float64
	for _, r := range recs {
		if r["session_id"] != osRespSession {
			continue
		}
		switch r["invocation_type"] {
		case "gateway":
			sessionDecisions++
		case "gateway_response":
			sessionSettlements++
		}
		c, _ := exec(r)["cost"].(float64)
		sessionCost += c
	}
	if sessionDecisions != 5 || sessionSettlements != 5 {
		t.Fatalf("session records: decisions=%v settlements=%v (the duplicate callback must not add a record)", sessionDecisions, sessionSettlements)
	}
	var settledSum float64
	for _, id := range []string{settlementID, redactedSettlementID} {
		c, _ := exec(byID[id])["cost"].(float64)
		settledSum += c
	}
	if sessionCost <= settledSum {
		t.Fatalf("session cost %v must be the settled actuals (%v) plus the estimate of the no-usage response, never estimate plus actual", sessionCost, settledSum)
	}
	exportJSON, _ := json.Marshal(recs)
	logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	for _, leak := range []string{email, providerSecretOwnedByRuntime, "talon-gw-openshell-resp-e2e-0001"} {
		if strings.Contains(string(exportJSON), leak) || strings.Contains(string(logs), leak) {
			t.Errorf("leak of %q in evidence or logs", leak)
		}
	}
	for _, id := range []string{decisionID, settlementID, redactedSettlementID, restartSettlementID, errorSettlementID} {
		if out, _, code := RunTalon(t, dir, nil, "audit", "verify", id); code != 0 || !strings.Contains(strings.ToUpper(out), "VALID") {
			t.Errorf("audit verify %s: %d %s", id, code, out)
		}
	}
	show, _, _ := RunTalon(t, dir, nil, "audit", "show", settlementID)
	if !strings.Contains(show, "gateway_response") {
		t.Errorf("audit show of the settlement:\n%s", show)
	}
	if provider.calls.Load() != 5 {
		t.Fatalf("provider calls = %d, want 5 (a repeated callback never re-reaches the provider)", provider.calls.Load())
	}
}

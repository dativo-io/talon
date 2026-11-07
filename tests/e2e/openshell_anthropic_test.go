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
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
)

// OpenShell composed model channel on the ANTHROPIC wire (#528): what the
// real Claude Code executable sends through OpenShell's PRE_CREDENTIALS hook,
// replayed by the fixture supervisor against the built Talon binary.
//
//	claude → POST /v1/messages?beta=true (x-api-key placeholder, anthropic-version,
//	         anthropic-beta, stream:true, system blocks with cache_control, tools,
//	         metadata) → OpenShell → Talon EvaluateHttpRequest → OpenShell injects
//	         x-api-key → provider (SSE) → PRE_RETURN → Talon settles → claude
//
// The request and response bodies are the shapes observed from
// claude-cli/2.1.319 (see scripts/openshell-live-claude-code.sh for the
// same path against the released runtime and the real executable). This
// test proves Talon's side offline in every CI run: the Anthropic family is
// selected by the provider's hostname, the Claude-Code-shaped body is
// parsed, PII inside a content block is redacted into a body that is still
// a valid Anthropic request, a company blocked_models DENY produces zero
// provider calls, count_tokens is governed at cost 0, the SSE answer is
// settled with the usage split across message_start/message_delta, and a
// truncated stream is never settled as the full answer. OpenShell's side is
// the documented contract replayed; the live lane replaces the replay.

const osAnthropicSession = "sess-openshell-claude-0001"

// anthropicFixtureProvider is the deterministic Anthropic Messages endpoint
// behind the fixture supervisor: it counts calls, records what reached it
// and answers JSON or the SSE event sequence (usage 12 in / 3 out).
type anthropicFixtureProvider struct {
	srv      *httptest.Server
	mu       sync.Mutex
	calls    int
	paths    []string
	queries  []string
	apiKeys  []string
	bodies   []string
	truncate bool
	// responsePII makes the streamed answer carry an e-mail address (the
	// provider echoing PII), for the guarded-stream case.
	responsePII bool
}

func startAnthropicFixtureProvider(t *testing.T) *anthropicFixtureProvider {
	t.Helper()
	p := &anthropicFixtureProvider{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.calls++
		seq := p.calls
		p.paths = append(p.paths, r.URL.Path)
		p.queries = append(p.queries, r.URL.RawQuery)
		p.apiKeys = append(p.apiKeys, r.Header.Get("x-api-key"))
		p.bodies = append(p.bodies, string(body))
		truncate, responsePII := p.truncate, p.responsePII
		p.mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/count_tokens") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"input_tokens":42}`))
			return
		}
		var req struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.Unmarshal(body, &req)
		text := fmt.Sprintf("mock anthropic completion %d", seq)
		if responsePII {
			text = "please contact jane.doe@example.com about the refund"
		}
		if !req.Stream {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"id":"msg_%d","type":"message","role":"assistant","model":%q,"content":[{"type":"text","text":%q}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":3}}`, seq, req.Model, text)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		var b strings.Builder
		ev := func(name, data string) { fmt.Fprintf(&b, "event: %s\ndata: %s\n\n", name, data) }
		ev("message_start", fmt.Sprintf(`{"type":"message_start","message":{"id":"msg_%d","type":"message","role":"assistant","model":%q,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":1}}}`, seq, req.Model))
		ev("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		ev("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, text))
		if truncate {
			_, _ = w.Write([]byte(b.String()))
			return // no content_block_stop, message_delta or message_stop
		}
		ev("content_block_stop", `{"type":"content_block_stop","index":0}`)
		ev("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":3}}`)
		ev("message_stop", `{"type":"message_stop"}`)
		_, _ = w.Write([]byte(b.String()))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *anthropicFixtureProvider) snapshot() (calls int, paths, queries, apiKeys, bodies []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, append([]string(nil), p.paths...), append([]string(nil), p.queries...), append([]string(nil), p.apiKeys...), append([]string(nil), p.bodies...)
}

// claudeCodeRequest is the request body shape claude-cli/2.1.319 sends in
// print mode (observed): top-level model, max_tokens, stream, system as an
// array of text blocks with cache_control, tools, metadata.user_id, and the
// prompt as a user message. Only the prompt varies here.
func claudeCodeRequest(model, prompt string, stream bool) string {
	return fmt.Sprintf(`{"model":%q,"max_tokens":32000,"stream":%t,"system":[{"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude.","cache_control":{"type":"ephemeral"}}],"tools":[{"name":"Bash","description":"Run a shell command","input_schema":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}],"metadata":{"user_id":"user_fixture_account__session_0659d481"},"messages":[{"role":"user","content":[{"type":"text","text":%q}]}],"temperature":1}`, model, stream, prompt)
}

// anthropicExchange replays one sandbox exchange on the Anthropic wire:
// EvaluateHttpRequest with Claude Code's headers and target, the provider
// call with OpenShell's x-api-key injection (after Talon, never before), and
// the PRE_RETURN exchange for the provider's answer (whole body or stream
// units, as Talon asks). It returns Talon's request result, the status and
// bytes the sandbox would receive, and both hooks' metadata.
//
//nolint:gocyclo // one sequential replay of the documented exchange
func anthropicExchange(t *testing.T, sup *fixtureSupervisor, provider *anthropicFixtureProvider, token, path, query, body string) (reqRes *middlewarev1.HttpRequestResult, deliveredStatus int, delivered []byte, respMeta map[string]string) {
	t.Helper()
	requestID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	headers := []*middlewarev1.HttpHeader{
		{Name: "content-type", Value: "application/json"},
		{Name: "accept", Value: "application/json"},
		{Name: "anthropic-version", Value: "2023-06-01"},
		{Name: "anthropic-beta", Value: "claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27"},
		{Name: "user-agent", Value: "claude-cli/2.1.319 (external, sdk-cli)"},
		{Name: "x-app", Value: "cli"},
		// OpenShell's placeholder as the sandbox presents it; the supervisor
		// resolves it only after this hook answered ALLOW.
		{Name: "x-api-key", Value: "openshell:resolve:env:ANTHROPIC_API_KEY"},
		{Name: "x-talon-session-id", Value: osAnthropicSession},
	}
	c := connect.NewClient[middlewarev1.HttpRequestEvaluation, middlewarev1.HttpRequestResult](sup.client, sup.talonURL+"/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest", connect.WithGRPC())
	req := connect.NewRequest(&middlewarev1.HttpRequestEvaluation{
		Phase:          middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Context:        &middlewarev1.RequestContext{RequestId: requestID, SandboxId: osSandbox, Sandbox: "claude-sandbox", OriginatingProcess: &middlewarev1.Process{Binary: "/usr/local/bin/claude"}},
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "https", Host: "api.anthropic.com", Port: 443, Method: "POST", Path: path, Query: query},
		Headers:        headers,
		Body:           []byte(body),
		MiddlewareName: "talon-governance",
	})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := c.CallUnary(ctx, req)
	if err != nil {
		t.Fatalf("request hook: %v", err)
	}
	reqRes = res.Msg
	if reqRes.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
		return reqRes, http.StatusForbidden, nil, nil
	}
	forward := body
	if reqRes.GetHasBody() {
		forward = string(reqRes.GetBody())
	}
	url := provider.srv.URL + path
	if query != "" {
		url += "?" + query
	}
	hreq, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(forward))
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("anthropic-version", "2023-06-01")
	hreq.Header.Set("x-api-key", providerSecretOwnedByRuntime) // credential injection: HERE, after Talon
	for _, m := range reqRes.GetHeaderMutations() {
		if w := m.GetWrite(); w != nil {
			hreq.Header.Set(w.GetName(), w.GetValue())
		}
	}
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	upstreamBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Permitted modes as OpenShell v0.1.3 computes them
	// (crates/openshell-supervisor-middleware/src/response/validation.rs):
	// HEADERS_ONLY always; WHOLE_BODY_BYTES only for a response that is not
	// open-ended — text/event-stream never gets it; STREAM_BYTES when the
	// binding has a payload cap. The first real run of the lane (PR #531)
	// found this: a fixture that offered WHOLE_BODY for SSE had hidden it.
	contentType := resp.Header.Get("Content-Type")
	modes := []middlewarev1.HttpResponseBodyMode{
		middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY,
		middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
		middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES,
	}
	if strings.HasPrefix(contentType, "text/event-stream") {
		modes = []middlewarev1.HttpResponseBodyMode{
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY,
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES,
		}
	}
	rc := connect.NewClient[middlewarev1.HttpResponseEvent, middlewarev1.HttpResponseEventResult](sup.client, sup.talonURL+"/openshell.middleware.v1.HttpResponsePreReturn/Evaluate", connect.WithGRPC())
	st := rc.CallBidiStream(ctx)
	st.RequestHeader().Set("Authorization", "Bearer "+token)
	if err := st.Send(&middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Preflight{Preflight: &middlewarev1.HttpResponsePreflight{
		Context:            &middlewarev1.RequestContext{RequestId: requestID, SandboxId: osSandbox},
		Target:             &middlewarev1.HttpRequestTarget{Scheme: "https", Host: "api.anthropic.com", Port: 443, Method: "POST", Path: path, Query: query},
		StatusCode:         uint32(resp.StatusCode),
		Headers:            []*middlewarev1.HttpHeader{{Name: "content-type", Value: contentType}},
		MiddlewareName:     "talon-governance",
		PermittedBodyModes: modes,
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
	respMeta = map[string]string{}
	for k, v := range pres.GetMetadata() {
		respMeta[k] = v
	}
	switch {
	case pres.GetBlockDelivery() != nil:
		_ = st.CloseRequest()
		return reqRes, http.StatusForbidden, nil, respMeta
	case pres.GetSkip() != nil:
		_ = st.CloseRequest()
		return reqRes, resp.StatusCode, upstreamBody, respMeta
	}
	mode := pres.GetInspect().GetBodyMode()
	respMeta["body_mode"] = mode.String()
	// WHOLE_BODY: one unit. STREAM_BYTES: one unit per provider flush (an
	// SSE frame each, as Anthropic-style providers flush), each held by the
	// runtime until Talon's result, delivered as that result says.
	units := [][]byte{upstreamBody}
	if mode == middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES {
		units = sseFrames(upstreamBody)
	}
	for i, u := range units {
		if err := st.Send(&middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Body{Body: &middlewarev1.HttpResponseBodyUnit{Sequence: uint64(i + 1), Payload: &middlewarev1.HttpResponseBodyUnit_Data{Data: u}, EndOfStream: i == len(units)-1}}}); err != nil {
			t.Fatalf("body unit %d: %v", i+1, err)
		}
		br, err := st.Receive()
		if err != nil {
			t.Fatalf("body result %d: %v", i+1, err)
		}
		bres := br.GetBodyResult()
		if bres == nil {
			t.Fatalf("no body result: %v", br)
		}
		for k, v := range bres.GetMetadata() {
			respMeta[k] = v
		}
		switch {
		case bres.GetBlockDelivery() != nil:
			// Before commitment OpenShell answers the canonical 403; after it
			// (a later stream unit) it aborts delivery: nothing further.
			respMeta["blocked_at_unit"] = fmt.Sprint(i + 1)
			respMeta["block_reason_code"] = bres.GetReasonCode()
			_ = st.CloseRequest()
			if len(delivered) == 0 {
				return reqRes, http.StatusForbidden, nil, respMeta
			}
			return reqRes, resp.StatusCode, delivered, respMeta
		case bres.GetTransform() != nil:
			delivered = append(delivered, bres.GetTransform().GetData()...)
		default:
			delivered = append(delivered, u...)
		}
	}
	_ = st.Send(&middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_SessionEnd{SessionEnd: &middlewarev1.MiddlewareSessionEnd{Reason: middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL}}})
	_ = st.CloseRequest()
	return reqRes, resp.StatusCode, delivered, respMeta
}

// sseFrames splits an SSE body into its frames (delimiter kept); a trailing
// partial frame — a stream the provider cut — is the last unit.
func sseFrames(body []byte) [][]byte {
	var units [][]byte
	for len(body) > 0 {
		i := bytes.Index(body, []byte("\n\n"))
		if i < 0 {
			units = append(units, body)
			break
		}
		units = append(units, body[:i+2])
		body = body[i+2:]
	}
	if len(units) == 0 {
		units = [][]byte{{}}
	}
	return units
}

//nolint:gocyclo // one sequential black-box scenario against the running binary
func TestE2E_OpenShell_DelegatedAnthropicMessages(t *testing.T) {
	provider := startAnthropicFixtureProvider(t)
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
	// The provider is "anthropic": its hostname maps the delegated request
	// to it and its name selects the Anthropic wire (x-api-key, /v1/messages,
	// count_tokens, SSE usage). The vault value is a decoy Talon must never
	// send and the sandbox must never see.
	cfg = append(cfg, []byte(fmt.Sprintf(`
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    anthropic:
      enabled: true
      secret_name: "anthropic-api-key"
      base_url: "https://api.anthropic.com"
  organization_policy:
    defaults:
      pii_action: "redact"
      daily_cost: 100.00
    constraints:
      blocked_models: ["claude-opus-4-8"]
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
      max_capture_bytes: 65536
`, osPort, osIssuer, osAudience, jwksPath))...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][2]string{{"anthropic-api-key", "sk-ant-talon-vault-value-never-used-on-delegated-path"}, {osAgent + "-talon-key", "talon-gw-openshell-claude-e2e-0001"}} {
		if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", kv[0], kv[1]); code != 0 {
			t.Fatalf("secrets set: %d\n%s", code, stderr)
		}
	}
	stop := startServe(t, dir, httpPort)
	defer func() { stop() }()
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
			if len(logs) > 12000 {
				logs = logs[len(logs)-12000:]
			}
			t.Logf("talon serve.log (tail):\n%s", logs)
		}
	})
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", osPort))
	sup.talonURL = fmt.Sprintf("http://127.0.0.1:%d", osPort)
	token := func() string { return sup.token(osSandbox, priv) }
	const email = "jane.doe@example.com"
	const model = "claude-sonnet-4-5"

	// 1. The Claude Code request, streamed, with PII in the prompt's content
	// block: ALLOW with a transformed body that is still a valid Anthropic
	// request (stream, model, tools, system kept; the e-mail gone), one
	// provider call under the runtime's x-api-key, the SSE answer delivered
	// and settled with the usage split across message_start/message_delta.
	res, status, delivered, respMeta := anthropicExchange(t, sup, provider, token(), "/v1/messages", "beta=true", claudeCodeRequest(model, "Draft a refund note for "+email+" about order 42.", true))
	if res.GetDecision() != middlewarev1.Decision_DECISION_ALLOW || !res.GetHasBody() {
		t.Fatalf("expected ALLOW with a transformed body, got %v", res)
	}
	decisionID := res.GetMetadata()["talon_evidence_id"]
	if decisionID == "" || res.GetMetadata()["talon_agent"] != osAgent {
		t.Fatalf("request metadata: %v", res.GetMetadata())
	}
	calls, paths, queries, apiKeys, bodies := provider.snapshot()
	if calls != 1 || paths[0] != "/v1/messages" || queries[0] != "beta=true" {
		t.Fatalf("provider saw %d call(s) %v %v, want one /v1/messages?beta=true", calls, paths, queries)
	}
	if apiKeys[0] != providerSecretOwnedByRuntime {
		t.Fatalf("the provider must receive the runtime-injected x-api-key, got %q", apiKeys[0])
	}
	forwarded := bodies[0]
	if strings.Contains(forwarded, email) || forwarded != string(res.GetBody()) {
		t.Fatalf("provider body must be exactly Talon's redacted replacement: %s", forwarded)
	}
	var fwd struct {
		Model    string           `json:"model"`
		Stream   bool             `json:"stream"`
		System   []map[string]any `json:"system"`
		Tools    []map[string]any `json:"tools"`
		Metadata map[string]any   `json:"metadata"`
		Messages []struct {
			Role    string           `json:"role"`
			Content []map[string]any `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(forwarded), &fwd); err != nil || fwd.Model != model || !fwd.Stream || len(fwd.System) != 1 || fwd.Metadata["user_id"] == nil || len(fwd.Messages) != 1 || len(fwd.Messages[0].Content) != 1 {
		t.Fatalf("the transformed body is not the Claude Code request with the content replaced: %v %s", err, forwarded)
	}
	// Tool governance applies to the client's tool list on this path too:
	// the scaffolded use case declares no tools, so Talon removes what the
	// client offered (tool_governance.tools_filtered). That is policy, not a
	// wire defect; it is recorded, not asserted on here.
	t.Logf("tools offered by the client: 1; forwarded after Talon's tool governance: %d", len(fwd.Tools))
	if text, _ := fwd.Messages[0].Content[0]["text"].(string); !strings.Contains(text, "order 42") {
		t.Fatalf("the redacted content block lost the rest of the prompt: %q", text)
	}
	if status != 200 || !bytes.Contains(delivered, []byte("event: message_stop")) || !bytes.Contains(delivered, []byte("mock anthropic completion 1")) {
		t.Fatalf("the sandbox must receive the complete SSE answer: %d %s (meta %v)", status, delivered, respMeta)
	}
	if respMeta["body_mode"] != "HTTP_RESPONSE_BODY_MODE_STREAM_BYTES" {
		t.Fatalf("an SSE answer under a preventive policy is inspected unit by unit on v0.1.3 (no WHOLE_BODY offer); got %v", respMeta)
	}
	settlementID := respMeta["talon_evidence_id"]
	if settlementID == "" {
		t.Fatalf("no settlement evidence id: %v", respMeta)
	}

	// 1b. The provider's streamed answer carries PII: the unit carrying it
	// is withheld together with everything after it (OpenShell holds each
	// unit until Talon answers); the sandbox never receives the value; the
	// settlement is a blocked, per-unit-preventive record.
	provider.mu.Lock()
	provider.responsePII = true
	provider.mu.Unlock()
	res, status, delivered, piiMeta := anthropicExchange(t, sup, provider, token(), "/v1/messages", "beta=true", claudeCodeRequest(model, "hi", true))
	provider.mu.Lock()
	provider.responsePII = false
	provider.mu.Unlock()
	if res.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
		t.Fatalf("response-PII request: %v", res)
	}
	if bytes.Contains(delivered, []byte(email)) || bytes.Contains(delivered, []byte("message_stop")) {
		t.Fatalf("the sandbox must receive neither the e-mail nor a completed stream: %d %s", status, delivered)
	}
	if piiMeta["blocked_at_unit"] != "3" || piiMeta["block_reason_code"] != "output_pii_blocked" || piiMeta["talon_decision"] != "block" {
		t.Fatalf("the delta carrying the e-mail (unit 3 after message_start and content_block_start) must be the withheld unit: %v", piiMeta)
	}
	if !bytes.Contains(delivered, []byte("event: content_block_start")) {
		t.Fatalf("units before the withheld one were released (per-unit prevention): %s", delivered)
	}
	piiSettlementID := piiMeta["talon_evidence_id"]
	if piiSettlementID == "" {
		t.Fatalf("no settlement evidence id for the withheld stream: %v", piiMeta)
	}

	// 2. count_tokens: governed on the same path, recorded as its own
	// invocation type at cost 0; the provider answered the count.
	res, status, delivered, countMeta := anthropicExchange(t, sup, provider, token(), "/v1/messages/count_tokens", "beta=true", `{"model":"`+model+`","messages":[{"role":"user","content":"hi"}]}`)
	if res.GetDecision() != middlewarev1.Decision_DECISION_ALLOW || status != 200 || !bytes.Contains(delivered, []byte(`"input_tokens":42`)) {
		t.Fatalf("count_tokens: %v status=%d delivered=%s meta=%v", res, status, delivered, countMeta)
	}
	countDecisionID := res.GetMetadata()["talon_evidence_id"]
	if calls, paths, _, _, _ = provider.snapshot(); calls != 3 || paths[2] != "/v1/messages/count_tokens" {
		t.Fatalf("provider after count_tokens: %d %v", calls, paths)
	}

	// 3. Company blocked model: DENY before credentials, zero provider calls.
	res, status, _, _ = anthropicExchange(t, sup, provider, token(), "/v1/messages", "beta=true", claudeCodeRequest("claude-opus-4-8", "hi", true))
	if res.GetDecision() != middlewarev1.Decision_DECISION_DENY || res.GetReasonCode() != "model_not_allowed" || status != http.StatusForbidden {
		t.Fatalf("expected model_not_allowed DENY, got %v status=%d", res, status)
	}
	denyID := res.GetMetadata()["talon_evidence_id"]
	if calls, _, _, _, _ = provider.snapshot(); calls != 3 {
		t.Fatalf("a Talon DENY must produce zero provider calls; count = %d", calls)
	}

	// 4. Identity failures on this wire: forged key, another sandbox, no token.
	_, forgedPriv := newFixtureKeypair(t)
	for name, tok := range map[string]string{"forged": sup.token(osSandbox, forgedPriv), "other-sandbox": sup.token("sb-attacker", priv), "none": ""} {
		res, status, _, _ = anthropicExchange(t, sup, provider, tok, "/v1/messages", "beta=true", claudeCodeRequest(model, "hi", true))
		if status != http.StatusForbidden || res.GetDecision() != middlewarev1.Decision_DECISION_DENY || !strings.HasPrefix(res.GetReasonCode(), "workload_identity_") {
			t.Fatalf("%s: expected identity DENY, got status=%d res=%v", name, status, res)
		}
	}
	if calls, _, _, _, _ = provider.snapshot(); calls != 3 {
		t.Fatalf("identity failures must produce zero provider calls; count = %d", calls)
	}

	// 5. Truncated stream: the provider closes before message_delta /
	// message_stop. Whatever Talon settles, it must not be the full answer's
	// usage, and the sandbox must not receive a terminal event.
	provider.mu.Lock()
	provider.truncate = true
	provider.mu.Unlock()
	res, status, delivered, truncMeta := anthropicExchange(t, sup, provider, token(), "/v1/messages", "beta=true", claudeCodeRequest(model, "hi", true))
	provider.mu.Lock()
	provider.truncate = false
	provider.mu.Unlock()
	if res.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
		t.Fatalf("truncated-stream request: %v", res)
	}
	if bytes.Contains(delivered, []byte("message_stop")) {
		t.Fatalf("a truncated stream must not be delivered with a terminal event: %d %s", status, delivered)
	}
	truncSettlementID := truncMeta["talon_evidence_id"]
	t.Logf("truncated stream: status=%d bytes=%d settlement meta=%v", status, len(delivered), truncMeta)

	// 6. Evidence.
	recs := exportRecords(t, dir)
	byID := map[string]map[string]any{}
	for _, r := range recs {
		if id, _ := r["id"].(string); id != "" {
			byID[id] = r
		}
	}
	exec := func(r map[string]any) map[string]any { m, _ := r["execution"].(map[string]any); return m }
	enf := func(r map[string]any) map[string]any { m, _ := r["enforcement"].(map[string]any); return m }
	dec, set := byID[decisionID], byID[settlementID]
	if dec == nil || set == nil {
		t.Fatalf("records missing: decision=%v settlement=%v", dec != nil, set != nil)
	}
	routing := func(r map[string]any) map[string]any { m, _ := r["routing_decision"].(map[string]any); return m }
	if routing(dec)["selected_provider"] != "anthropic" || exec(dec)["model_used"] != model || dec["invocation_type"] != "gateway" || dec["upstream_auth_mode"] != "external_runtime" {
		t.Fatalf("decision record: provider=%v model=%v type=%v auth=%v", routing(dec)["selected_provider"], exec(dec)["model_used"], dec["invocation_type"], dec["upstream_auth_mode"])
	}
	if enf(dec)["provenance"] != "delegated_expected" || enf(dec)["decision_authority"] != "talon" || enf(dec)["decision_returned_via"] != "openshell_middleware" {
		t.Fatalf("decision enforcement: %v", enf(dec))
	}
	if wi, _ := dec["workload_identity"].(map[string]any); wi["status"] != "verified" || wi["subject"] != osSubject || wi["issuer"] != osIssuer {
		t.Fatalf("decision workload identity: %v", dec["workload_identity"])
	}
	if cls, _ := dec["classification"].(map[string]any); cls["input_pii_detected"] != true && cls["pii_detected"] != true {
		t.Logf("decision classification (PII in a content block): %v", cls)
	}
	if exec(dec)["cost"] != 0.0 || exec(dec)["pricing_basis"] != "awaiting_settlement" {
		t.Fatalf("decision must book no cost while settling: %v", exec(dec))
	}
	if set["invocation_type"] != "gateway_response" || set["correlation_id"] != dec["correlation_id"] {
		t.Fatalf("settlement does not join its decision: %v", set)
	}
	if tokens, _ := exec(set)["tokens"].(map[string]any); tokens["input"] != 12.0 || tokens["output"] != 3.0 {
		t.Fatalf("settlement must carry the SSE usage (message_start input 12, message_delta output 3): %v", exec(set)["tokens"])
	}
	if cost, _ := exec(set)["cost"].(float64); cost <= 0 || exec(set)["pricing_basis"] == "estimate_no_usage" {
		t.Fatalf("settlement must price the actual usage from the table: %v", exec(set))
	}
	annotations := func(r map[string]any) string { a, _ := json.Marshal(r["gateway_annotations"]); return string(a) }
	if !strings.Contains(annotations(set), "response_observed") || strings.Contains(annotations(set), "decision_unmatched") {
		t.Fatalf("settlement annotations: %s", annotations(set))
	}
	if set["session_id"] != osAnthropicSession || dec["session_id"] != osAnthropicSession {
		t.Fatalf("session join: decision=%v settlement=%v", dec["session_id"], set["session_id"])
	}
	responseScan := func(r map[string]any) map[string]any {
		cls, _ := r["classification"].(map[string]any)
		rs, _ := cls["response_scan"].(map[string]any)
		return rs
	}
	if responseScan(set)["enforcement"] != "preventive_per_unit" || !strings.Contains(annotations(set), "stream_unit_guarded") {
		t.Fatalf("a guarded stream settles as preventive_per_unit with stream_unit_guarded: scan=%v annotations=%s", responseScan(set), annotations(set))
	}
	pset := byID[piiSettlementID]
	if pset == nil {
		t.Fatalf("withheld-stream settlement %s missing", piiSettlementID)
	}
	if pd, _ := pset["policy_decision"].(map[string]any); pd["allowed"] != false {
		t.Fatalf("the withheld stream must settle as blocked: %v", pset["policy_decision"])
	}
	if cls, _ := pset["classification"].(map[string]any); cls["output_pii_detected"] != true || responseScan(pset)["enforcement"] != "preventive_per_unit" {
		t.Fatalf("withheld-stream classification: %v", pset["classification"])
	}
	if pset["correlation_id"] == "" || pset["correlation_id"] == dec["correlation_id"] {
		t.Fatalf("the withheld stream settles under its own decision: %v", pset["correlation_id"])
	}
	cdec := byID[countDecisionID]
	if cdec == nil || cdec["invocation_type"] != "gateway_count_tokens" || exec(cdec)["cost"] != 0.0 {
		t.Fatalf("count_tokens decision: %v", cdec)
	}
	for _, r := range recs {
		if r["invocation_type"] == "gateway_response" && r["correlation_id"] == cdec["correlation_id"] {
			if c, _ := exec(r)["cost"].(float64); c != 0 {
				t.Fatalf("a count_tokens settlement must never bill: %v", exec(r))
			}
		}
	}
	ddec := byID[denyID]
	if ddec == nil || exec(ddec)["model_used"] != "claude-opus-4-8" {
		t.Fatalf("deny record: %v", ddec)
	}
	if pd, _ := ddec["policy_decision"].(map[string]any); pd["allowed"] != false {
		t.Fatalf("deny record must be a denial: %v", pd)
	}
	if truncSettlementID != "" {
		ts := byID[truncSettlementID]
		if ts == nil {
			t.Fatalf("truncated-stream settlement %s missing", truncSettlementID)
		}
		if tokens, _ := exec(ts)["tokens"].(map[string]any); tokens["output"] == 3.0 {
			t.Fatalf("a truncated stream must not settle with the full answer's output usage: %v", exec(ts))
		}
		t.Logf("truncated stream settlement: status=%v basis=%v tokens=%v annotations=%s", ts["status"], exec(ts)["pricing_basis"], exec(ts)["tokens"], annotations(ts))
	}
	for _, r := range recs {
		if r["invocation_type"] == "gateway_response" && strings.Contains(annotations(r), "decision_unmatched") {
			t.Fatalf("no settlement may lose its request half: %v", r["id"])
		}
		if (r["invocation_type"] == "gateway" || r["invocation_type"] == "gateway_response" || r["invocation_type"] == "gateway_count_tokens") && enf(r)["provenance"] == "talon_enforced" {
			t.Fatalf("a delegated model record must never be talon_enforced: %v", r["id"])
		}
	}
	exportJSON, _ := json.Marshal(recs)
	logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	for _, leak := range []string{email, providerSecretOwnedByRuntime, "sk-ant-talon-vault-value", "talon-gw-openshell-claude-e2e-0001"} {
		if strings.Contains(string(exportJSON), leak) || strings.Contains(string(logs), leak) {
			t.Errorf("leak of %q in evidence or logs", leak)
		}
	}
	for _, id := range []string{decisionID, settlementID, piiSettlementID, countDecisionID, denyID} {
		if out, _, code := RunTalon(t, dir, nil, "audit", "verify", id); code != 0 || !strings.Contains(strings.ToUpper(out), "VALID") {
			t.Errorf("audit verify %s: %d %s", id, code, out)
		}
	}
	report, _, code := RunTalon(t, dir, nil, "audit", "list", "--runtime-ref", osSandbox, "--report")
	if code != 0 || !strings.Contains(report, model) || strings.Contains(report, email) || strings.Contains(report, providerSecretOwnedByRuntime) {
		t.Errorf("walkthrough report for the sandbox (code %d):\n%s", code, report)
	}
}

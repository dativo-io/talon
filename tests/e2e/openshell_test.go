//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
)

// OpenShell composition smoke (#482, first slice).
//
// This test is the deterministic, clean-checkout proof of the composed
// model channel:
//
//	agent in sandbox → OpenShell network admission → Talon (this middleware)
//	→ OpenShell credential injection → provider
//
// OpenShell itself is NOT started here: installing it needs OS packages and
// a Docker/Kubernetes compute driver. Instead a FIXTURE SUPERVISOR replays
// the pinned v0.1.2 supervisor-middleware contract exactly as documented —
// it mints the gateway-signed extension JWT, calls EvaluateHttpRequest over
// real gRPC, forwards ONLY on ALLOW with the replaced body and its own
// provider credential, and emits an OCSF denial line for a destination its
// (simulated) network policy rejects. Everything asserted about TALON is
// therefore real; everything asserted about OpenShell's side is the
// documented contract replayed, and the docs say so. The live lane against
// a real OpenShell gateway is docs/integration/openshell.md.
//
// Proves: verified composed identity; one Talon transformation (PII
// redaction) reaching the provider path exactly once with exactly the
// redacted bytes; one Talon prevention (model restriction) with zero
// provider dispatch; invalid identity with zero dispatch; one imported
// OpenShell containment fact labelled external-runtime enforcement; the
// provider credential never entering Talon; signed evidence that verifies
// offline; and survival of a Talon restart.

const (
	osIssuer   = "openshell-gateway:gw-smoke"
	osAudience = "urn:openshell:extension:middleware:talon"
	osSandbox  = "sb-smoke-0001"
	osSubject  = "spiffe://openshell/sandbox/" + osSandbox
	osAgent    = "sandboxed-support"
	// The provider credential lives with the fixture supervisor (as it
	// lives with OpenShell in production). Talon never sees it.
	providerSecretOwnedByRuntime = "sk-runtime-owned-provider-credential-0001"
)

type fixtureProvider struct {
	server   *httptest.Server
	mu       sync.Mutex
	calls    atomic.Int64
	bodies   []string
	authHdrs []string
}

func startFixtureProvider(t *testing.T) *fixtureProvider {
	t.Helper()
	p := &fixtureProvider{}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.bodies = append(p.bodies, string(body))
		p.authHdrs = append(p.authHdrs, r.Header.Get("Authorization"))
		p.mu.Unlock()
		p.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":1}}`))
	}))
	t.Cleanup(p.server.Close)
	return p
}

type fixtureSupervisor struct {
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	kid      string
	client   *http.Client
	talonURL string
	provider *fixtureProvider
	ocsf     []string
}

func (s *fixtureSupervisor) jwks() []byte {
	doc := map[string]any{"keys": []map[string]any{{"kty": "OKP", "crv": "Ed25519", "kid": s.kid, "x": base64.RawURLEncoding.EncodeToString(s.pub)}}}
	b, _ := json.Marshal(doc)
	return b
}

func (s *fixtureSupervisor) token(sandbox string, priv ed25519.PrivateKey) string {
	now := time.Now()
	claims := map[string]any{
		"iss": osIssuer, "aud": osAudience, "sub": "spiffe://openshell/sandbox/" + sandbox, "caller_kind": "supervisor",
		"sandbox_id": sandbox, "jti": fmt.Sprintf("j-%d", now.UnixNano()), "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(),
	}
	h, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "openshell-ext+jwt", "kid": s.kid})
	c, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signing)))
}

// admit replays one sandbox request through the documented pipeline:
// network policy (fixture: only api.openai.com is admitted) → Talon →
// credential injection → provider. Returns Talon's result and the HTTP
// status the sandbox would see.
func (s *fixtureSupervisor) admit(t *testing.T, token, host, path, body string) (*middlewarev1.HttpRequestResult, int) {
	t.Helper()
	if host != "api.openai.com" {
		// OpenShell default-deny: the destination is not in network policy,
		// Talon is never consulted. OCSF 4001 Network Activity, Denied.
		s.ocsf = append(s.ocsf, fmt.Sprintf(`{"class_uid":4001,"activity_name":"Open","severity_id":3,"status":"Failure","action":"Denied","disposition":"Blocked","status_detail":"no matching policy","message":"CONNECT denied %s:443","time":%d,"dst_endpoint":{"domain":%q,"port":443},"actor":{"process":{"name":"/usr/bin/curl","pid":63}},"container":{"uid":%q},"firewall_rule":{"name":"-","type":"opa"}}`,
			host, time.Now().UnixMilli(), host, osSandbox))
		return nil, http.StatusForbidden
	}
	c := connect.NewClient[middlewarev1.HttpRequestEvaluation, middlewarev1.HttpRequestResult](s.client, s.talonURL+"/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest", connect.WithGRPC())
	req := connect.NewRequest(&middlewarev1.HttpRequestEvaluation{
		Phase:          middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Context:        &middlewarev1.RequestContext{RequestId: fmt.Sprintf("req-%d", time.Now().UnixNano()), SandboxId: osSandbox, Sandbox: "support-sandbox"},
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "https", Host: host, Port: 443, Method: "POST", Path: path},
		Headers:        []*middlewarev1.HttpHeader{{Name: "content-type", Value: "application/json"}},
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
		// Middleware failure = fail closed (OpenShell default on_error).
		t.Logf("middleware call failed (fail-closed): %v", err)
		return nil, http.StatusForbidden
	}
	if res.Msg.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
		return res.Msg, http.StatusForbidden
	}
	forward := body
	if res.Msg.GetHasBody() {
		forward = string(res.Msg.GetBody())
	}
	// Credential injection happens HERE, after Talon, never before.
	hreq, _ := http.NewRequest(http.MethodPost, s.provider.server.URL+path, strings.NewReader(forward))
	hreq.Header.Set("Authorization", "Bearer "+providerSecretOwnedByRuntime)
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatalf("forward to provider: %v", err)
	}
	_ = resp.Body.Close()
	return res.Msg, resp.StatusCode
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("%s not listening within 15s", addr)
}

func startServe(t *testing.T, dir string, httpPort int) func() {
	t.Helper()
	return startServeWithEnv(t, dir, httpPort, nil, "--gateway", "--gateway-config", filepath.Join(dir, "talon.config.yaml"))
}

// startServeWithEnv starts `talon serve` on httpPort with extra env and
// args, waits for /health and returns a stop func.
func startServeWithEnv(t *testing.T, dir string, httpPort int, env map[string]string, extraArgs ...string) func() {
	t.Helper()
	args := append([]string{"serve", "--port", fmt.Sprintf("%d", httpPort)}, extraArgs...)
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TALON_DATA_DIR="+dir, "TALON_SECRETS_KEY="+testSecretsKey, "TALON_SIGNING_KEY="+testSigningKey)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "serve.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", httpPort))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return stop
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	stop()
	logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	t.Fatalf("serve not healthy; log:\n%s", logs)
	return nil
}

func TestE2E_OpenShell_ComposedModelChannel(t *testing.T) {
	provider := startFixtureProvider(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sup := &fixtureSupervisor{priv: priv, pub: pub, kid: "gw-smoke-k1", provider: provider}
	sup.client = &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}

	// 1. Scaffold one AI use case and bind the sandbox subject to it.
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", osAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	agentYAML, err := os.ReadFile(agentPath)
	if err != nil {
		t.Fatal(err)
	}
	keyLine := fmt.Sprintf("  key:\n    secret_name: \"%s-talon-key\"\n", osAgent)
	if !strings.Contains(string(agentYAML), keyLine) {
		t.Fatalf("scaffold changed; expected key block:\n%s", agentYAML)
	}
	binding := keyLine + "  workload_identity:\n    bindings:\n      - runtime: openshell\n        subject: \"" + osSubject + "\"\n"
	if err := os.WriteFile(agentPath, []byte(strings.Replace(string(agentYAML), keyLine, binding, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	jwksPath := filepath.Join(dir, "openshell-jwks.json")
	if err := os.WriteFile(jwksPath, sup.jwks(), 0o600); err != nil {
		t.Fatal(err)
	}
	osPort := freePort(t)
	httpPort := freePort(t)
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
    constraints:
      blocked_models: ["gpt-4o"]
  openshell:
    enabled: true
    listen: "127.0.0.1:%d"
    allow_insecure_transport: true
    middleware_name: "talon"
    identity:
      issuer: %q
      audience: %q
      jwks_file: %q
`, osPort, osIssuer, osAudience, jwksPath))...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	// Talon's own vault holds a DIFFERENT value than the runtime's credential:
	// if the runtime-owned secret ever appears in Talon evidence/logs, or the
	// vault value ever reaches the provider, the boundary leaked.
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "openai-api-key", "sk-talon-vault-value-never-used-on-delegated-path"); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", osAgent+"-talon-key", "talon-gw-openshell-e2e-0001"); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}

	stop := startServe(t, dir, httpPort)
	defer func() { stop() }()
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", osPort))
	sup.talonURL = fmt.Sprintf("http://127.0.0.1:%d", osPort)

	// 2. OpenShell gateway startup: Describe.
	dc := connect.NewClient[middlewarev1.MiddlewareDescribeRequest, middlewarev1.MiddlewareManifest](sup.client, sup.talonURL+"/openshell.middleware.v1.SupervisorMiddleware/Describe", connect.WithGRPC())
	manifest, err := dc.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.MiddlewareDescribeRequest{}))
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if manifest.Msg.GetName() != "talon" || manifest.Msg.GetExpectedAudience() != osAudience || len(manifest.Msg.GetBindings()) != 1 {
		t.Fatalf("manifest: %v", manifest.Msg)
	}

	// 3. Allowed + transformed: PII is redacted and the provider receives
	// exactly the redacted representation, once, with the RUNTIME's credential.
	piiBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Refund request from jane.doe@example.com for order 42"}]}`
	res, status := sup.admit(t, sup.token(osSandbox, priv), "api.openai.com", "/v1/chat/completions", piiBody)
	if status != http.StatusOK || res.GetDecision() != middlewarev1.Decision_DECISION_ALLOW || !res.GetHasBody() {
		t.Fatalf("expected ALLOW with replaced body, got status=%d res=%v", status, res)
	}
	allowEvidenceID := res.GetMetadata()["talon_evidence_id"]
	if allowEvidenceID == "" || res.GetMetadata()["talon_agent"] != osAgent {
		t.Fatalf("metadata: %v", res.GetMetadata())
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("provider dispatch count = %d, want 1", provider.calls.Load())
	}
	provider.mu.Lock()
	forwarded, auth := provider.bodies[0], provider.authHdrs[0]
	provider.mu.Unlock()
	if strings.Contains(forwarded, "jane.doe@example.com") {
		t.Fatalf("provider received unredacted PII: %s", forwarded)
	}
	if forwarded != string(res.GetBody()) {
		t.Fatalf("provider received bytes that differ from Talon's replacement body")
	}
	if auth != "Bearer "+providerSecretOwnedByRuntime {
		t.Fatalf("provider credential was not the runtime-owned one: %q", auth)
	}

	// 4. Talon prevention: blocked model → DENY, zero additional dispatch.
	res, status = sup.admit(t, sup.token(osSandbox, priv), "api.openai.com", "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	if status != http.StatusForbidden || res.GetDecision() != middlewarev1.Decision_DECISION_DENY || res.GetReasonCode() != "model_not_allowed" {
		t.Fatalf("expected model_not_allowed DENY, got status=%d res=%v", status, res)
	}
	denyEvidenceID := res.GetMetadata()["talon_evidence_id"]
	if provider.calls.Load() != 1 {
		t.Fatalf("Talon deny must produce zero provider dispatch; count = %d", provider.calls.Load())
	}

	// 5. Adversarial identity: a token signed by a key OpenShell's gateway
	// never published, a token for another sandbox, and no token at all.
	_, forgedPriv, _ := ed25519.GenerateKey(rand.Reader)
	for name, tok := range map[string]string{"forged": sup.token(osSandbox, forgedPriv), "other-sandbox": sup.token("sb-attacker", priv), "none": ""} {
		res, status = sup.admit(t, tok, "api.openai.com", "/v1/chat/completions", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)
		if status != http.StatusForbidden || res.GetDecision() != middlewarev1.Decision_DECISION_DENY || !strings.HasPrefix(res.GetReasonCode(), "workload_identity_") {
			t.Fatalf("%s: expected identity DENY, got status=%d res=%v", name, status, res)
		}
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("identity failures must produce zero provider dispatch; count = %d", provider.calls.Load())
	}

	// 6. OpenShell-only containment: the sandbox tries a destination its
	// network policy does not admit. Talon is never consulted; the only
	// trace is OpenShell's OCSF export, which Talon imports and labels as
	// external-runtime enforcement.
	if _, status = sup.admit(t, sup.token(osSandbox, priv), "exfil.example.net", "/upload", `{}`); status != http.StatusForbidden {
		t.Fatalf("fixture network policy should deny")
	}
	ocsfPath := filepath.Join(dir, "openshell-ocsf.log")
	if err := os.WriteFile(ocsfPath, []byte(strings.Join(sup.ocsf, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := RunTalon(t, dir, nil, "audit", "import-external", "--runtime", "openshell", "--file", ocsfPath, "--runtime-id", osIssuer)
	if code != 0 || !strings.Contains(out, "1 imported") {
		t.Fatalf("import-external: %d\n%s\n%s", code, out, stderr)
	}
	var importedID string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "imported  ext_") {
			importedID = strings.Fields(line)[1]
		}
	}
	if importedID == "" {
		t.Fatalf("no imported record id in output:\n%s", out)
	}

	// 7. Evidence: provenance labels, identity, no secret leakage, verification.
	showAllow, _, code := RunTalon(t, dir, nil, "audit", "show", allowEvidenceID)
	if code != 0 {
		t.Fatalf("audit show allow: %d", code)
	}
	for _, want := range []string{
		"Enforcement: delegated_expected | mechanism=delegate | boundary=external_runtime | decided_by=talon | decision_returned_via=openshell_middleware",
		"runtime=openshell(" + osIssuer + ")", "runtime_policy=talon-governance", "runtime_ref=" + osSandbox,
		"Workload Identity: verified | runtime=openshell | subject=" + osSubject, "binding=agent_config",
	} {
		if !strings.Contains(showAllow, want) {
			t.Errorf("allow record projection missing %q:\n%s", want, showAllow)
		}
	}
	showDeny, _, _ := RunTalon(t, dir, nil, "audit", "show", denyEvidenceID)
	if !strings.Contains(showDeny, "mechanism=delegate") || !strings.Contains(showDeny, "decided_by=talon") {
		t.Errorf("deny record projection:\n%s", showDeny)
	}
	showExt, _, _ := RunTalon(t, dir, nil, "audit", "show", importedID)
	for _, want := range []string{
		"Enforcement: external_asserted | mechanism=verify | boundary=external_runtime | decided_by=external_runtime",
		"receipt=openshell_ocsf verified=false", "Workload Identity: asserted",
	} {
		if !strings.Contains(showExt, want) {
			t.Errorf("imported record projection missing %q:\n%s", want, showExt)
		}
	}
	if strings.Contains(showExt, "decided_by=talon") {
		t.Errorf("an OpenShell-only denial must never be projected as a Talon decision:\n%s", showExt)
	}
	export, _, code := RunTalon(t, dir, nil, "audit", "export", "--format", "signed-json")
	if code != 0 {
		t.Fatalf("audit export: %d", code)
	}
	exportPath := filepath.Join(dir, "export.json")
	if err := os.WriteFile(exportPath, []byte(export), 0o600); err != nil {
		t.Fatal(err)
	}
	logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	for _, leak := range []string{providerSecretOwnedByRuntime, "sk-talon-vault-value", "jane.doe@example.com"} {
		if strings.Contains(export, leak) {
			t.Errorf("evidence export leaks %q", leak)
		}
		if strings.Contains(string(logs), leak) {
			t.Errorf("serve log leaks %q", leak)
		}
	}
	if strings.Contains(string(logs), "eyJ") {
		t.Errorf("serve log appears to contain a JWT")
	}
	for _, id := range []string{allowEvidenceID, denyEvidenceID, importedID} {
		if out, _, code := RunTalon(t, dir, nil, "audit", "verify", id); code != 0 || !strings.Contains(strings.ToUpper(out), "VALID") {
			t.Errorf("audit verify %s: code=%d\n%s", id, code, out)
		}
	}
	if out, _, code := RunTalon(t, dir, nil, "audit", "verify", "--file", exportPath); code != 0 {
		t.Errorf("offline verify of signed export failed: %d\n%s", code, out)
	}

	// 8. Restart Talon: bindings and trust anchors are configuration, so the
	// composed identity resolves again and prior records still verify.
	stop()
	stop = startServe(t, dir, httpPort)
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", osPort))
	res, status = sup.admit(t, sup.token(osSandbox, priv), "api.openai.com", "/v1/chat/completions", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"after restart"}]}`)
	if status != http.StatusOK || res.GetDecision() != middlewarev1.Decision_DECISION_ALLOW {
		t.Fatalf("after restart: status=%d res=%v", status, res)
	}
	if provider.calls.Load() != 2 {
		t.Fatalf("provider dispatch count after restart = %d, want 2", provider.calls.Load())
	}
	if out, _, code := RunTalon(t, dir, nil, "audit", "verify", allowEvidenceID); code != 0 || !strings.Contains(strings.ToUpper(out), "VALID") {
		t.Errorf("pre-restart record no longer verifies: %s", out)
	}
}

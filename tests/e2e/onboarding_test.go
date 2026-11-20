//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
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

	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// Onboarding acceptance (#472): an engineer connects an existing application
// to a real `talon serve --gateway`, verifies that it runs under the company
// policy, and repeats it for a second, unrelated application. Every step
// goes through the product's own interfaces: the `talon` CLI, the gateway's
// HTTP endpoint, the console's read API. The provider is a deterministic
// upstream that counts what really reaches it.

var useCaseKeyRe = regexp.MustCompile(`talon_uc_[0-9a-f]{48}`)

const piiPrompt = "Refund to IBAN DE89370400440532013000 for jan.kowalski@example.com"

// onboardingProviderKey is the provider's key: Talon holds it in the vault
// and the application never sees it.
const onboardingProviderKey = "sk-fake-provider-key-never-sent-to-the-app"

type onboarding struct {
	t        *testing.T
	dir      string
	cfgPath  string
	upstream *httptest.Server
	calls    atomic.Int64
	// hold, when armed, makes the upstream keep exactly the next request
	// open until the channel is closed: a request that is in flight at the
	// provider. holding is signalled once that request has arrived.
	hold    atomic.Pointer[chan struct{}]
	holding chan struct{}
	port    int
	url     string
	stop    func()
}

// newOnboarding prepares an installation the way the documentation does:
// one talon.config.yaml with the provider and the company policy, the
// provider's key in the vault. No use case exists yet.
func newOnboarding(t *testing.T) *onboarding {
	t.Helper()
	o := &onboarding{t: t, dir: t.TempDir(), holding: make(chan struct{}, 1)}
	o.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.calls.Add(1)
		if release := o.hold.Swap(nil); release != nil {
			o.holding <- struct{}{}
			<-*release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl_onboarding","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`))
	}))
	t.Cleanup(o.upstream.Close)
	o.cfgPath = filepath.Join(o.dir, "talon.config.yaml")
	cfg := fmt.Sprintf(`agents_dir: %q
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: %q
  organization_policy:
    defaults:
      pii_action: block
      daily_cost: 50
      monthly_cost: 500
    constraints:
      forbidden_tools: ["delete_*"]
`, filepath.Join(o.dir, "agents"), o.upstream.URL)
	if err := os.WriteFile(o.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := o.talonStdin(onboardingProviderKey, "secrets", "set", "openai-api-key"); code != 0 {
		t.Fatalf("storing the provider key: %d\n%s", code, out)
	}
	return o
}

func (o *onboarding) env() map[string]string {
	return map[string]string{"TALON_GATEWAY_CONFIG": o.cfgPath, "TALON_AGENTS_RELOAD_INTERVAL": "1s", "TALON_ADMIN_KEY": "admin-e2e-onboarding-0001"}
}

func (o *onboarding) talon(args ...string) (stdout, stderr string, code int) {
	o.t.Helper()
	return RunTalon(o.t, o.dir, o.env(), args...)
}

// talonStdin runs the CLI with a value on stdin: how a secret is given to
// `talon secrets set` without ever being a process argument.
func (o *onboarding) talonStdin(stdin string, args ...string) (string, int) {
	o.t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = o.dir
	cmd.Env = append(os.Environ(), "TALON_DATA_DIR="+o.dir, "TALON_SECRETS_KEY="+testSecretsKey, "TALON_SIGNING_KEY="+testSigningKey)
	for k, v := range o.env() {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return out.String(), ee.ExitCode()
	} else if err != nil {
		o.t.Fatalf("talon %s: %v", strings.Join(args, " "), err)
	}
	return out.String(), 0
}

func (o *onboarding) serve() {
	o.t.Helper()
	if o.port == 0 {
		o.port = freePort(o.t)
		o.url = fmt.Sprintf("http://127.0.0.1:%d", o.port)
	}
	// The documented start: the admin key is set (env) and the listener is
	// this machine only.
	o.stop = startConsoleServe(o.t, o.dir, o.port, o.env(), "--host", "127.0.0.1")
}

// register runs `talon agents add` and returns the key from the secret
// block at the end of its output.
func (o *onboarding) register(name string, args ...string) (key, out string) {
	o.t.Helper()
	out, stderr, code := o.talon(append([]string{"agents", "add", name}, args...)...)
	if code != 0 {
		o.t.Fatalf("talon agents add %s: %d\n%s\n%s", name, code, out, stderr)
	}
	secretAt := strings.Index(out, "SECRET — shown once")
	if secretAt < 0 || useCaseKeyRe.MatchString(out[:secretAt]) {
		o.t.Fatalf("the key must appear only in the secret block at the end:\n%s", out)
	}
	key = useCaseKeyRe.FindString(out[secretAt:])
	if key == "" {
		o.t.Fatalf("no key in the secret block:\n%s", out)
	}
	return key, out
}

func (o *onboarding) report(name string) *effective.Report {
	o.t.Helper()
	out, stderr, code := o.talon("agents", "show", name, "--effective", "--json")
	if code != 0 {
		o.t.Fatalf("talon agents show %s --effective --json: %d\n%s\n%s", name, code, out, stderr)
	}
	var r effective.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		o.t.Fatalf("decoding the effective report: %v\n%s", err, out)
	}
	if r.Verification == nil {
		o.t.Fatalf("the effective report has no verification section:\n%s", out)
	}
	return &r
}

func (o *onboarding) waitFor(what string, cond func() bool) {
	o.t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(filepath.Join(o.dir, "serve.log"))
			o.t.Fatalf("timed out waiting for: %s\nserve log tail:\n%s", what, tail(string(log), 3000))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func (o *onboarding) waitLoaded(name string) {
	o.t.Helper()
	o.waitFor("a running process to load "+name, func() bool {
		return o.report(name).Loaded.State == runtimestatus.LoadedMatchesFile
	})
}

func traffic(r *effective.Report, boundary string) effective.TrafficObservation {
	for i := range r.Verification.Traffic {
		if r.Verification.Traffic[i].Boundary == boundary {
			return r.Verification.Traffic[i]
		}
	}
	return effective.TrafficObservation{}
}

type sdkResult struct {
	OK      bool   `json:"ok"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Content string `json:"content"`
	Message string `json:"message"`
}

// sdk sends one chat completion with the official OpenAI Node SDK
// (tests/onboarding/client.mjs), as the application would.
func (o *onboarding) sdk(key, prompt string) sdkResult {
	o.t.Helper()
	dir := os.Getenv("TALON_ONBOARDING_SDK_DIR")
	cmd := exec.Command("node", filepath.Join(dir, "client.mjs"), prompt)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TALON_URL="+o.url, "TALON_USE_CASE_KEY="+key)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		o.t.Fatalf("the SDK client failed: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	var res sdkResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); err != nil {
		o.t.Fatalf("the SDK client printed no result line: %v\n%s", err, stdout.String())
	}
	return res
}

func (o *onboarding) wantCalls(want int64, why string) {
	o.t.Helper()
	if got := o.calls.Load(); got != want {
		o.t.Fatalf("%s: the upstream received %d calls, want %d", why, got, want)
	}
}

// noSecretInClearText fails when one of the secrets appears in clear text in
// any file of the installation: the served processes' logs, the evidence
// database, the vault file (which holds the values encrypted), runtime
// records, the agent files and the company configuration.
func (o *onboarding) noSecretInClearText(secrets ...string) {
	o.t.Helper()
	files := 0
	err := filepath.WalkDir(o.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		for _, secret := range secrets {
			if bytes.Contains(raw, []byte(secret)) {
				o.t.Errorf("a secret is in clear text in %s", strings.TrimPrefix(path, o.dir))
			}
		}
		return nil
	})
	if err != nil {
		o.t.Fatalf("reading the installation's files: %v", err)
	}
	for _, must := range []string{"serve.log", "evidence.db", "secrets.db"} {
		if _, err := os.Stat(filepath.Join(o.dir, must)); err != nil {
			o.t.Fatalf("the check did not cover %s: %v", must, err)
		}
	}
	if files == 0 {
		o.t.Fatal("the check read no file")
	}
}

// view runs a default (human) operator view and returns what it printed.
func (o *onboarding) view(args ...string) string {
	o.t.Helper()
	out, stderr, code := o.talon(args...)
	if code != 0 {
		o.t.Fatalf("talon %s: %d\n%s\n%s", strings.Join(args, " "), code, out, stderr)
	}
	if strings.Contains(out, " INF ") || strings.Contains(stderr, " INF ") {
		o.t.Fatalf("talon %s prints informational log lines into an operator view:\n%s\n%s", strings.Join(args, " "), out, stderr)
	}
	return out
}

// wantView asserts what a default operator view says, and that it never
// says "healthy": the absence of a failure signal is not a working
// application, and the views keep the two apart (#567 review).
func (o *onboarding) wantView(why string, args []string, wants ...string) string {
	o.t.Helper()
	out := o.view(args...)
	for _, want := range wants {
		if !strings.Contains(out, want) {
			o.t.Fatalf("%s: `talon %s` misses %q:\n%s", why, strings.Join(args, " "), want, out)
		}
	}
	if strings.Contains(out, "healthy") {
		o.t.Fatalf("%s: `talon %s` says 'healthy':\n%s", why, strings.Join(args, " "), out)
	}
	return out
}

// listLine returns the line of the fleet listing for one use case, with its
// columns separated by single spaces.
func listLine(t *testing.T, listing, name string) string {
	t.Helper()
	for _, l := range strings.Split(listing, "\n") {
		if strings.HasPrefix(l, name+" ") {
			return strings.Join(strings.Fields(l), " ")
		}
	}
	t.Fatalf("no line for %s in:\n%s", name, listing)
	return ""
}

// wantReading asserts the one-line verification reading and what the newest
// LLM gateway record establishes about the credential stored now (#567
// review: historical traffic, traffic of the current registration and proof
// of the current credential are three different things).
func (o *onboarding) wantReading(name, why, code, credential string) effective.TrafficObservation {
	o.t.Helper()
	r := o.report(name)
	obs := traffic(r, effective.BoundaryLLMGateway)
	if r.Verification.Reading.Code != code || obs.Credential != credential {
		o.t.Fatalf("%s: reading %q, credential %q (%s); want reading %q, credential %q\n%s",
			why, r.Verification.Reading.Code, obs.Credential, obs.CredentialNote, code, credential, r.Verification.Reading.Text)
	}
	return obs
}

// registrationRecords counts a use case's signed registration records by
// kind.
func (o *onboarding) registrationRecords(name string) map[string]int {
	o.t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(o.dir, "evidence.db")+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		o.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.QueryContext(context.Background(), `SELECT invocation_type, COUNT(*) FROM evidence WHERE agent_id = ? AND invocation_type LIKE 'agent_regist%' GROUP BY invocation_type`, name)
	if err != nil {
		o.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			o.t.Fatal(err)
		}
		out[kind] = n
	}
	return out
}

// gatewayRecords counts the signed LLM gateway records per use case.
func (o *onboarding) gatewayRecords() map[string]int {
	o.t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(o.dir, "evidence.db")+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		o.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.QueryContext(context.Background(), `SELECT agent_id, COUNT(*) FROM evidence WHERE invocation_type = 'gateway' GROUP BY agent_id`)
	if err != nil {
		o.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var a string
		var n int
		if err := rows.Scan(&a, &n); err != nil {
			o.t.Fatal(err)
		}
		out[a] = n
	}
	return out
}

// TestE2E_Onboarding_FirstAndSecondApplication is the customer journey:
// register → connect → verify → operate, then a second unrelated
// application under the same, unchanged company policy. It needs the
// pinned OpenAI Node SDK (TALON_ONBOARDING_SDK_DIR); scripts/
// onboarding-acceptance.sh installs it and fails unless this test PASSES.
func TestE2E_Onboarding_FirstAndSecondApplication(t *testing.T) {
	if os.Getenv("TALON_ONBOARDING_SDK_DIR") == "" {
		t.Skip("set TALON_ONBOARDING_SDK_DIR to tests/onboarding with the pinned OpenAI SDK installed (scripts/onboarding-acceptance.sh does, and requires this test to pass)")
	}
	o := newOnboarding(t)
	companyBefore, _ := os.ReadFile(o.cfgPath)

	// 1-2. The installation is prepared; nothing is registered.
	if out, stderr, code := o.talon("validate"); code != 0 && !strings.Contains(out+stderr, "agent") {
		t.Fatalf("talon validate on the prepared installation: %d\n%s\n%s", code, out, stderr)
	}

	// 3. Register the first existing application. Nothing runs yet.
	key1, out := o.register("customer-support", "--owner", "support-engineering", "--description", "AI customer support assistant")
	for _, want := range []string{
		"Registered customer-support (tenant default)", "Owner     support-engineering", "Purpose   AI customer support assistant",
		"Company policy: inherited", "daily_cost 50", "pii_action block", "always enforced", "forbidden_tools delete_*",
		"Not active: no Talon process of this installation is running", "<talon-url>/v1/proxy/openai/v1",
		"Send one request from the application, then:", "talon agents show customer-support",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("registration output misses %q:\n%s", want, out)
		}
	}
	// The registration answers five questions on one screen; the policy's
	// provenance is one command away.
	if n := strings.Count(out, "\n"); n > 30 || strings.Contains(out, "precedence:") {
		t.Fatalf("the registration output is %d lines (want at most 30) or prints policy provenance:\n%s", n, out)
	}
	// Registered is not active and not connected: both operator views say
	// exactly what is known, and what to do next.
	o.wantView("registered, nothing running", []string{"agents", "show", "customer-support"},
		"customer-support — AI customer support assistant", "owner support-engineering",
		"Status      Not active", "Configured  enabled", "Runtime     not running", "Traffic     no request observed",
		"Policy      daily_cost 50 · monthly_cost 500 · pii_action block · forbidden_tools delete_*",
		"No Talon process of this installation is running", "talon agents show customer-support --effective")
	if got := listLine(t, o.wantView("registered, nothing running", []string{"agents"}, "USE CASE", "RUNTIME", "LAST REQUEST", "ATTENTION"), "customer-support"); !strings.HasPrefix(got, "customer-support enabled not running none observed ") {
		t.Fatalf("the listing for a registered use case nothing serves: %q", got)
	}
	agentFile, _ := os.ReadFile(filepath.Join(o.dir, "agents", "customer-support", "agent.talon.yaml"))
	if strings.Contains(string(agentFile), "pii_action") || strings.Contains(string(agentFile), key1) {
		t.Fatalf("the use case's file must hold neither company policy nor the key:\n%s", agentFile)
	}
	r := o.report("customer-support")
	if r.Loaded.State == runtimestatus.LoadedMatchesFile || r.LastDecision != nil || traffic(r, effective.BoundaryLLMGateway).State != effective.TrafficNone {
		t.Fatalf("registered, nothing running, no traffic: got loaded=%s last=%v traffic=%+v", r.Loaded.State, r.LastDecision, r.Verification.Traffic)
	}
	if c := r.Verification.Reading.Code; c != effective.ReadingLoadUnknown && c != effective.ReadingNotLoaded {
		t.Fatalf("a registered use case with no process must not read as loaded or connected: %s (%s)", c, r.Verification.Reading.Text)
	}
	if r.Effective.PIIAction != "block" || r.Effective.DailyCap != 50 {
		t.Fatalf("the company defaults are inherited: pii=%s daily=%v", r.Effective.PIIAction, r.Effective.DailyCap)
	}

	// 4-5. Start the gateway. The registration alone is not a connection:
	// loaded, and still no authenticated traffic.
	o.serve()
	defer func() { o.stop() }()
	o.waitLoaded("customer-support")
	r = o.report("customer-support")
	if r.Verification.Reading.Code != effective.ReadingLoadedNoTraffic || r.LastDecision != nil {
		t.Fatalf("loaded but never connected: %s; last decision %v", r.Verification.Reading.Text, r.LastDecision)
	}
	o.wantCalls(0, "before any application request")
	o.wantView("loaded, no request yet", []string{"agents", "show", "customer-support"},
		"Status      Waiting for its first request", "Runtime     loaded by the running Talon process", "Traffic     no request observed",
		"Point the application at <talon-url>/v1/proxy/openai/v1 with its Talon key", "answered 401 and leaves no record")
	if got := listLine(t, o.view("agents"), "customer-support"); !strings.HasPrefix(got, "customer-support enabled loaded none observed ") {
		t.Fatalf("the listing for a loaded use case without traffic: %q", got)
	}

	// The application, with the real SDK: a permitted request is answered
	// through Talon by the provider; a request the company policy blocks
	// never reaches the provider.
	if res := o.sdk(key1, "Summarise ticket T-30 in five words."); !res.OK || res.Content != "ok" {
		t.Fatalf("the permitted request: %+v", res)
	}
	o.wantCalls(1, "one permitted request")
	if res := o.sdk(key1, piiPrompt); res.OK || res.Status != 400 || res.Code != "pii_policy_violation" {
		t.Fatalf("the request the company policy blocks must surface as HTTP 400 pii_policy_violation in the SDK: %+v", res)
	}
	o.wantCalls(1, "the denied request reached the provider zero times")
	if res := o.sdk("talon_uc_"+strings.Repeat("0", 48), "hello"); res.OK || res.Status != 401 {
		t.Fatalf("an unknown key must be rejected with 401: %+v", res)
	}
	o.wantCalls(1, "an unknown key reached the provider zero times")

	// 6. Verify: authenticated traffic observed at the LLM gateway, the
	// record's signature verifies, and it was evaluated under the policy
	// the current files compile to. The newest request was denied: that
	// establishes the connection and the evaluation, not the provider.
	r = o.report("customer-support")
	g := traffic(r, effective.BoundaryLLMGateway)
	if g.State != effective.TrafficObserved || g.Verification != "valid" || g.Policy != effective.PolicyMatchesCurrent || g.Outcome == nil || g.Outcome.Decision != "denied" {
		t.Fatalf("observed traffic of the first application: %+v", g)
	}
	if r.Verification.Reading.Code != effective.ReadingTrafficMatches || r.LastDecision == nil || r.LastDecision.EvidenceID != g.EvidenceID {
		t.Fatalf("reading %s; last decision %+v", r.Verification.Reading.Code, r.LastDecision)
	}
	if traffic(r, effective.BoundaryActionGateway).State != effective.TrafficNone || traffic(r, effective.BoundaryMCPProxy).State != effective.TrafficNone {
		t.Fatalf("an LLM application is not presented as action or MCP traffic: %+v", r.Verification.Traffic)
	}
	if !strings.Contains(strings.Join(r.Verification.NotEstablished, "\n"), "that a provider was reached") {
		t.Fatalf("a denied newest request must not claim the provider was reached: %v", r.Verification.NotEstablished)
	}
	if vout, stderr, code := o.talon("audit", "verify", g.EvidenceID); code != 0 {
		t.Fatalf("talon audit verify %s: %d\n%s\n%s", g.EvidenceID, code, vout, stderr)
	}
	text, _, _ := o.talon("agents", "show", "customer-support", "--effective")
	for _, want := range []string{"5. Connection and verification", "Authenticated traffic observed under the expected policy", "llm_gateway:", "signature valid; policy matches_current", "not established by the above:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("talon agents show --effective misses %q:\n%s", want, text)
		}
	}

	// 7. Operate: the same facts in the read-only console (one projection).
	ui := startConsoleUI(t, o.dir, freePort(t), "--gateway-config", o.cfgPath)
	cc := newConsoleClient(t, ui.base)
	if st, body := cc.pair(ui.waitCodes(t, 1)[0]); st != 200 {
		t.Fatalf("pairing the console: %d %s", st, body)
	}
	var dto struct {
		Report *effective.Report `json:"report"`
	}
	consoleGet(t, cc, "/console/v1/use-cases/customer-support/effective-policy", &dto)
	cliV, _ := json.Marshal(o.report("customer-support").Verification)
	uiV, _ := json.Marshal(dto.Report.Verification)
	if !bytes.Equal(cliV, uiV) {
		t.Fatalf("the console and the CLI must state the same verification:\nCLI     %s\nconsole %s", cliV, uiV)
	}

	// 8. A second, unrelated application: one command, the same company
	// policy, nothing copied and nothing of the company or of the first
	// application changed. The first one keeps serving meanwhile.
	key2, out2 := o.register("hr-copilot", "--owner", "people-ops", "--description", "HR policy assistant")
	if key2 == key1 || !strings.Contains(out2, "Not active yet: the running Talon process loads it at its next re-scan of agents_dir") || !strings.Contains(out2, "No restart is needed") {
		t.Fatalf("second registration while serving:\n%s", out2)
	}
	if !strings.Contains(out2, "Company policy: inherited") || !strings.Contains(out2, "daily_cost 50") {
		t.Fatalf("the second application inherits the same company policy, stated the same way:\n%s", out2)
	}
	if res := o.sdk(key1, "Summarise ticket T-31 in five words."); !res.OK {
		t.Fatalf("the first application during the second registration: %+v", res)
	}
	o.wantCalls(2, "the first application keeps working")
	o.waitLoaded("hr-copilot")
	if res := o.sdk(key2, "Which policy covers parental leave?"); !res.OK {
		t.Fatalf("the second application's permitted request: %+v", res)
	}
	o.wantCalls(3, "the second application's permitted request")
	if res := o.sdk(key2, piiPrompt); res.OK || res.Status != 400 || res.Code != "pii_policy_violation" {
		t.Fatalf("the same company rule applies to the second application: %+v", res)
	}
	o.wantCalls(3, "the second application's denied request reached the provider zero times")

	r2 := o.report("hr-copilot")
	if g2 := traffic(r2, effective.BoundaryLLMGateway); g2.State != effective.TrafficObserved || g2.Policy != effective.PolicyMatchesCurrent || g2.EvidenceID == g.EvidenceID {
		t.Fatalf("observed traffic of the second application: %+v", g2)
	}
	if r2.Effective.PIIAction != r.Effective.PIIAction || r2.Effective.DailyCap != r.Effective.DailyCap || fmt.Sprint(r2.Effective.ForbiddenTools) != fmt.Sprint(r.Effective.ForbiddenTools) {
		t.Fatalf("both applications run under the same company baseline: %+v vs %+v", r2.Effective, r.Effective)
	}
	if got := o.gatewayRecords(); got["customer-support"] != 3 || got["hr-copilot"] != 2 || len(got) != 2 {
		t.Fatalf("evidence is scoped to each application (and an unknown key leaves none): %v", got)
	}
	companyAfter, _ := os.ReadFile(o.cfgPath)
	if !bytes.Equal(companyBefore, companyAfter) {
		t.Fatal("registering applications changed the company configuration")
	}

	// Operating both: the listing is what an operator scans, the single
	// view says what happened and that nothing needs doing. The newest
	// request of the second application was denied by the company policy:
	// that is traffic and a policy evaluation, shown as what it is.
	listing := o.wantView("two applications with traffic", []string{"agents"}, "USE CASE", "STATE", "RUNTIME", "LAST REQUEST", "COST THIS MONTH", "ATTENTION")
	for _, name := range []string{"customer-support", "hr-copilot"} {
		if got := listLine(t, listing, name); !regexp.MustCompile(`^` + name + ` enabled loaded \d+[sm] ago `).MatchString(got) {
			t.Fatalf("the listing for %s after its requests: %q", name, got)
		}
	}
	o.wantView("the second application after an allowed and a denied request", []string{"agents", "show", "hr-copilot"},
		"hr-copilot — HR policy assistant", "owner people-ops", "Status      Working", "Runtime     loaded by the running Talon process",
		"in the last hour (1 denied)", "the newest authenticated request was evaluated under this policy",
		"LLM gateway · denied by Talon, not dispatched", "POLICY_DENIED_PII_INPUT", "(signature valid)", "Nothing to do")

	// The machine contracts did not change with the views: the listing's
	// JSON is the fleet rows, the single view's JSON is one such row, and
	// the full report is still `--effective`.
	var fleetJSON struct {
		Offline bool                         `json:"offline"`
		Agents  []map[string]json.RawMessage `json:"agents"`
	}
	rawFleet, _, _ := o.talon("agents", "--json")
	if err := json.Unmarshal([]byte(rawFleet), &fleetJSON); err != nil || len(fleetJSON.Agents) != 2 {
		t.Fatalf("talon agents --json: %v\n%s", err, rawFleet)
	}
	var rowJSON map[string]json.RawMessage
	rawRow, _, _ := o.talon("agents", "show", "hr-copilot", "--json")
	if err := json.Unmarshal([]byte(rawRow), &rowJSON); err != nil {
		t.Fatalf("talon agents show --json: %v\n%s", err, rawRow)
	}
	for _, field := range []string{"name", "tenant_id", "state", "health", "why", "spend_month", "monthly_cap", "requests", "denied", "last_run", "config_path", "policy_digest", "use_case"} {
		if _, ok := rowJSON[field]; !ok {
			t.Fatalf("talon agents show --json lost the field %q:\n%s", field, rawRow)
		}
		if _, ok := fleetJSON.Agents[0][field]; !ok && field != "use_case" && field != "last_run" {
			t.Fatalf("talon agents --json rows lost the field %q:\n%s", field, rawFleet)
		}
	}
	for _, added := range []string{"verification", "next", "loaded"} {
		if _, ok := rowJSON[added]; ok {
			t.Fatalf("talon agents show --json grew the field %q: the row contract is the fleet row; the report is --effective --json", added)
		}
	}
	if full := o.view("agents", "show", "hr-copilot", "--effective"); !strings.Contains(full, "5. Connection and verification") || !strings.Contains(full, "precedence:") {
		t.Fatalf("the full report must stay available and detailed:\n%s", full)
	}

	// A policy change to the first application: its earlier request is now
	// reported as evaluated under ANOTHER policy than the current file,
	// never as verified; a new request matches again.
	path := filepath.Join(o.dir, "agents", "customer-support", "agent.talon.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(agentFile), "cost_limits: {}", "cost_limits:\n    daily: 5", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	o.waitLoaded("customer-support")
	r = o.report("customer-support")
	if g := traffic(r, effective.BoundaryLLMGateway); g.Policy != effective.PolicyDiffers || r.Verification.Reading.Code != effective.ReadingTrafficDiffers || r.Effective.DailyCap != 5 {
		t.Fatalf("after a policy change the earlier evidence must read as a different policy: %+v (%s), daily cap %v", g, r.Verification.Reading.Code, r.Effective.DailyCap)
	}
	if res := o.sdk(key1, "Summarise ticket T-32 in five words."); !res.OK {
		t.Fatalf("a request under the changed policy: %+v", res)
	}
	o.wantCalls(4, "a request under the changed policy")
	if r = o.report("customer-support"); r.Verification.Reading.Code != effective.ReadingTrafficMatches {
		t.Fatalf("a request under the current policy verifies again: %s", r.Verification.Reading.Text)
	}

	// A use case cannot weaken a mandatory company rule from its own file:
	// it asks for "redact" where the company floor is "block". After the
	// reload the effective policy still blocks, the canonical projection
	// says which layer won, and a request with personal data is still
	// refused before the provider.
	weaker := strings.Replace(string(agentFile), "cost_limits: {}", "data_classification:\n    input_scan: true\n    redact_pii: true\n  cost_limits:\n    daily: 5", 1)
	if err := os.WriteFile(path, []byte(weaker), 0o600); err != nil {
		t.Fatal(err)
	}
	o.waitLoaded("customer-support")
	r = o.report("customer-support")
	var pii struct{ effective, winner, useCase string }
	for _, rule := range r.Effective.Rules {
		if rule.Rule == "pii_action" {
			pii.effective, pii.winner = rule.Effective, rule.Winner
			for _, c := range rule.Candidates {
				if c.Source == "use_case" {
					pii.useCase = c.Value
				}
			}
		}
	}
	if r.Effective.PIIAction != "block" || pii.effective != "block" || pii.winner != "organization.defaults" || pii.useCase != "redact" {
		t.Fatalf("the company floor must win over the use case's weaker value: effective=%s rule=%+v", r.Effective.PIIAction, pii)
	}
	before := o.calls.Load()
	if res := o.sdk(key1, piiPrompt); res.OK || res.Status != 400 || res.Code != "pii_policy_violation" {
		t.Fatalf("a use case that asks for a weaker PII action is still blocked by the company floor: %+v", res)
	}
	o.wantCalls(before, "the request the company floor blocks reached the provider zero times")
	if res := o.sdk(key1, "Summarise ticket T-33 in five words."); !res.OK {
		t.Fatalf("a permitted request under the tightened file: %+v", res)
	}
	o.wantCalls(before+1, "a permitted request under the tightened file")

	// An invalid file appears in the fleet: the reload is rejected, the
	// last-known-good generation keeps serving both applications, a new
	// registration is refused without writing, and nothing claims the
	// broken fleet is active.
	broken := filepath.Join(o.dir, "agents", "broken")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "agent.talon.yaml"), []byte("agent:\n  name: broken\n  typo_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second) // several reload intervals
	if res := o.sdk(key1, "Still there?"); !res.OK {
		t.Fatalf("last-known-good must keep serving the first application: %+v", res)
	}
	if res := o.sdk(key2, "Still there?"); !res.OK {
		t.Fatalf("last-known-good must keep serving the second application: %+v", res)
	}
	o.wantCalls(before+3, "both applications on last-known-good")
	if out, stderr, code := o.talon("agents", "add", "third-app"); code == 0 || !strings.Contains(stderr, "does not validate") {
		t.Fatalf("a registration into an invalid fleet must be refused: %d\n%s\n%s", code, out, stderr)
	}
	if _, err := os.Stat(filepath.Join(o.dir, "agents", "third-app")); !os.IsNotExist(err) {
		t.Fatal("the refused registration wrote a directory")
	}
	if err := os.RemoveAll(broken); err != nil {
		t.Fatal(err)
	}

	// After the whole journey no credential has left the vault in clear
	// text: neither application's key and not the provider's key, in no
	// file of the installation (logs, evidence, vault file, runtime
	// records, agent files, company configuration) and in nothing the
	// console's read API returns.
	o.noSecretInClearText(key1, key2, onboardingProviderKey)

	// The server stops. The traffic that verified is still on record, and
	// nothing serves the applications now: the views say the second, not
	// "working" on the strength of the first.
	o.stop()
	o.wantView("verified earlier, server stopped", []string{"agents", "show", "hr-copilot"},
		"Status      Not active", "Runtime     not running", "verified, but that was earlier", "no Talon process of this installation is running")
	if got := listLine(t, o.view("agents"), "hr-copilot"); !strings.HasPrefix(got, "hr-copilot enabled not running ") {
		t.Fatalf("the listing after the server stopped: %q", got)
	}
	for _, path := range []string{
		"/console/v1/overview", "/console/v1/use-cases", "/console/v1/use-cases/customer-support", "/console/v1/use-cases/hr-copilot",
		"/console/v1/use-cases/customer-support/effective-policy", "/console/v1/use-cases/hr-copilot/effective-policy",
		"/console/v1/configuration", "/console/v1/system", "/console/v1/activity", "/console/v1/sessions", "/console/v1/costs",
	} {
		status, body, _ := cc.do(http.MethodGet, path, "", nil)
		if status != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, status, body)
		}
		for _, secret := range []string{key1, key2, onboardingProviderKey} {
			if strings.Contains(body, secret) {
				t.Fatalf("the console returned a credential in %s", path)
			}
		}
		if strings.Contains(body, "talon_uc_") {
			t.Fatalf("the console returned something shaped like a use-case key in %s", path)
		}
	}
}

// chat sends one request with the given key over plain HTTP and returns the
// status (the credential-lifecycle test needs many, quickly).
func (o *onboarding) chat(key string) int {
	o.t.Helper()
	return chatThroughGateway(o.t, o.url, key, "")
}

// inFlight sends one request that the upstream keeps open, and returns once
// it is in flight at the provider. release lets the provider answer; the
// returned channel then yields the HTTP status the application received
// (0 when the request failed).
func (o *onboarding) inFlight(key string) (release func(), status <-chan int) {
	o.t.Helper()
	gate := make(chan struct{})
	o.hold.Store(&gate)
	done := make(chan int, 1)
	go func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, o.url+"/v1/proxy/openai/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"a request that is in flight"}]}`))
		if err != nil {
			done <- 0
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- 0
			return
		}
		_ = resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case <-o.holding:
	case st := <-done:
		o.t.Fatalf("the request never reached the provider: HTTP %d", st)
	case <-time.After(20 * time.Second):
		o.t.Fatal("the request never reached the provider")
	}
	return sync.OnceFunc(func() { close(gate) }), done
}

// TestE2E_Onboarding_CredentialLifecycle: one active key per use case, and
// what an operator actually does to replace, recover and revoke it.
func TestE2E_Onboarding_CredentialLifecycle(t *testing.T) {
	o := newOnboarding(t)
	key, _ := o.register("customer-support", "--owner", "support-engineering")
	other, _ := o.register("hr-copilot", "--owner", "people-ops")
	o.serve()
	defer func() { o.stop() }()
	o.waitLoaded("customer-support")
	if st := o.chat(key); st != 200 {
		t.Fatalf("the issued key: HTTP %d", st)
	}
	o.wantCalls(1, "the issued key")
	first := o.wantReading("customer-support", "the first request with the issued key", effective.ReadingTrafficMatches, effective.CredentialCurrent)

	// `talon secrets rotate` re-encrypts the SAME value with a fresh nonce:
	// it is not a credential replacement. After it, and a restart, the same
	// key still authenticates.
	if out, stderr, code := o.talon("secrets", "rotate", "customer-support-talon-key"); code != 0 {
		t.Fatalf("secrets rotate: %d\n%s\n%s", code, out, stderr)
	}
	o.stop()
	o.serve()
	if st := o.chat(key); st != 200 {
		t.Fatalf("after 'secrets rotate' and a restart the SAME key must still work (rotate re-encrypts, it does not replace): HTTP %d", st)
	}
	o.wantCalls(2, "after secrets rotate")
	// Re-encryption is not a new credential: the traffic stays attributed to
	// the credential stored now.
	o.wantReading("customer-support", "after 'secrets rotate' (same value, re-encrypted)", effective.ReadingTrafficMatches, effective.CredentialCurrent)

	// Replacement (also the lost-key procedure): a new value through stdin,
	// never an argument, with the ACL of the use case.
	const replacement = "talon_uc_replacement_0123456789abcdef0123456789abcdef"
	out, code := o.talonStdin(replacement, "secrets", "set", "customer-support-talon-key", "--tenant", "default", "--agent", "customer-support")
	if code != 0 || strings.Contains(out, replacement) {
		t.Fatalf("replacing the key through stdin (and never echoing it): %d\n%s", code, out)
	}
	// Replacing the credential does not imply that it is used: every record
	// so far was made with the previous one.
	o.wantReading("customer-support", "after the replacement, before any new request", effective.ReadingTrafficHistorical, effective.CredentialPrevious)
	// The default view says it in one line and names the step.
	o.wantView("key replaced, server not restarted", []string{"agents", "show", "customer-support"},
		"Status      Needs attention", "The key was replaced, and the running Talon process still holds the earlier one. Restart `talon serve`")
	// A secret-only change is not a configuration change: the running
	// process keeps the key it loaded until it is restarted.
	time.Sleep(2500 * time.Millisecond) // more than two reload intervals
	if st := o.chat(key); st != 200 {
		t.Fatalf("before the restart the running process still holds the old key: HTTP %d", st)
	}
	if st := o.chat(replacement); st != 401 {
		t.Fatalf("before the restart the new key is not active: HTTP %d", st)
	}
	o.wantCalls(3, "before the restart")
	// That request is NEWER than the stored credential, and it still proves
	// nothing about it: the process that served it started before the
	// replacement and holds the previous key. A record's time alone never
	// verifies the current credential.
	o.wantReading("customer-support", "a request the previous runtime generation served after the replacement", effective.ReadingTrafficCredentialUnproven, effective.CredentialNotEstablished)
	// The restart is a graceful stop (SIGTERM): a request that is in flight
	// at the provider is not cut off. The process stops accepting new
	// connections, waits for the answer, delivers it, and only then exits.
	releaseOld, inFlightOld := o.inFlight(key)
	defer releaseOld()
	stopped := make(chan struct{})
	go func() { o.stop(); close(stopped) }()
	o.waitFor("the stopping process to refuse new connections", func() bool {
		conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", o.port))
		if err == nil {
			_ = conn.Close()
		}
		return err != nil
	})
	select {
	case <-stopped:
		t.Fatal("the process exited while a request was still in flight at the provider")
	case st := <-inFlightOld:
		t.Fatalf("the in-flight request ended before the provider answered: HTTP %d", st)
	default:
	}
	releaseOld()
	select {
	case st := <-inFlightOld:
		if st != 200 {
			t.Fatalf("a request in flight during the graceful restart must finish: HTTP %d", st)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the in-flight request never finished")
	}
	<-stopped
	o.wantCalls(4, "the request that was in flight during the restart")
	o.serve()
	// The restart alone verifies nothing either: the newest record is still
	// the one the previous process served.
	o.wantReading("customer-support", "after the restart, before any request with the new key", effective.ReadingTrafficCredentialUnproven, effective.CredentialNotEstablished)
	if st := o.chat(key); st != 401 {
		t.Fatalf("after the restart the OLD key must be rejected: HTTP %d", st)
	}
	if st := o.chat(replacement); st != 200 {
		t.Fatalf("after the restart the NEW key must work: HTTP %d", st)
	}
	o.wantCalls(5, "the replaced key: one accepted request, the old key reached the provider zero times")
	// New traffic, served by a process that started with the stored
	// credential: verified.
	o.wantReading("customer-support", "the first request with the replacement key", effective.ReadingTrafficMatches, effective.CredentialCurrent)
	if st := o.chat(other); st != 200 {
		t.Fatalf("the other application is unaffected by the replacement: HTTP %d", st)
	}
	o.wantCalls(6, "the other application")

	// Emergency disable: a configuration change, effective when the running
	// process has loaded it — verified, not assumed. First the hard case:
	// another file of the fleet is invalid, so the reload is rejected, the
	// last-known-good generation keeps serving and the disable is NOT
	// active, although the file says "disabled". The report says exactly
	// that: configured as disabled, and the running process has another
	// version of the file.
	broken := filepath.Join(o.dir, "agents", "broken")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "agent.talon.yaml"), []byte("agent:\n  name: broken\n  typo_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dout, stderr, code := o.talon("agents", "disable", "customer-support")
	if code != 0 || !strings.Contains(dout, "last-known-good") {
		t.Fatalf("agents disable with an invalid fleet must succeed and warn that the running fleet keeps last-known-good: %d\n%s\n%s", code, dout, stderr)
	}
	time.Sleep(3 * time.Second) // several reload intervals, every one rejected
	if st := o.chat(replacement); st != 200 {
		t.Fatalf("while the reload is rejected the disable is not active and last-known-good keeps serving: HTTP %d", st)
	}
	if r := o.report("customer-support"); r.Verification.Configured != "disabled" || r.Loaded.State == runtimestatus.LoadedMatchesFile {
		t.Fatalf("configured as disabled but not loaded must not read as active: configured=%s loaded=%s (%s)", r.Verification.Configured, r.Loaded.State, r.Loaded.Reason)
	}
	// A request of the use case is in flight at the provider when the
	// disable becomes active.
	release, inFlight := o.inFlight(replacement)
	defer release()
	// The fleet is fixed: the next reload activates the disable.
	if err := os.RemoveAll(broken); err != nil {
		t.Fatal(err)
	}
	o.waitFor("the running process to refuse the disabled use case", func() bool { return o.chat(replacement) != 200 })
	before := o.calls.Load()
	if st := o.chat(replacement); st == 200 || st == 401 {
		t.Fatalf("a disabled use case is refused as itself (authenticated, then denied), not as an unknown key: HTTP %d", st)
	}
	o.wantCalls(before, "a disabled use case reaches the provider zero times")
	// The disable refuses NEW work; the request that was already in flight
	// is not cut off: when the provider answers, the application gets its
	// answer.
	select {
	case st := <-inFlight:
		t.Fatalf("the in-flight request ended before the provider answered: HTTP %d", st)
	default:
	}
	release()
	select {
	case st := <-inFlight:
		if st != 200 {
			t.Fatalf("a request in flight when the disable became active must finish: HTTP %d", st)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the in-flight request never finished after the provider answered")
	}
	o.wantCalls(before, "the in-flight request was counted when it reached the provider, before the disable")
	if r := o.report("customer-support"); r.Verification.Configured != "disabled" || r.Verification.Reading.Code != effective.ReadingDisabled {
		t.Fatalf("the report must say the use case is configured as disabled: %+v", r.Verification.Reading)
	}
	o.wantView("disabled and active", []string{"agents", "show", "customer-support"},
		"Status      Disabled", "Configured  disabled (agent.enabled: false)", "talon agents enable customer-support")
	if got := listLine(t, o.view("agents"), "customer-support"); !strings.HasPrefix(got, "customer-support stopped ") || !strings.Contains(got, "stopped: disabled by operator") {
		t.Fatalf("the listing for a disabled use case: %q", got)
	}
	if st := o.chat(other); st != 200 {
		t.Fatalf("the other application keeps working while one is disabled: HTTP %d", st)
	}
	if out, stderr, code := o.talon("agents", "enable", "customer-support"); code != 0 {
		t.Fatalf("agents enable: %d\n%s\n%s", code, out, stderr)
	}
	o.waitFor("the running process to serve the re-enabled use case", func() bool { return o.chat(replacement) == 200 })

	// Revocation: the use case is removed from the fleet; after the reload
	// its key is an unknown key. The vault entry is deleted afterwards.
	if err := os.RemoveAll(filepath.Join(o.dir, "agents", "customer-support")); err != nil {
		t.Fatal(err)
	}
	o.waitFor("the running process to drop the removed use case", func() bool { return o.chat(replacement) == 401 })
	if out, stderr, code := o.talon("secrets", "delete", "customer-support-talon-key"); code != 0 {
		t.Fatalf("secrets delete: %d\n%s\n%s", code, out, stderr)
	}
	if st := o.chat(other); st != 200 {
		t.Fatalf("the other application after the revocation: HTTP %d", st)
	}
	// The same name can be registered again with a new key.
	again, _ := o.register("customer-support", "--owner", "support-engineering")
	if again == key || again == replacement {
		t.Fatal("a re-registration issues a new key")
	}
	// A re-registration without new traffic is not verified: every record
	// under the name was made with a credential that no longer exists. The
	// earlier evidence stays readable and still verifies as evidence.
	old := o.wantReading("customer-support", "a re-registration before any request with its key", effective.ReadingTrafficHistorical, effective.CredentialPrevious)
	if old.EvidenceID == "" || old.Verification != "valid" {
		t.Fatalf("the earlier record must stay accessible and verifiable: %+v", old)
	}
	for _, id := range []string{first.EvidenceID, old.EvidenceID} {
		if out, stderr, code := o.talon("audit", "verify", id); code != 0 {
			t.Fatalf("talon audit verify %s (a record of the previous registration): %d\n%s\n%s", id, code, out, stderr)
		}
	}
	o.waitFor("the re-registered use case to be served", func() bool { return o.chat(again) == 200 })
	// The running process picked the name up by a reload. It had started
	// before the new credential was stored, and a reload is not proof that
	// it read the new key (a rebuild keeps the previous one when the vault
	// cannot be read at that moment): the request is observed, the current
	// credential is not established, and the report says so.
	unproven := o.wantReading("customer-support", "a request the already-running process served after the re-registration", effective.ReadingTrafficCredentialUnproven, effective.CredentialNotEstablished)
	if unproven.EvidenceID == old.EvidenceID {
		t.Fatal("the report must name the new request, not the previous registration's")
	}
	// A process that starts after the credential was stored reads it from
	// the vault and can hold nothing else: its first request verifies.
	o.stop()
	o.serve()
	o.waitLoaded("customer-support")
	if st := o.chat(again); st != 200 {
		t.Fatalf("the re-registration's key after a restart: HTTP %d", st)
	}
	now := o.wantReading("customer-support", "the first request served by a process started after the re-registration", effective.ReadingTrafficMatches, effective.CredentialCurrent)
	if now.EvidenceID == unproven.EvidenceID || now.EvidenceID == old.EvidenceID {
		t.Fatal("the verified record must be the request the restarted process served")
	}
}

// Concurrent registrations of ONE name, as separate processes (#567 review):
// exactly one succeeds; the losers change nothing; the winner's printed key
// is the key that authenticates. The registration lock serializes them, so
// the evidence is truthful too: one signed intent and one completion, and
// no record that says a registration was rolled back, because none was.
func TestE2E_Onboarding_ConcurrentProcessesOneWinner(t *testing.T) {
	o := newOnboarding(t)
	const n = 5
	var wg sync.WaitGroup
	outs, codes := make([]string, n), make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, stderr, code := RunTalon(t, o.dir, o.env(), "agents", "add", "refund-bot", "--owner", "finance")
			outs[i], codes[i] = out+stderr, code
		}(i)
	}
	wg.Wait()
	winner := ""
	for i := 0; i < n; i++ {
		k := useCaseKeyRe.FindString(outs[i])
		switch {
		case codes[i] == 0 && k != "" && winner == "":
			winner = k
		case codes[i] == 0:
			t.Fatalf("more than one registration succeeded:\n%s", strings.Join(outs, "\n---\n"))
		case k != "":
			t.Fatalf("a refused registration printed a key:\n%s", outs[i])
		}
	}
	if winner == "" {
		t.Fatalf("no registration succeeded:\n%s", strings.Join(outs, "\n---\n"))
	}
	if out, stderr, code := o.talon("validate"); code != 0 {
		t.Fatalf("talon validate after the race: %d\n%s\n%s", code, out, stderr)
	}
	for i := 0; i < n; i++ {
		if codes[i] != 0 && !strings.Contains(outs[i], "already registered") {
			t.Fatalf("a registration that lost the race must be refused because the name is registered, got:\n%s", outs[i])
		}
	}
	if got := o.registrationRecords("refund-bot"); got["agent_registration_intent"] != 1 || got["agent_registered"] != 1 || len(got) != 2 {
		t.Fatalf("the race must leave one signed intent, one completion and no rollback record, got %v", got)
	}
	if out, _, _ := o.talon("doctor", "--skip-upstream"); !strings.Contains(out, "No unresolved use-case registration.") {
		t.Fatalf("after the race doctor must report no unresolved registration:\n%s", out)
	}
	o.serve()
	defer func() { o.stop() }()
	o.waitFor("the winner's key to authenticate", func() bool { return o.chat(winner) == 200 })
}

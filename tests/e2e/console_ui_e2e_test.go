//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/console/access"
	"github.com/dativo-io/talon/internal/fleet"
)

var pairingCodeRE = regexp.MustCompile(`Talon console pairing code: ([A-Z2-9]{5}(?:-[A-Z2-9]{5}){3})`)

// uiProcess is a running `talon ui serve`.
type uiProcess struct {
	cmd  *exec.Cmd
	log  string
	base string
}

func startConsoleUI(t *testing.T, dir string, port int, extra ...string) *uiProcess {
	t.Helper()
	args := append([]string{"ui", "serve", "--listen", fmt.Sprintf("127.0.0.1:%d", port), "--store-wait", "5s"}, extra...)
	cmd := exec.CommandContext(context.Background(), binaryPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TALON_DATA_DIR="+dir, "TALON_SIGNING_KEY="+testSigningKey, "TALON_LOG_FORMAT=json")
	logPath := filepath.Join(dir, fmt.Sprintf("ui-%d-%d.log", port, time.Now().UnixNano()))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ui serve: %v", err)
	}
	p := &uiProcess{cmd: cmd, log: logPath, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	t.Cleanup(func() { p.stop(); _ = logFile.Close() })
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, p.base+"/healthz", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return p
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("ui serve not healthy; log:\n%s", p.readLog())
	return nil
}

func (p *uiProcess) stop() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
}

func (p *uiProcess) readLog() string {
	b, _ := os.ReadFile(p.log)
	return string(b)
}

// codes returns every pairing code printed so far, oldest first: the only
// place a code ever appears.
func (p *uiProcess) codes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, m := range pairingCodeRE.FindAllStringSubmatch(p.readLog(), -1) {
		out = append(out, m[1])
	}
	return out
}

func (p *uiProcess) waitCodes(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c := p.codes(t); len(c) >= n {
			return c
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected %d pairing codes in the log, log:\n%s", n, p.readLog())
	return nil
}

type consoleClient struct {
	t    *testing.T
	http *http.Client
	base string
}

func newConsoleClient(t *testing.T, base string) *consoleClient {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &consoleClient{t: t, http: &http.Client{Jar: jar, Timeout: 10 * time.Second}, base: base}
}

func (c *consoleClient) do(method, path, body string, hdr map[string]string) (int, string, http.Header) {
	c.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String(), resp.Header
}

func (c *consoleClient) pair(code string) (int, string) {
	c.t.Helper()
	status, body, hdr := c.do(http.MethodPost, "/console/auth/pair", `{"code":`+strconv(code)+`}`, map[string]string{"Content-Type": "application/json"})
	if status == http.StatusOK {
		set := hdr.Get("Set-Cookie")
		if !strings.Contains(set, access.CookieName+"=") || !strings.Contains(set, "HttpOnly") || !strings.Contains(set, "SameSite=Strict") || strings.Contains(set, code) {
			c.t.Fatalf("Set-Cookie must carry an HttpOnly, SameSite=Strict opaque session, got %q", set)
		}
	}
	return status, body
}

func strconv(s string) string { b, _ := json.Marshal(s); return string(b) }

func (c *consoleClient) sessionCookie() *http.Cookie {
	c.t.Helper()
	u, _ := http.NewRequest(http.MethodGet, c.base, nil)
	for _, ck := range c.http.Jar.Cookies(u.URL) {
		if ck.Name == access.CookieName {
			return ck
		}
	}
	return nil
}

// TestE2E_ConsoleUI_PairingReadOnlyProcess (#536, #537): the packaged binary
// runs the console as its own process on loopback; a browser pairs with the
// one-time code printed to the process log, reads the same facts the CLI
// reads, cannot reach any privileged route, and the console's restarts and
// stops never touch the data plane.
func TestE2E_ConsoleUI_PairingReadOnlyProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl_ui","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", consoleAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	gatewayBlock := fmt.Sprintf("\ngateway:\n  enabled: true\n  listen_prefix: \"/v1/proxy\"\n  providers:\n    openai:\n      enabled: true\n      secret_name: \"openai-api-key\"\n      base_url: %q\n", upstream.URL)
	if err := os.WriteFile(cfgPath, append(cfg, []byte(gatewayBlock)...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][2]string{{"openai-api-key", "sk-fake-e2e-provider-key"}, {consoleAgent + "-talon-key", consoleAgentKey}} {
		if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", kv[0], kv[1]); code != 0 {
			t.Fatalf("secrets set %s: %d\n%s", kv[0], code, stderr)
		}
	}

	// ---- fail closed before anything listens ----------------------------
	uiPort := freePort(t)
	missing := filepath.Join(t.TempDir(), "nowhere")
	out, stderr, code := RunTalon(t, dir, map[string]string{"TALON_DATA_DIR": missing}, "ui", "serve", "--listen", fmt.Sprintf("127.0.0.1:%d", uiPort), "--store-wait", "1s")
	if code == 0 || !strings.Contains(stderr+out, "no Talon installation") {
		t.Fatalf("ui serve without an installation must fail naming the problem; code=%d\n%s%s", code, out, stderr)
	}
	out, stderr, code = RunTalon(t, dir, nil, "ui", "serve", "--listen", fmt.Sprintf("127.0.0.1:%d", uiPort), "--store-wait", "1s")
	if code == 0 || !strings.Contains(stderr+out, "start 'talon serve'") {
		t.Fatalf("ui serve before the data plane ever ran must fail and say what to start; code=%d\n%s%s", code, out, stderr)
	}
	out, stderr, code = RunTalon(t, dir, nil, "ui", "serve", "--listen", fmt.Sprintf("0.0.0.0:%d", uiPort))
	if code == 0 || !strings.Contains(stderr+out, "allow-non-loopback") {
		t.Fatalf("ui serve on a non-loopback address must be refused without --allow-non-loopback; code=%d\n%s%s", code, out, stderr)
	}
	probe, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/healthz", uiPort), nil)
	if resp, err := http.DefaultClient.Do(probe); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("nothing may listen after a refused start")
	}

	// ---- data plane with real traffic ------------------------------------
	dpPort := freePort(t)
	dpURL := fmt.Sprintf("http://127.0.0.1:%d", dpPort)
	stopDP := startConsoleServe(t, dir, dpPort, map[string]string{"TALON_ADMIN_KEY": consoleAdminKey})
	defer func() { stopDP() }()
	for i := 0; i < 2; i++ {
		if code := chatThroughGateway(t, dpURL, consoleAgentKey, consoleSession); code != http.StatusOK {
			t.Fatalf("governed chat %d: HTTP %d", i, code)
		}
	}

	// ---- console process: pairing ----------------------------------------
	ui := startConsoleUI(t, dir, uiPort)
	logBefore := ui.readLog()
	if strings.Contains(logBefore, consoleAdminKey) || strings.Contains(logBefore, consoleAgentKey) || strings.Contains(logBefore, testSigningKey) {
		t.Fatalf("a key leaked into the console log:\n%s", logBefore)
	}
	first := ui.waitCodes(t, 1)[0]

	anon := newConsoleClient(t, ui.base)
	if status, body, _ := anon.do(http.MethodGet, "/console/v1/overview", "", nil); status != http.StatusUnauthorized || !strings.Contains(body, access.ReasonSessionRequired) {
		t.Fatalf("unpaired read: %d %s", status, body)
	}
	if status, body, _ := anon.do(http.MethodGet, "/", "", nil); status != http.StatusOK || !strings.Contains(body, `<div id="root"></div>`) {
		t.Fatalf("shell: %d", status)
	}
	if status, body := anon.pair("AAAAA-AAAAA-AAAAA-AAAAA"); status != http.StatusUnauthorized || !strings.Contains(body, access.ReasonPairingMismatch) {
		t.Fatalf("wrong code: %d %s", status, body)
	}
	if status, body := anon.pair(first); status != http.StatusTooManyRequests || !strings.Contains(body, access.ReasonPairingThrottled) {
		t.Fatalf("an attempt right after another must be throttled: %d %s", status, body)
	}
	time.Sleep(access.DefaultMinAttemptGap + 100*time.Millisecond)
	cross := newConsoleClient(t, ui.base)
	if status, body, _ := cross.do(http.MethodPost, "/console/auth/pair", `{"code":"`+first+`"}`, map[string]string{"Content-Type": "application/json", "Origin": "http://evil.example"}); status != http.StatusForbidden || !strings.Contains(body, access.ReasonCrossOrigin) {
		t.Fatalf("cross-origin pairing: %d %s", status, body)
	}
	if cross.sessionCookie() != nil {
		t.Fatalf("a rejected pairing minted a cookie")
	}
	rebound, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ui.base+"/healthz", nil)
	rebound.Host = "attacker.example:" + fmt.Sprint(uiPort)
	if resp, err := http.DefaultClient.Do(rebound); err != nil || resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("DNS-rebinding host must be refused (421), got %v %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}

	browser := newConsoleClient(t, ui.base)
	if status, body := browser.pair(first); status != http.StatusOK {
		t.Fatalf("pair with the printed code: %d %s", status, body)
	}
	ck := browser.sessionCookie()
	if ck == nil || ck.Value == first || len(ck.Value) < 40 {
		t.Fatalf("session cookie: %+v", ck)
	}
	time.Sleep(access.DefaultMinAttemptGap + 100*time.Millisecond)
	if status, body := newConsoleClient(t, ui.base).pair(first); status != http.StatusUnauthorized || !strings.Contains(body, access.ReasonPairingNoCode) {
		t.Fatalf("replay of a used code: %d %s", status, body)
	}

	// ---- the paired browser reads what the CLI reads ----------------------
	var ov console.Overview
	status, body, hdr := browser.do(http.MethodGet, "/console/v1/overview?tenant=default", "", nil)
	if status != http.StatusOK {
		t.Fatalf("overview: %d %s", status, body)
	}
	if hdr.Get("Cache-Control") != "no-store" || !strings.Contains(hdr.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("security headers missing: %v", hdr)
	}
	mustJSON(t, body, &ov)
	var row *fleet.AgentRow
	for i := range ov.UseCases.Rows {
		if ov.UseCases.Rows[i].Name == consoleAgent {
			row = &ov.UseCases.Rows[i]
		}
	}
	if row == nil || row.Requests != 2 {
		t.Fatalf("console overview row: %+v", row)
	}
	var cli struct {
		Agents []fleet.AgentRow `json:"agents"`
	}
	out, stderr, code = RunTalon(t, dir, map[string]string{"TALON_ADMIN_KEY": consoleAdminKey}, "agents", "--json", "--url", dpURL)
	if code != 0 {
		t.Fatalf("agents --json: %d %s", code, stderr)
	}
	mustJSON(t, out, &cli)
	for _, a := range cli.Agents {
		if a.Name == consoleAgent && (a.Requests != row.Requests || a.Denied != row.Denied) {
			t.Fatalf("CLI %+v vs console %+v", a, *row)
		}
	}
	var sd console.SessionDetail
	status, body, _ = browser.do(http.MethodGet, "/console/v1/sessions/"+consoleSession+"?tenant=default", "", nil)
	if status != http.StatusOK {
		t.Fatalf("session detail: %d %s", status, body)
	}
	mustJSON(t, body, &sd)
	if sd.Detail == nil || sd.Detail.Summary.Requests != 2 {
		t.Fatalf("session summary: %+v", sd.Detail)
	}

	// ---- the browser credential is read-only and console-only -------------
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/v1/secrets"},
		{http.MethodPost, "/v1/agents/run"},
		{http.MethodPost, "/v1/runs/x/approve"},
		{http.MethodPut, "/v1/policies/agent"},
		{http.MethodPost, "/mcp"},
		{http.MethodGet, "/api/v1/metrics"},
		{http.MethodGet, "/v1/evidence"},
	} {
		if status, _, _ := browser.do(p.method, p.path, "{}", map[string]string{"Content-Type": "application/json"}); status != http.StatusNotFound {
			t.Fatalf("%s %s on the console process: %d, expected 404 (no such route exists there)", p.method, p.path, status)
		}
	}
	if status, _, _ := browser.do(http.MethodPost, "/console/v1/overview", "{}", map[string]string{"Content-Type": "application/json"}); status != http.StatusMethodNotAllowed {
		t.Fatalf("write verb on the read API: %d", status)
	}
	dp, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, dpURL+"/api/v1/metrics", nil)
	dp.AddCookie(ck)
	if resp, err := http.DefaultClient.Do(dp); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("console cookie on the data plane must be nothing: %v %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}

	// ---- reissue via talon ui pair: new code, old sessions survive -------
	out, stderr, code = RunTalon(t, dir, nil, "ui", "pair")
	if code != 0 {
		t.Fatalf("ui pair: %d\n%s%s", code, out, stderr)
	}
	if strings.Contains(out, first) {
		t.Fatalf("ui pair must not print the code itself (it goes to the console's log): %s", out)
	}
	codes := ui.waitCodes(t, 2)
	second := codes[1]
	if second == first {
		t.Fatalf("reissue printed the same code")
	}
	time.Sleep(access.DefaultMinAttemptGap + 100*time.Millisecond)
	other := newConsoleClient(t, ui.base)
	if status, body := other.pair(second); status != http.StatusOK {
		t.Fatalf("pair with the reissued code: %d %s", status, body)
	}
	if status, _, _ := browser.do(http.MethodGet, "/console/v1/system", "", nil); status != http.StatusOK {
		t.Fatalf("first session must survive a reissue: %d", status)
	}
	if status, _, _ := browser.do(http.MethodPost, "/console/auth/logout", "{}", map[string]string{"Content-Type": "application/json"}); status != http.StatusOK {
		t.Fatalf("logout: %d", status)
	}
	if status, _, _ := browser.do(http.MethodGet, "/console/v1/system", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", status)
	}

	// ---- restart independence --------------------------------------------
	ui.stop()
	if code := chatThroughGateway(t, dpURL, consoleAgentKey, consoleSession); code != http.StatusOK {
		t.Fatalf("data plane must keep serving while the console is down: %d", code)
	}
	ui2 := startConsoleUI(t, dir, uiPort)
	stale := newConsoleClient(t, ui2.base)
	u, _ := http.NewRequest(http.MethodGet, ui2.base, nil)
	stale.http.Jar.SetCookies(u.URL, []*http.Cookie{{Name: access.CookieName, Value: ck.Value}})
	if status, _, _ := stale.do(http.MethodGet, "/console/v1/system", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("a session from before the restart must be gone: %d", status)
	}
	third := ui2.waitCodes(t, 1)[0]
	fresh := newConsoleClient(t, ui2.base)
	if status, body := fresh.pair(third); status != http.StatusOK {
		t.Fatalf("pair after restart: %d %s", status, body)
	}
	status, body, _ = fresh.do(http.MethodGet, "/console/v1/sessions/"+consoleSession+"?tenant=default", "", nil)
	mustJSON(t, body, &sd)
	if status != http.StatusOK || sd.Detail.Summary.Requests != 3 {
		t.Fatalf("after restart the console reads the third call too: %d %+v", status, sd.Detail.Summary)
	}

	// ---- data plane stopped: the console still reads the store ------------
	stopDP()
	stopDP = func() {}
	status, body, _ = fresh.do(http.MethodGet, "/console/v1/overview?tenant=default", "", nil)
	if status != http.StatusOK {
		t.Fatalf("overview with the data plane stopped: %d %s", status, body)
	}
	mustJSON(t, body, &ov)
	if ov.UseCases.Runtime.Availability.State != console.StateUnknown {
		t.Fatalf("runtime must be unknown, never inferred: %+v", ov.UseCases.Runtime.Availability)
	}
	if strings.Contains(ui2.readLog(), consoleAdminKey) || strings.Contains(ui2.readLog(), consoleAgentKey) {
		t.Fatalf("a key leaked into the console log")
	}
}

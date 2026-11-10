//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/console"
)

// otherSecretsKey is a valid secrets key that is NOT the one the agent key
// was stored with: every stored secret fails to decrypt under it.
const otherSecretsKey = "abcdefghijklmnopqrstuvwxyz123456"

// TestE2E_ConsoleReadiness_UndecryptableAgentKey (#533 PR 1, Case G) is the
// failure met in the People Analytics demo, over real processes: the agent
// key was stored under one TALON_SECRETS_KEY and the data plane starts with
// another. Both `serve --gateway` and `serve --proxy-config` refuse to start
// (a declared key that no longer decrypts is never open access, #557 review
// P0) and nothing reaches the HR backend. Evidence stays readable and there
// is no traffic. The console must not report a healthy installation, in any
// tenant scope, and must name the cause.
func TestE2E_ConsoleReadiness_UndecryptableAgentKey(t *testing.T) {
	up := startHRUpstream(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", paAgent); code != 0 {
		t.Fatalf("init: %d %s", code, stderr)
	}
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := fmt.Sprintf("\ngateway:\n  enabled: true\n  listen_prefix: \"/v1/proxy\"\n  providers:\n    openai:\n      enabled: true\n      secret_name: \"openai-api-key\"\n      base_url: %q\n", up.srv.URL)
	if err := os.WriteFile(cfgPath, append(cfg, []byte(gw)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", paAgent+"-talon-key", paKey); code != 0 {
		t.Fatalf("secrets set: %d %s", code, stderr)
	}
	proxyCfg := filepath.Join(dir, "proxy.talon.yaml")
	if err := os.WriteFile(proxyCfg, []byte(`agent:
  name: hr-mcp-proxy
  type: mcp_proxy
proxy:
  upstream:
    vendor: hr-backend
    url: "`+up.srv.URL+`/mcp"
  allowed_tools:
    - name: hr_aggregate_sql
  forbidden_tools: ["hr_employee_export"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// TALON_ADMIN_KEY is cleared explicitly: CI runs without one, and that
	// is the shape in which a degraded identity registry used to leave the
	// tenant-scoped APIs open (#557 review P0).
	wrongKey := map[string]string{"TALON_SECRETS_KEY": otherSecretsKey, "TALON_ADMIN_KEY": ""}
	rightKey := map[string]string{"TALON_ADMIN_KEY": ""}

	// The installation ran before the secrets key changed (as the demo did):
	// one clean proxy start initialises the stores, then stops.
	dpPort := freePort(t)
	first := startProxyServe(t, dir, dpPort, rightKey)
	_ = first.cmd.Process.Signal(syscall.SIGTERM) // graceful: its record reads stopped
	_, _ = first.cmd.Process.Wait()

	// The gateway cannot start: its agent key does not decrypt.
	_, stderr, code := RunTalon(t, dir, wrongKey, "serve", "--port", fmt.Sprint(freePort(t)), "--gateway", "--gateway-config", cfgPath)
	if code == 0 {
		t.Fatal("serve --gateway started with an undecryptable agent key")
	}
	if !strings.Contains(stderr, "decrypt") {
		t.Fatalf("the gateway's own error should name the decryption failure:\n%s", stderr)
	}
	// Neither can the MCP proxy: a declared agent key that no longer
	// decrypts is a failed configured identity, never open access.
	pcode, pout := runServeExpectExit(t, dir, wrongKey, 30*time.Second, "serve", "--port", fmt.Sprint(dpPort), "--proxy-config", proxyCfg)
	if pcode == 0 || !strings.Contains(pout, "decrypt") {
		t.Fatalf("serve --proxy-config with an undecryptable agent key: exit %d, want a refusal naming decryption:\n%s", pcode, pout)
	}
	// Nothing listens, so neither the formerly correct key nor a wrong key
	// can reach the HR backend.
	for _, key := range []string{paKey, "talon-wrong-key"} {
		if st, ok := tryPACall(fmt.Sprintf("http://127.0.0.1:%d", dpPort), key); ok {
			t.Fatalf("a proxy answered (HTTP %d) after refusing to start", st)
		}
	}
	if up.total() != 0 {
		t.Fatalf("backend calls after the vault-key mismatch: %v", up.calls)
	}

	ui := startConsoleUI(t, dir, freePort(t), "--proxy-config", proxyCfg, "--gateway-config", cfgPath)
	c := newConsoleClient(t, ui.base)
	if status, body := c.pair(ui.waitCodes(t, 1)[0]); status != http.StatusOK {
		t.Fatalf("pair: %d %s", status, body)
	}
	for _, tenant := range []string{"", "default", "tenant-without-traffic"} {
		var ov console.Overview
		consoleGet(t, c, "/console/v1/overview?tenant="+tenant, &ov)
		r := ov.Readiness
		if r.Overall != console.OverallDegraded {
			t.Fatalf("tenant %q: overall %q (%s), want degraded", tenant, r.Overall, r.Summary)
		}
		if r.Scope != console.ScopeInstallation {
			t.Fatalf("tenant %q: readiness scope %q", tenant, r.Scope)
		}
		dims := map[string]console.ReadinessDimension{}
		for _, d := range r.Dimensions {
			dims[d.Key] = d
		}
		for _, k := range []string{console.DimGateway, console.DimMCPProxy} {
			if d := dims[k]; d.State != console.ReadyDegraded || !strings.Contains(d.Reason, "failed to start") || !strings.Contains(d.Reason, "decrypted") {
				t.Fatalf("tenant %q: %s dimension %+v, want degraded: failed to start, key not decryptable", tenant, k, d)
			}
		}
		if d := dims[console.DimAgentKeys]; d.State != console.ReadyDegraded {
			t.Fatalf("tenant %q: agent authentication %+v, want degraded", tenant, d)
		}
		if d := dims[console.DimEvidenceStore]; d.State != console.ReadyOK {
			t.Fatalf("tenant %q: evidence store %+v, want readable", tenant, d)
		}
		got := map[string]bool{}
		for _, f := range ov.Findings {
			got[f.Code] = true
			if f.Severity == "" || f.Title == "" || f.Why == "" || f.Link == "" {
				t.Fatalf("finding without what/why/where: %+v", f)
			}
		}
		for _, want := range []string{"runtime_failed_to_start", "agent_keys_unavailable"} {
			if !got[want] {
				t.Fatalf("tenant %q: findings %v lack %s", tenant, ov.Findings, want)
			}
		}
		if ov.Today.Requests != 0 {
			t.Fatalf("tenant %q: %d requests today; this scenario has no traffic", tenant, ov.Today.Requests)
		}
	}
	// The records the failed processes left carry a fixed cause, not the
	// raw error (which can quote configuration).
	var sys console.System
	consoleGet(t, c, "/console/v1/system", &sys)
	for _, p := range sys.Runtime.Processes {
		if p.StartupFailure != nil && strings.Contains(p.StartupFailure.Reason, paAgent+"-talon-key") {
			t.Fatalf("startup failure record copies error text: %+v", p.StartupFailure)
		}
	}

	// Control: with the secrets key the agent key was stored under (still no
	// admin key), the proxy starts, clears its failure record, authenticates
	// the right key and refuses a wrong one. The refusal above was the key
	// mismatch, not a broken fixture.
	startProxyServe(t, dir, dpPort, rightKey)
	waitRole(t, c, "mcp_proxy", "running", 20*time.Second)
	base := fmt.Sprintf("http://127.0.0.1:%d", dpPort)
	if st, out := paCall(t, base, "talon-wrong-key", "hr_aggregate_sql", paValidSQL, "corr-ready-wrong"); st != http.StatusUnauthorized || up.total() != 0 {
		t.Fatalf("wrong key: HTTP %d %v, backend calls %d; want 401 and 0", st, out, up.total())
	}
	if st, out := paCall(t, base, paKey, "hr_aggregate_sql", paValidSQL, "corr-ready-right"); st != http.StatusOK || up.total() != 1 {
		t.Fatalf("right key with the right secrets key: HTTP %d %v, backend calls %d; want 200 and 1", st, out, up.total())
	}
}

// runServeExpectExit runs a serve command that must refuse to start. A
// process still running at the deadline is killed and reported as started
// (exit code 0).
func runServeExpectExit(t *testing.T, dir string, env map[string]string, within time.Duration, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TALON_DATA_DIR="+dir, "TALON_SECRETS_KEY="+testSecretsKey, "TALON_SIGNING_KEY="+testSigningKey)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return 0, string(out) + "\n(still running at the deadline)"
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// tryPACall reports whether anything answered an MCP tool call at base.
func tryPACall(base, key string) (int, bool) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hr_aggregate_sql","arguments":{"sql":"SELECT 1"}}}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/mcp/proxy", strings.NewReader(body))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return 0, false
	}
	_ = resp.Body.Close()
	return resp.StatusCode, true
}

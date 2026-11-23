//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
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

// dataPlane is a running `talon serve` process.
type dataPlane struct {
	cmd *exec.Cmd
	log string
}

// startDataPlane starts a native `talon serve`: the governed MCP endpoint
// and the Action Gateway, no LLM gateway.
func startDataPlane(t *testing.T, dir string, port int, env map[string]string) *dataPlane {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), binaryPath, "serve", "--port", fmt.Sprint(port))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TALON_DATA_DIR="+dir, "TALON_SECRETS_KEY="+testSecretsKey, "TALON_SIGNING_KEY="+testSigningKey, "TALON_AGENTS_RELOAD_INTERVAL=1s", "TALON_LOG_FORMAT=json")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	logPath := filepath.Join(dir, fmt.Sprintf("serve-%d-%d.log", port, time.Now().UnixNano()))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{cmd: cmd, log: logPath}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait(); _ = f.Close() })
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/health", port), nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return dp
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("talon serve not healthy:\n%s", b)
	return nil
}

func (c *consoleClient) system(t *testing.T) console.System {
	t.Helper()
	status, body, _ := c.do(http.MethodGet, "/console/v1/system", "", nil)
	if status != http.StatusOK {
		t.Fatalf("system: %d %s", status, body)
	}
	var s console.System
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func roleState(s console.System, role string) (string, string) {
	for _, r := range s.Runtime.Roles {
		if r.Role == role {
			return r.State, r.InstanceID
		}
	}
	return "", ""
}

func waitRole(t *testing.T, c *consoleClient, role, want string, within time.Duration) console.System {
	t.Helper()
	deadline := time.Now().Add(within)
	var s console.System
	for time.Now().Before(deadline) {
		s = c.system(t)
		if st, _ := roleState(s, role); st == want {
			return s
		}
		time.Sleep(500 * time.Millisecond)
	}
	b, _ := json.MarshalIndent(s.Runtime, "", "  ")
	t.Fatalf("role %s did not become %s within %s; runtime:\n%s", role, want, within, b)
	return s
}

// TestE2E_ConsoleRuntime_ProcessTruth (#538) runs the production binary: a
// real `talon serve` (governed MCP endpoint, no LLM gateway) publishes its
// runtime record and the separate console reports it. Negative paths: the
// optional gateway is absent; a failed reload keeps the last-known-good
// generation and is shown as rejected; a SIGKILLed serve goes stale (no fake
// running); a restart is a
// new instance while history stays; a process of another installation (other
// signing key, same directory) is rejected; an unreadable store is reported
// as unavailable while runtime facts stay readable.
func TestE2E_ConsoleRuntime_ProcessTruth(t *testing.T) {
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", consoleAgent); code != 0 {
		t.Fatalf("init: %d %s", code, stderr)
	}

	dpPort := freePort(t)
	dp := startDataPlane(t, dir, dpPort, nil)
	uiPort := freePort(t)
	ui := startConsoleUI(t, dir, uiPort)
	c := newConsoleClient(t, ui.base)
	if status, body := c.pair(ui.waitCodes(t, 1)[0]); status != http.StatusOK {
		t.Fatalf("pair: %d %s", status, body)
	}

	// Running MCP endpoint, absent optional gateway.
	s := waitRole(t, c, "mcp", "running", 15*time.Second)
	if st, _ := roleState(s, "gateway"); st != "not_configured" {
		t.Fatalf("gateway: %q, expected not_configured (optional and absent)", st)
	}
	if s.Runtime.ActiveGeneration == "" {
		t.Fatalf("the running serve must report its active generation: %+v", s.Runtime)
	}
	_, firstInstance := roleState(s, "mcp")
	gen := s.Runtime.ActiveGeneration

	// Configuration: the current agent file is what the process loaded.
	var cfg console.Configuration
	status, body, _ := c.do(http.MethodGet, "/console/v1/configuration", "", nil)
	if status != http.StatusOK {
		t.Fatalf("configuration: %d", status)
	}
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.UseCases.Items) == 0 || cfg.UseCases.Items[0].Active.State != "loaded_matches_file" {
		t.Fatalf("use case active state: %+v", cfg.UseCases.Items)
	}
	if len(cfg.Active) == 0 || cfg.Active[0].AgentFilesMatch == nil || !*cfg.Active[0].AgentFilesMatch {
		t.Fatalf("the agent files must match what the process loaded: %+v", cfg.Active)
	}

	// Failed reload: break the agent file. Last-known-good keeps serving and
	// the record says the reload was rejected.
	agentFile := filepath.Join(dir, "agent.talon.yaml")
	good, _ := os.ReadFile(agentFile)
	if err := os.WriteFile(agentFile, []byte("agent: [this is not valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var rejected bool
	for time.Now().Before(deadline) && !rejected {
		s = c.system(t)
		for _, p := range s.Runtime.Processes {
			if p.Current && p.Catalog != nil && p.Catalog.ReloadRejected {
				rejected = true
				if p.Catalog.ActiveGeneration != gen {
					t.Fatalf("a rejected reload must keep the last-known-good generation %s, got %s", gen, p.Catalog.ActiveGeneration)
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !rejected {
		b, _ := os.ReadFile(dp.log)
		t.Fatalf("the failed reload never appeared as rejected; serve log:\n%s", b)
	}
	status, body, _ = c.do(http.MethodGet, "/console/v1/configuration", "", nil)
	_ = json.Unmarshal([]byte(body), &cfg)
	if status != http.StatusOK || len(cfg.Active) == 0 || !cfg.Active[0].ReloadRejected || cfg.Active[0].AgentFilesMatch == nil || *cfg.Active[0].AgentFilesMatch {
		t.Fatalf("configuration must show the rejected reload and that the files differ from the active generation: %+v", cfg.Active)
	}

	// #593: the real serve signed that rejection as an installation event,
	// under the reserved namespace. It is listed on System, verifies in the
	// console and with the CLI, and makes no tenant: the selector lists only
	// the use case's tenant.
	var reload console.InstallationEvent
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && reload.EvidenceID == "" {
		for _, e := range c.system(t).InstallationActivity.Events {
			if e.InvocationType == "config_reload" && !e.Allowed {
				reload = e
			}
		}
		if reload.EvidenceID == "" {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if reload.EvidenceID == "" || reload.RecordedBy != "talon-serve" || len(reload.Reasons) == 0 {
		t.Fatalf("the rejected reload must be listed as installation activity with its causes: %+v", c.system(t).InstallationActivity)
	}
	tenantsNow := func() console.Tenants {
		var ts console.Tenants
		if status, body, _ := c.do(http.MethodGet, "/console/v1/tenants", "", nil); status != http.StatusOK {
			t.Fatalf("tenants: %d %s", status, body)
		} else {
			mustJSON(t, body, &ts)
		}
		return ts
	}
	// The only agent file is broken: no valid use case, and the installation
	// event alone makes no tenant.
	if ts := tenantsNow(); len(ts.Tenants) != 0 || ts.Installation.TenantID != "system" {
		t.Fatalf("with no valid use case the selector must be empty, never list the installation namespace: %+v", ts)
	}
	var ev console.EvidenceDetail
	if status, body, _ = c.do(http.MethodGet, "/console/v1/evidence/"+reload.EvidenceID, "", nil); status != http.StatusOK {
		t.Fatalf("evidence %s: %d %s", reload.EvidenceID, status, body)
	}
	mustJSON(t, body, &ev)
	if ev.Detail == nil || !ev.Detail.InstallationEvent || ev.Detail.Verification.State != "valid" {
		t.Fatalf("the reload record must open as a verified installation event: %s", body)
	}
	if out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", reload.EvidenceID); code != 0 {
		t.Fatalf("talon audit verify %s: %d\n%s\n%s", reload.EvidenceID, code, out, stderr)
	}
	_ = os.WriteFile(agentFile, good, 0o600)
	if ts := tenantsNow(); len(ts.Tenants) != 1 || ts.Tenants[0].TenantID != "default" || ts.Tenants[0].UseCases != 1 {
		t.Fatalf("one use case: the selector lists only its tenant: %+v", ts.Tenants)
	}

	// Another installation (different signing key) in the same directory is
	// never combined.
	foreignPort := freePort(t)
	foreign := startDataPlane(t, dir, foreignPort, map[string]string{"TALON_SIGNING_KEY": "another-installation-signing-key-0000000000"})
	deadline = time.Now().Add(15 * time.Second)
	sawRejected := false
	for time.Now().Before(deadline) && !sawRejected {
		s = c.system(t)
		for _, r := range s.Runtime.Rejected {
			if strings.Contains(r.Reason, "different installation") {
				sawRejected = true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !sawRejected {
		t.Fatalf("a process with another signing key must be rejected: %+v", s.Runtime.Rejected)
	}
	if _, inst := roleState(s, "mcp"); inst != firstInstance {
		t.Fatalf("the foreign process must not become this installation's MCP endpoint: %s vs %s", inst, firstInstance)
	}
	_ = foreign.cmd.Process.Signal(syscall.SIGTERM)
	_, _ = foreign.cmd.Process.Wait()

	// SIGKILL: no shutdown record; the serve becomes stale, never "running".
	_ = dp.cmd.Process.Kill()
	_, _ = dp.cmd.Process.Wait()
	waitRole(t, c, "mcp", "stale", 30*time.Second)

	// Restart: a new instance runs; the killed one stays as history.
	startDataPlane(t, dir, dpPort, nil)
	s = waitRole(t, c, "mcp", "running", 15*time.Second)
	if _, inst := roleState(s, "mcp"); inst == firstInstance {
		t.Fatalf("the restarted serve must be a new instance")
	}
	history := 0
	for _, p := range s.Runtime.Processes {
		if p.InstanceID == firstInstance && !p.Current {
			history++
		}
	}
	if history != 1 {
		t.Fatalf("the killed instance must remain visible as history: %+v", s.Runtime.Processes)
	}

	// Unreadable store: a console started against it fails closed (nothing
	// listens) and names the store; the running console's runtime view is
	// unaffected. (An already-open read-only handle keeps reading the file,
	// so the failure shows at open, which is when it can happen.)
	db := filepath.Join(dir, "evidence.db")
	if os.Geteuid() != 0 {
		if err := os.Chmod(db, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(db, 0o600) //nolint:errcheck // restore for cleanup
		port2 := freePort(t)
		out, stderr, code := RunTalon(t, dir, nil, "ui", "serve", "--listen", fmt.Sprintf("127.0.0.1:%d", port2), "--store-wait", "1s")
		if code == 0 || !strings.Contains(out+stderr, "evidence store") {
			t.Fatalf("a console over an unreadable store must refuse to start naming the store; code=%d\n%s%s", code, out, stderr)
		}
		if st, _ := roleState(c.system(t), "mcp"); st != "running" {
			t.Fatalf("runtime facts do not depend on the store: %q", st)
		}
	}
}

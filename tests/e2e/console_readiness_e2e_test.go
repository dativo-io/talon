package e2e

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
// another. `serve --gateway` refuses to start; `serve --proxy-config` starts
// and heartbeats, but without the use case's key. Evidence stays readable
// and there is no traffic. The console must not report a healthy
// installation, in any tenant scope, and must name both causes.
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
	wrongKey := map[string]string{"TALON_SECRETS_KEY": otherSecretsKey}

	// The gateway cannot start: its agent key does not decrypt.
	_, stderr, code := RunTalon(t, dir, wrongKey, "serve", "--port", fmt.Sprint(freePort(t)), "--gateway", "--gateway-config", cfgPath)
	if code == 0 {
		t.Fatal("serve --gateway started with an undecryptable agent key")
	}
	if !strings.Contains(stderr, "decrypt") {
		t.Fatalf("the gateway's own error should name the decryption failure:\n%s", stderr)
	}
	// The MCP proxy starts and heartbeats without the key.
	dpPort := freePort(t)
	startProxyServe(t, dir, dpPort, wrongKey)
	ui := startConsoleUI(t, dir, freePort(t), "--proxy-config", proxyCfg, "--gateway-config", cfgPath)
	c := newConsoleClient(t, ui.base)
	if status, body := c.pair(ui.waitCodes(t, 1)[0]); status != http.StatusOK {
		t.Fatalf("pair: %d %s", status, body)
	}
	waitRole(t, c, "mcp_proxy", "running", 20*time.Second)

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
		if d := dims[console.DimGateway]; d.State != console.ReadyDegraded || !strings.Contains(d.Reason, "failed to start") || !strings.Contains(d.Reason, "decrypted") {
			t.Fatalf("tenant %q: gateway dimension %+v, want degraded: failed to start, key not decryptable", tenant, d)
		}
		if d := dims[console.DimMCPProxy]; d.State != console.ReadyOK {
			t.Fatalf("tenant %q: MCP proxy dimension %+v, want ok (its heartbeat is fresh)", tenant, d)
		}
		if d := dims[console.DimAgentKeys]; d.State != console.ReadyDegraded {
			t.Fatalf("tenant %q: agent authentication %+v, want degraded despite the fresh heartbeat", tenant, d)
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
	// The record the failed gateway left carries a fixed cause, not the
	// raw error (which can quote configuration).
	var sys console.System
	consoleGet(t, c, "/console/v1/system", &sys)
	for _, p := range sys.Runtime.Processes {
		if p.StartupFailure != nil && strings.Contains(p.StartupFailure.Reason, paAgent+"-talon-key") {
			t.Fatalf("startup failure record copies error text: %+v", p.StartupFailure)
		}
	}
	// Nothing in the scenario reached the HR backend.
	if up.total() != 0 {
		t.Fatalf("backend calls: %v", up.calls)
	}
	// The degraded verdict is the truth: a client holding the RIGHT key is
	// refused by the heartbeating proxy, and nothing reaches the backend.
	st, out := paCall(t, fmt.Sprintf("http://127.0.0.1:%d", dpPort), paKey, "hr_aggregate_sql", paValidSQL, "corr-ready-1")
	if st != http.StatusUnauthorized || up.total() != 0 {
		t.Fatalf("right key against a proxy without it: HTTP %d %v, backend calls %d; want 401 and 0", st, out, up.total())
	}
}

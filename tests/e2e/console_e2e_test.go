//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/console/httpapi"
	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/session"
)

const (
	consoleAgent    = "hr-analytics-assistant"
	consoleAgentKey = "talon-gw-e2e-console-0001"
	consoleAdminKey = "admin-e2e-console-key-0001"
	consoleSession  = "hr-demo-e2e"
)

// startConsoleServe runs the built binary as `serve --gateway` with env.
func startConsoleServe(t *testing.T, dir string, port int, env map[string]string) func() {
	t.Helper()
	cmd := exec.Command(binaryPath, "serve", "--port", fmt.Sprintf("%d", port), "--gateway", "--gateway-config", filepath.Join(dir, "talon.config.yaml"))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TALON_DATA_DIR="+dir, "TALON_SECRETS_KEY="+testSecretsKey, "TALON_SIGNING_KEY="+testSigningKey)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "serve.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open serve log: %v", err)
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
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return stop
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	stop()
	log, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	t.Fatalf("serve not healthy; log:\n%s", log)
	return nil
}

func chatThroughGateway(t *testing.T, baseURL, key, sessionID string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/proxy/openai/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"headcount by department"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	if sessionID != "" {
		req.Header.Set("X-Talon-Session-ID", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func mustJSON(t *testing.T, raw string, out interface{}) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
}

// TestE2E_Console_ReadModelMatchesCLIOnLiveStore (#535): the console read
// model, opened read-only on the store a running `talon serve --gateway`
// writes, shows the same facts as the CLI's structured output — during
// traffic, across a restart of the data-plane process, and after it stops.
// The CLI's remote-error semantics are asserted on the real binary too.
func TestE2E_Console_ReadModelMatchesCLIOnLiveStore(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl_e2e","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`))
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
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "openai-api-key", "sk-fake-e2e-provider-key"); code != 0 {
		t.Fatalf("secrets set provider key: %d\n%s", code, stderr)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", consoleAgent+"-talon-key", consoleAgentKey); code != 0 {
		t.Fatalf("secrets set agent key: %d\n%s", code, stderr)
	}

	port := freePort(t)
	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	serveEnv := map[string]string{"TALON_ADMIN_KEY": consoleAdminKey}
	stop := startConsoleServe(t, dir, port, serveEnv)
	defer func() { stop() }()

	// Real traffic: two governed model calls in one asserted session, one
	// request with an unknown key (refused before the provider).
	for i := 0; i < 2; i++ {
		if code := chatThroughGateway(t, serverURL, consoleAgentKey, consoleSession); code != http.StatusOK {
			t.Fatalf("governed chat %d: HTTP %d", i, code)
		}
	}
	if code := chatThroughGateway(t, serverURL, "talon-gw-unknown-key", consoleSession); code != http.StatusUnauthorized {
		t.Fatalf("unknown key: expected 401, got %d", code)
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream received %d calls, expected exactly 2 (the unknown key never reached it)", got)
	}

	adminEnv := map[string]string{"TALON_ADMIN_KEY": consoleAdminKey}

	// ---- CLI readings (structured) -------------------------------------
	var agentsOut struct {
		Offline bool             `json:"offline"`
		Agents  []fleet.AgentRow `json:"agents"`
	}
	out, stderr, code := RunTalon(t, dir, adminEnv, "agents", "--json", "--url", serverURL)
	if code != 0 {
		t.Fatalf("agents --json: %d\n%s", code, stderr)
	}
	mustJSON(t, out, &agentsOut)
	if agentsOut.Offline {
		t.Fatalf("agents should have read the running server, got offline view")
	}
	var cliRow *fleet.AgentRow
	for i := range agentsOut.Agents {
		if agentsOut.Agents[i].Name == consoleAgent {
			cliRow = &agentsOut.Agents[i]
		}
	}
	if cliRow == nil {
		t.Fatalf("agent %s missing from CLI fleet: %s", consoleAgent, out)
	}
	if cliRow.Requests != 2 || cliRow.Denied != 0 {
		t.Fatalf("CLI fleet counters: requests=%d denied=%d, expected 2/0 (hand count)", cliRow.Requests, cliRow.Denied)
	}
	if cliRow.SpendDay <= 0 {
		t.Fatalf("CLI spend_day should be positive for two priced gpt-4o-mini calls, got %v", cliRow.SpendDay)
	}

	var cliCosts costs.Report
	out, stderr, code = RunTalon(t, dir, adminEnv, "costs", "--json", "--tenant", "default", "--agent", consoleAgent, "--url", serverURL)
	if code != 0 {
		t.Fatalf("costs --json: %d\n%s", code, stderr)
	}
	mustJSON(t, out, &cliCosts)
	if cliCosts.DailyBudget == nil || !strings.HasPrefix(cliCosts.DailyBudget.Source, "server_") {
		t.Fatalf("costs should take the running server's caps (server_*), got %+v", cliCosts.DailyBudget)
	}

	var cliSession session.Detail
	out, stderr, code = RunTalon(t, dir, adminEnv, "session", "show", consoleSession, "--json")
	if code != 0 {
		t.Fatalf("session show: %d\n%s", code, stderr)
	}
	mustJSON(t, out, &cliSession)
	if cliSession.Summary.Requests != 2 || cliSession.Summary.Allowed != 2 {
		t.Fatalf("session summary: %+v", cliSession.Summary)
	}

	var cliTimeline session.Timeline
	out, stderr, code = RunTalon(t, dir, adminEnv, "audit", "list", "--json", "--session", consoleSession)
	if code != 0 {
		t.Fatalf("audit list --session --json: %d\n%s", code, stderr)
	}
	mustJSON(t, out, &cliTimeline)
	if len(cliTimeline.Records) != 2 {
		t.Fatalf("timeline records: %d, expected 2", len(cliTimeline.Records))
	}

	// metrics: the real server requires the admin key; without it the CLI
	// fails loudly instead of showing local numbers.
	_, stderr, code = RunTalon(t, dir, map[string]string{"TALON_ADMIN_KEY": ""}, "metrics", "--json", "--url", serverURL)
	if code == 0 || !strings.Contains(stderr, "TALON_ADMIN_KEY") {
		t.Fatalf("metrics without the admin key must fail naming TALON_ADMIN_KEY; code=%d stderr=%s", code, stderr)
	}
	out, stderr, code = RunTalon(t, dir, adminEnv, "metrics", "--json", "--url", serverURL)
	if code != 0 || !strings.Contains(out, consoleAgent) {
		t.Fatalf("metrics with the admin key: code=%d\n%s\n%s", code, out, stderr)
	}

	// ---- Console reading over the live store (read-only) ---------------
	ro, err := evidence.OpenReadOnly(filepath.Join(dir, "evidence.db"), testSigningKey)
	if err != nil {
		t.Fatalf("open evidence read-only: %v", err)
	}
	defer ro.Close()
	ss, err := session.OpenReadOnly(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatalf("open sessions read-only: %v", err)
	}
	defer ss.Close()
	fleetSrc := console.OfflineFleetSource("", filepath.Join(dir, "agent.talon.yaml"), cfgPath, cliCosts.Currency, ro, ss, nil)
	svc := console.New(console.Config{Evidence: ro, Sessions: ss, StorePath: filepath.Join(dir, "evidence.db"), Currency: cliCosts.Currency, Fleet: fleetSrc, Budgets: console.FleetCapsBudgets{Fleet: fleetSrc}, Version: "e2e"})
	api := httptest.NewServer(httpapi.Handler(svc))
	defer api.Close()

	getDTO := func(path string, out interface{}) {
		t.Helper()
		resp, err := http.Get(api.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: HTTP %d", path, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}

	var ov console.Overview
	getDTO("/console/v1/overview", &ov)
	if ov.UseCases.Availability.State != console.StateOK {
		t.Fatalf("use cases availability: %+v", ov.UseCases.Availability)
	}
	var dtoRow *fleet.AgentRow
	for i := range ov.UseCases.Rows {
		if ov.UseCases.Rows[i].Name == consoleAgent {
			dtoRow = &ov.UseCases.Rows[i]
		}
	}
	if dtoRow == nil {
		t.Fatalf("agent missing from console rows")
	}
	if dtoRow.Requests != cliRow.Requests || dtoRow.Denied != cliRow.Denied || dtoRow.Health != cliRow.Health || dtoRow.State != cliRow.State {
		t.Fatalf("console row %+v != CLI row %+v", dtoRow, cliRow)
	}
	if diff := dtoRow.SpendDay - cliRow.SpendDay; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("spend_day console=%v cli=%v", dtoRow.SpendDay, cliRow.SpendDay)
	}
	if ov.UseCases.Runtime.Availability.State != console.StateUnknown {
		t.Fatalf("runtime must be unknown without a probe, got %+v", ov.UseCases.Runtime.Availability)
	}
	if ov.Today.Requests != 2 || ov.Today.Denied != 0 {
		t.Fatalf("today: %+v", ov.Today)
	}
	if diff := ov.Today.Cost - cliCosts.TodayEUR; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("today cost console=%v cli=%v", ov.Today.Cost, cliCosts.TodayEUR)
	}

	var dtoCosts console.Costs
	getDTO("/console/v1/costs?tenant=default&agent="+consoleAgent, &dtoCosts)
	if dtoCosts.Report == nil || dtoCosts.Report.DailyBudget == nil {
		t.Fatalf("console costs: %+v", dtoCosts)
	}
	if diff := dtoCosts.Report.TodayEUR - cliCosts.TodayEUR; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("costs today console=%v cli=%v", dtoCosts.Report.TodayEUR, cliCosts.TodayEUR)
	}
	if dtoCosts.Report.DailyBudget.LimitEUR != cliCosts.DailyBudget.LimitEUR {
		t.Fatalf("daily cap console=%v (%s) cli=%v (%s): same agent, same resolver", dtoCosts.Report.DailyBudget.LimitEUR, dtoCosts.Report.DailyBudget.Source, cliCosts.DailyBudget.LimitEUR, cliCosts.DailyBudget.Source)
	}

	var dtoSession console.SessionDetail
	getDTO("/console/v1/sessions/"+consoleSession, &dtoSession)
	if dtoSession.Detail == nil || dtoSession.Timeline == nil {
		t.Fatalf("console session: %+v", dtoSession)
	}
	if dtoSession.Detail.Summary.Requests != cliSession.Summary.Requests || dtoSession.Detail.Summary.TotalCost != cliSession.Summary.TotalCost {
		t.Fatalf("session summary console=%+v cli=%+v", dtoSession.Detail.Summary, cliSession.Summary)
	}
	if len(dtoSession.Timeline.Records) != len(cliTimeline.Records) || dtoSession.Timeline.Records[0].ID != cliTimeline.Records[0].ID {
		t.Fatalf("timeline console=%+v cli=%+v", dtoSession.Timeline.Records, cliTimeline.Records)
	}
	var dtoEvidence console.EvidenceDetail
	getDTO("/console/v1/evidence/"+cliTimeline.Records[0].ID+"?tenant=default", &dtoEvidence)
	if dtoEvidence.Detail.Verification.State != "valid" {
		t.Fatalf("live record should verify: %+v", dtoEvidence.Detail.Verification)
	}

	// ---- Restart the data plane: facts persist, new traffic shows up ----
	stop()
	stop = startConsoleServe(t, dir, port, serveEnv)
	if code := chatThroughGateway(t, serverURL, consoleAgentKey, consoleSession); code != http.StatusOK {
		t.Fatalf("post-restart chat: HTTP %d", code)
	}
	out, stderr, code = RunTalon(t, dir, adminEnv, "agents", "--json", "--url", serverURL)
	if code != 0 {
		t.Fatalf("agents after restart: %d\n%s", code, stderr)
	}
	mustJSON(t, out, &agentsOut)
	getDTO("/console/v1/overview", &ov)
	var afterCLI, afterDTO int
	for _, r := range agentsOut.Agents {
		if r.Name == consoleAgent {
			afterCLI = r.Requests
		}
	}
	for _, r := range ov.UseCases.Rows {
		if r.Name == consoleAgent {
			afterDTO = r.Requests
		}
	}
	if afterCLI != 3 || afterDTO != 3 {
		t.Fatalf("after restart requests: cli=%d console=%d, expected 3 (2 persisted + 1 new)", afterCLI, afterDTO)
	}

	// ---- Stop the data plane: the CLI says so, the console keeps the store ----
	stop()
	stop = func() {}
	_, stderr, code = RunTalon(t, dir, adminEnv, "metrics", "--json", "--url", serverURL)
	if code == 0 || !strings.Contains(stderr, "refusing the offline fallback") {
		t.Fatalf("metrics against a stopped explicit server must fail without a silent local fallback; code=%d stderr=%s", code, stderr)
	}
	getDTO("/console/v1/overview", &ov)
	if ov.UseCases.Availability.State != console.StateOK || ov.Today.Requests != 3 {
		t.Fatalf("console after data plane stopped: %+v / %+v", ov.UseCases.Availability, ov.Today)
	}
	var sys console.System
	getDTO("/console/v1/system", &sys)
	if !sys.Store.ReadOnly || sys.Store.RecordCount < 3 || sys.Runtime.Availability.State != console.StateUnknown {
		t.Fatalf("system: %+v", sys)
	}
}

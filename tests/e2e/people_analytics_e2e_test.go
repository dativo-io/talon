//go:build e2e

package e2e

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/session"
)

// hrUpstream is the People Analytics HR backend as a separate MCP server.
// Its counters are the boundary proof: they count tools/call requests that
// reached the backend, independently of anything Talon records.
// hr_aggregate_sql runs only aggregate queries (a SELECT with GROUP BY): any
// other SQL is rejected by the backend's own validation, after Talon allowed
// and dispatched the call. rejected counts those backend rejections.
type hrUpstream struct {
	srv      *httptest.Server
	mu       sync.Mutex
	calls    map[string]int
	rejected int
}

// validAggregate is the backend's own query-shape rule, not Talon's.
func validAggregate(sql string) bool {
	q := strings.ToUpper(strings.TrimSpace(sql))
	return strings.HasPrefix(q, "SELECT ") && strings.Contains(q, " GROUP BY ")
}

func startHRUpstream(t *testing.T) *hrUpstream {
	t.Helper()
	u := &hrUpstream{calls: map[string]int{}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string `json:"name"`
				Arguments struct {
					SQL string `json:"sql"`
				} `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[{"name":"hr_aggregate_sql","inputSchema":{"type":"object"}},{"name":"hr_employee_export","inputSchema":{"type":"object"}}],"ttlMs":30000,"cacheScope":"public"}}`, req.ID)
		case "tools/call":
			u.mu.Lock()
			u.calls[req.Params.Name]++
			invalid := req.Params.Name == "hr_aggregate_sql" && !validAggregate(req.Params.Arguments.SQL)
			if invalid {
				u.rejected++
			}
			u.mu.Unlock()
			if invalid {
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"HR backend: invalid SQL or query shape (aggregate SELECT ... GROUP BY only)"}}`, req.ID)
				return
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":"department,headcount\nEngineering,42\nSales,17"}]}}`, req.ID)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"unknown"}}`, req.ID)
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *hrUpstream) count(tool string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls[tool]
}

func (u *hrUpstream) rejections() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.rejected
}

func (u *hrUpstream) total() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, c := range u.calls {
		n += c
	}
	return n
}

const (
	paAgent   = "hr-analytics-assistant"
	paKey     = "talon-pa-e2e-agent-key-0001"
	paSession = "pa-live-session-1"
)

// People Analytics queries: an aggregate the backend runs, and one it
// rejects as an invalid query shape (individual rows, no GROUP BY).
const (
	paValidSQL   = "SELECT department, COUNT(*) AS headcount FROM employees GROUP BY department"
	paInvalidSQL = "SELECT name, salary FROM employees WHERE department = 'Sales'"
)

// paCall sends one tools/call through the MCP proxy in the People Analytics
// session, with a correlation id the test chose.
func paCall(t *testing.T, base, key, tool, sql, corr string) (int, map[string]any) {
	t.Helper()
	c := &mcpClient{t: t, base: base, key: key}
	args, _ := json.Marshal(map[string]string{"sql": sql})
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{` + mcpMeta + `,"name":"` + tool + `","arguments":` + string(args) + `}}`
	st, _, out := c.post("/mcp/proxy", "tools/call", tool, body, map[string]string{"X-Talon-Session-ID": paSession, "X-Correlation-ID": corr})
	return st, out
}

func consoleGet(t *testing.T, c *consoleClient, path string, out any) {
	t.Helper()
	status, body, _ := c.do(http.MethodGet, path, "", nil)
	if status != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, status, body)
	}
	if err := json.Unmarshal([]byte(body), out); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
}

func talonJSON(t *testing.T, dir string, out any, args ...string) {
	t.Helper()
	stdout, stderr, code := RunTalon(t, dir, nil, args...)
	if code != 0 {
		t.Fatalf("talon %s: exit %d\n%s", strings.Join(args, " "), code, stderr)
	}
	if err := json.Unmarshal([]byte(stdout), out); err != nil {
		t.Fatalf("talon %s: %v\n%s", strings.Join(args, " "), err, stdout)
	}
}

// TestE2E_PeopleAnalytics_CrossProcess (#545) is the People Analytics
// acceptance run over real processes: a separate HR MCP backend with its own
// call counters, the production `talon serve --proxy-config` and the
// production `talon ui serve`, all on loopback. No provider key is used and
// no LLM call is made: the proof is the MCP boundary.
//
// It proves, in order: unauthenticated console reads and a wrong workload key
// reach nothing; a valid hr_aggregate_sql query is dispatched (backend
// counter +1) and recorded as completed; hr_employee_export is denied before
// dispatch (its backend counter stays 0); an hr_aggregate_sql query with
// invalid SQL is allowed by Talon, reaches the backend (counter +1) and is
// rejected by the backend's own validation, shown as dispatched and rejected
// by the destination, not as a Talon denial; the MCP decisions are proven
// active by the running proxy while the gateway policy is not (no gateway
// runs); the last decision's signature is verified;
// session and correlation ids are the ones the client asserted; every record
// verifies; the console's session, evidence, search, effective-policy and
// runtime answers equal the CLI's; spend stays zero; a SIGKILLed data plane
// goes stale, nothing more reaches the backend, the evidence stays
// readable, and a restart is a new instance that serves the same session; a
// record changed in the database after signing reads as invalid in the
// console and fails `talon audit verify`.
//
// With TALON_PA_BROWSER=1 the Playwright spec tests/browser/live runs
// against this installation while the data plane is up (CLI = API = browser).
func TestE2E_PeopleAnalytics_CrossProcess(t *testing.T) {
	up := startHRUpstream(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", paAgent); code != 0 {
		t.Fatalf("init: %d %s", code, stderr)
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
	dbPath := filepath.Join(dir, "evidence.db")

	dpPort := freePort(t)
	dp := startProxyServe(t, dir, dpPort, nil)
	base := fmt.Sprintf("http://127.0.0.1:%d", dpPort)
	ui := startConsoleUI(t, dir, freePort(t), "--proxy-config", proxyCfg)

	// --- Negative auth: no console session, wrong workload key.
	anon := newConsoleClient(t, ui.base)
	for _, p := range []string{"/console/v1/overview", "/console/v1/sessions/" + paSession, "/console/v1/use-cases/" + paAgent + "/effective-policy"} {
		if status, _, _ := anon.do(http.MethodGet, p, "", nil); status != http.StatusUnauthorized {
			t.Fatalf("unpaired GET %s: %d, want 401", p, status)
		}
	}
	if st, _ := paCall(t, base, "talon-not-a-real-key-0000", "hr_aggregate_sql", paValidSQL, "corr-pa-badkey"); st < 400 {
		t.Fatalf("wrong workload key: HTTP %d, want a 4xx", st)
	}
	if up.total() != 0 {
		t.Fatalf("a request with a wrong key reached the HR backend: %v", up.calls)
	}

	c := newConsoleClient(t, ui.base)
	if status, body := c.pair(ui.waitCodes(t, 1)[0]); status != http.StatusOK {
		t.Fatalf("pair: %d %s", status, body)
	}

	// --- Traffic in one asserted session: a valid aggregate, the forbidden
	// export, and an aggregate the HR backend rejects as invalid SQL.
	st, out := paCall(t, base, paKey, "hr_aggregate_sql", paValidSQL, "corr-pa-allowed")
	if st != http.StatusOK || out["result"] == nil {
		t.Fatalf("allowed call: %d %v", st, out)
	}
	if n := up.count("hr_aggregate_sql"); n != 1 {
		t.Fatalf("allowed call: backend saw %d calls, want 1", n)
	}
	_, out = paCall(t, base, paKey, "hr_employee_export", "", "corr-pa-forbidden")
	if out["error"] == nil {
		t.Fatalf("forbidden call must be an error: %v", out)
	}
	if n := up.count("hr_employee_export"); n != 0 {
		t.Fatalf("forbidden call reached the HR backend %d times", n)
	}
	_, out = paCall(t, base, paKey, "hr_aggregate_sql", paInvalidSQL, "corr-pa-invalid-sql")
	if out["error"] == nil {
		t.Fatalf("an invalid query must surface the backend's error: %v", out)
	}
	if n, rej := up.count("hr_aggregate_sql"), up.rejections(); n != 2 || rej != 1 {
		t.Fatalf("invalid query: backend saw %d aggregate calls and rejected %d, want 2 and 1 (Talon allowed and dispatched it; the backend refused it)", n, rej)
	}

	// --- Console session = CLI session, with three distinct outcomes.
	var sd console.SessionDetail
	consoleGet(t, c, "/console/v1/sessions/"+paSession+"?agent="+paAgent, &sd)
	if sd.Timeline == nil || sd.Detail == nil {
		t.Fatalf("session detail: %+v", sd.Availability)
	}
	// Keyed by the client's correlation id: two records share a tool.
	byCorr := map[string]evidence.Index{}
	for _, r := range sd.Timeline.Records {
		if r.SessionID != paSession || r.AgentID != paAgent {
			t.Fatalf("record %s: session %q agent %q, want the asserted session and the key's use case", r.ID, r.SessionID, r.AgentID)
		}
		if r.Outcome == nil {
			t.Fatalf("record %s has no outcome", r.ID)
		}
		byCorr[r.CorrelationID] = r
	}
	want := map[string]struct {
		tool    string
		outcome [3]string
	}{
		"corr-pa-allowed":     {"hr_aggregate_sql", [3]string{"allowed", evidence.DispatchDispatched, evidence.DownstreamCompleted}},
		"corr-pa-forbidden":   {"hr_employee_export", [3]string{"denied", evidence.DispatchNotDispatched, evidence.DownstreamNone}},
		"corr-pa-invalid-sql": {"hr_aggregate_sql", [3]string{"allowed", evidence.DispatchDispatched, evidence.DownstreamRejected}},
	}
	for corr, w := range want {
		r, ok := byCorr[corr]
		if !ok {
			t.Fatalf("no record with the client's correlation id %s: %+v", corr, sd.Timeline.Records)
		}
		if r.Outcome.Tool != w.tool {
			t.Fatalf("%s: tool %q, want %q", corr, r.Outcome.Tool, w.tool)
		}
		if got := [3]string{r.Outcome.Decision, r.Outcome.Dispatch, r.Outcome.Downstream}; got != w.outcome {
			t.Fatalf("%s: outcome %v, want %v (basis %q)", corr, got, w.outcome, r.Outcome.Basis)
		}
	}
	if len(sd.Timeline.Records) != 3 {
		t.Fatalf("session has %d records, want 3 (the wrong-key call is not this session's): %+v", len(sd.Timeline.Records), sd.Timeline.Records)
	}
	var cliTimeline session.Timeline
	talonJSON(t, dir, &cliTimeline, "audit", "list", "--json", "--session", paSession)
	if len(cliTimeline.Records) != 3 {
		t.Fatalf("CLI timeline has %d records", len(cliTimeline.Records))
	}
	for _, r := range cliTimeline.Records {
		a := byCorr[r.CorrelationID]
		if r.ID != a.ID || *r.Outcome != *a.Outcome {
			t.Fatalf("CLI and console differ for %s:\nCLI %+v %+v\nAPI %+v %+v", r.CorrelationID, r, r.Outcome, a, a.Outcome)
		}
	}
	var cliDetail session.Detail
	talonJSON(t, dir, &cliDetail, "session", "show", paSession, "--json")
	if cliDetail.Summary.RecordCount != 3 || sd.Detail.Summary.RecordCount != 3 || cliDetail.Summary.ToolCallsDenied != sd.Detail.Summary.ToolCallsDenied {
		t.Fatalf("session summaries differ: CLI %+v API %+v", cliDetail.Summary, sd.Detail.Summary)
	}

	// --- Every record verifies, in the console and with the CLI.
	for tool := range byCorr {
		r := byCorr[tool]
		var ed console.EvidenceDetail
		consoleGet(t, c, "/console/v1/evidence/"+r.ID, &ed)
		if ed.Detail == nil || ed.Detail.Verification.State != "valid" {
			t.Fatalf("%s: console verification %+v", tool, ed.Detail)
		}
		var cliEd evidence.RecordDetail
		talonJSON(t, dir, &cliEd, "audit", "show", r.ID, "--json")
		if cliEd.Outcome != ed.Detail.Outcome || cliEd.Verification.State != "valid" {
			t.Fatalf("%s: CLI %+v vs API %+v", tool, cliEd.Outcome, ed.Detail.Outcome)
		}
		if _, stderr, code := RunTalon(t, dir, nil, "audit", "verify", r.ID); code != 0 {
			t.Fatalf("%s: talon audit verify: %d %s", tool, code, stderr)
		}
	}

	// --- Search by the client's correlation id finds exactly that record.
	var sr console.SearchResults
	consoleGet(t, c, "/console/v1/search?q=corr-pa-forbidden&tenant=default", &sr)
	if len(sr.Evidence) != 1 || sr.Evidence[0].ID != byCorr["corr-pa-forbidden"].ID {
		t.Fatalf("correlation search: %+v", sr.Evidence)
	}

	// --- Effective policy: each boundary proved on its own. The running MCP
	// proxy proves its tool decisions; no gateway runs, so the gateway
	// policy is compiled from the files and not proven active. CLI = API.
	var ep console.EffectivePolicyDTO
	consoleGet(t, c, "/console/v1/use-cases/"+paAgent+"/effective-policy", &ep)
	if ep.Report == nil || ep.Report.Loaded.State != "loaded_matches_file" {
		t.Fatalf("the agent file must be proven loaded by the running proxy: %+v", ep.Report)
	}
	if !ep.Report.MCPBoundary.ProvenActive {
		t.Fatalf("the running proxy loaded the current proxy config, its decisions are proven: %+v", ep.Report.MCPBoundary.Proof)
	}
	if ep.Report.Effective.ProvenActive || ep.Report.Effective.Proof.State != "no_running_process" {
		t.Fatalf("no gateway runs: the gateway policy must not be proven active: %+v", ep.Report.Effective.Proof)
	}
	denied := false
	for _, d := range ep.Report.MCPBoundary.Tools {
		if d.Tool == "hr_employee_export" && !d.Allowed && d.Stage == "forbidden_tools" {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("hr_employee_export must be denied at forbidden_tools: %+v", ep.Report.MCPBoundary)
	}
	if ep.Report.LastDecision == nil || ep.Report.LastDecision.EvidenceID != byCorr["corr-pa-invalid-sql"].ID || ep.Report.LastDecision.Verification != "valid" {
		t.Fatalf("last decision must be the newest record, verified: %+v", ep.Report.LastDecision)
	}
	var cliEp effective.Report
	talonJSON(t, dir, &cliEp, "agents", "show", paAgent, "--effective", "--json", "--proxy-config", proxyCfg)
	if cliEp.Loaded.State != ep.Report.Loaded.State || cliEp.CurrentFiles.PolicyDigest != ep.Report.CurrentFiles.PolicyDigest ||
		cliEp.LastDecision == nil || cliEp.LastDecision.EvidenceID != ep.Report.LastDecision.EvidenceID || len(cliEp.Effective.Rules) != len(ep.Report.Effective.Rules) ||
		cliEp.Effective.Proof.State != ep.Report.Effective.Proof.State || cliEp.MCPBoundary.Proof.State != ep.Report.MCPBoundary.Proof.State {
		t.Fatalf("CLI and console effective policy differ:\nCLI %+v\nAPI %+v", cliEp, *ep.Report)
	}

	// --- Runtime and spend: the proxy runs, no gateway is configured, no money was spent.
	s := waitRole(t, c, "mcp_proxy", "running", 15*time.Second)
	if st, _ := roleState(s, "gateway"); st != "not_configured" {
		t.Fatalf("gateway role: %q, want not_configured (no provider is involved)", st)
	}
	var costsDTO console.Costs
	consoleGet(t, c, "/console/v1/costs?tenant=default&agent="+paAgent, &costsDTO)
	if costsDTO.Report == nil || costsDTO.Report.TodayEUR != 0 || costsDTO.Report.MonthEUR != 0 {
		t.Fatalf("no provider call was made, spend must be zero: %+v", costsDTO.Report)
	}

	// --- Browser: the same installation in Chromium (CLI = API = browser).
	if os.Getenv("TALON_PA_BROWSER") == "1" {
		runLiveBrowser(t, dir, ui, proxyCfg, byCorr)
	}

	// --- SIGKILL the data plane: stale, nothing reaches the backend, evidence stays readable.
	_, firstInstance := roleState(s, "mcp_proxy")
	if err := dp.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_, _ = dp.cmd.Process.Wait()
	before := up.total()
	downReq, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/mcp/proxy", strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"hr_aggregate_sql"}}`))
	downReq.Header.Set("Authorization", "Bearer "+paKey)
	if resp, err := http.DefaultClient.Do(downReq); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a killed data plane answered HTTP %d", resp.StatusCode)
	}
	if up.total() != before {
		t.Fatal("a call reached the HR backend while the data plane was down")
	}
	waitRole(t, c, "mcp_proxy", "stale", 30*time.Second)
	consoleGet(t, c, "/console/v1/sessions/"+paSession+"?agent="+paAgent, &sd)
	if sd.Timeline == nil || len(sd.Timeline.Records) != 3 {
		t.Fatalf("evidence must stay readable while the data plane is down: %+v", sd.Availability)
	}

	// --- Restart: a new instance continues the same session.
	dp = startProxyServe(t, dir, dpPort, nil)
	s = waitRole(t, c, "mcp_proxy", "running", 20*time.Second)
	if _, inst := roleState(s, "mcp_proxy"); inst == firstInstance || inst == "" {
		t.Fatalf("a restart must be a new instance (was %s, now %s)", firstInstance, inst)
	}
	if st, _ := paCall(t, base, paKey, "hr_aggregate_sql", paValidSQL, "corr-pa-after-restart"); st != http.StatusOK {
		t.Fatalf("call after restart: %d", st)
	}
	if n := up.count("hr_aggregate_sql"); n != 3 {
		t.Fatalf("after restart: backend saw %d aggregate calls, want 3", n)
	}
	consoleGet(t, c, "/console/v1/sessions/"+paSession+"?agent="+paAgent, &sd)
	if len(sd.Timeline.Records) != 4 {
		t.Fatalf("the restarted data plane must extend the same session: %d records", len(sd.Timeline.Records))
	}

	// --- Tamper: make the forbidden call look allowed in the database.
	_ = dp.cmd.Process.Signal(syscall.SIGTERM)
	_, _ = dp.cmd.Process.Wait()
	id := byCorr["corr-pa-forbidden"].ID
	tamperRecord(t, dbPath, id)
	var ed console.EvidenceDetail
	consoleGet(t, c, "/console/v1/evidence/"+id, &ed)
	if ed.Detail == nil || ed.Detail.Verification.State != "invalid" {
		t.Fatalf("a record changed after signing must read as invalid: %+v", ed.Detail)
	}
	if _, _, code := RunTalon(t, dir, nil, "audit", "verify", id); code == 0 {
		t.Fatal("talon audit verify must fail on a tampered record")
	}
	if b, _ := os.ReadFile(dp.log); strings.Contains(string(b), paKey) {
		t.Fatal("the workload key appeared in the data-plane log")
	}
	if strings.Contains(ui.readLog(), paKey) {
		t.Fatal("the workload key appeared in the console log")
	}
}

// tamperRecord rewrites one stored record's decision without re-signing it.
func tamperRecord(t *testing.T, dbPath, id string) {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var js string
	if err := db.QueryRowContext(t.Context(), `SELECT evidence_json FROM evidence WHERE id = ?`, id).Scan(&js); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(js, `"allowed":false`, `"allowed":true`, 1)
	if changed == js {
		t.Fatalf("record %s has no decision to tamper with: %s", id, js)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE evidence SET evidence_json = ? WHERE id = ?`, changed, id); err != nil {
		t.Fatal(err)
	}
}

// runLiveBrowser runs tests/browser/live against this installation. It
// writes the state file the browser helpers read (installation dir, console
// log for pairing codes, binary) plus the expectations, and fails the test
// when the spec fails. Node and the Playwright Chromium are required: when
// TALON_PA_BROWSER=1 is set a missing tool is a failure, not a skip.
func runLiveBrowser(t *testing.T, dir string, ui *uiProcess, proxyCfg string, byCorr map[string]evidence.Index) {
	t.Helper()
	browserDir, err := filepath.Abs("../browser")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{
		"allowed":     byCorr["corr-pa-allowed"].ID,
		"forbidden":   byCorr["corr-pa-forbidden"].ID,
		"invalid_sql": byCorr["corr-pa-invalid-sql"].ID,
	}
	port := strings.TrimPrefix(ui.base, "http://127.0.0.1:")
	state := map[string]any{
		"dir": dir, "uiLogPath": ui.log, "uiPort": port, "bin": binaryPath,
		"env":     map[string]string{"TALON_DATA_DIR": dir, "TALON_SIGNING_KEY": testSigningKey, "TALON_SECRETS_KEY": testSecretsKey},
		"fixture": map[string]any{"use_case": paAgent, "session": paSession, "evidence": ids, "proxy_config": proxyCfg},
	}
	raw, _ := json.Marshal(state)
	statePath := filepath.Join(dir, "browser-state.json")
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "npx", "playwright", "test", "--config", "playwright.live.config.js")
	cmd.Dir = browserDir
	cmd.Env = append(os.Environ(), "TALON_BROWSER_STATE="+statePath, "TALON_CONSOLE_URL="+ui.base)
	out, err := cmd.CombinedOutput()
	t.Logf("live browser run:\n%s", out)
	if err != nil {
		t.Fatalf("live browser spec failed: %v", err)
	}
}

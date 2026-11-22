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
		case "server/discover":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":600000,"cacheScope":"public","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"hr-backend","version":"1"}}}}`, req.ID)
		case "tools/list":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[{"name":"hr_aggregate_sql","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"]}},{"name":"hr_employee_export","inputSchema":{"type":"object","properties":{"department":{"type":"string"}}}}],"ttlMs":600000,"cacheScope":"public"}}`, req.ID)
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

// paAgentFile is the People Analytics use case: the HR backend is its
// trusted MCP action source; the aggregate query is a read-only action (one
// call); the export is forbidden by the use case.
func paAgentFile(hrURL string) string {
	return `agent:
  name: ` + paAgent + `
  version: "1.0.0"
  key:
    secret_name: "` + paAgent + `-talon-key"
capabilities:
  forbidden_tools: [hr_employee_export]
actions:
  sources:
    hr:
      type: mcp
      url: "` + hrURL + `"
  definitions:
    hr_aggregate_sql:
      source: hr
      read_only: true
      review: {fields: [sql]}
    hr_employee_export:
      source: hr
      review: {fields: [department]}
policies:
  cost_limits:
    daily: 10
    monthly: 100
`
}

// paCall sends one tools/call to the governed MCP endpoint in the People
// Analytics session, with a correlation id the test chose (client-asserted
// attribution, #431).
func paCall(t *testing.T, base, key, tool, sql, corr string) (int, map[string]any) {
	t.Helper()
	c := &mcpClient{t: t, base: base, key: key}
	args := "{}"
	if sql != "" {
		b, _ := json.Marshal(map[string]string{"sql": sql})
		args = string(b)
	}
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{` + mcpMeta + `,"name":"` + tool + `","arguments":` + args + `}}`
	st, _, out := c.post("/mcp", "tools/call", tool, body, map[string]string{"X-Talon-Session-ID": paSession, "X-Correlation-ID": corr})
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
// call counters is the use case's trusted MCP action source; the production
// `talon serve` (governed MCP endpoint, no LLM gateway) and the production
// `talon ui serve` run on loopback. No provider key is used and no LLM call
// is made: the proof is the MCP boundary and the Action Gateway (#431).
//
// It proves, in order: unauthenticated console reads and a wrong workload key
// reach nothing; a valid hr_aggregate_sql query (a read-only action) is
// executed in one call (backend counter +1) and recorded as completed;
// hr_employee_export is denied by the use case's policy before dispatch (its
// backend counter stays 0); a query the HR backend rejects after Talon
// dispatched it is recorded as unknown — never as a Talon denial; the
// client's session and correlation ids are attribution on every lifecycle
// record of each operation; every record verifies and every operation's
// lifecycle verifies; the console's session, evidence, search,
// effective-policy and runtime answers equal the CLI's; readiness is
// operational for this MCP-only installation; spend stays zero; a SIGKILLed
// data plane goes stale, nothing more reaches the backend, the evidence stays
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
	if err := os.WriteFile(filepath.Join(dir, "agent.talon.yaml"), []byte(paAgentFile(up.srv.URL+"/mcp")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", paAgent+"-talon-key", paKey); code != 0 {
		t.Fatalf("secrets set: %d %s", code, stderr)
	}
	dbPath := filepath.Join(dir, "evidence.db")

	dpPort := freePort(t)
	dp := startDataPlane(t, dir, dpPort, nil)
	base := fmt.Sprintf("http://127.0.0.1:%d", dpPort)
	ui := startConsoleUI(t, dir, freePort(t))

	// --- Negative auth: no console session, wrong workload key.
	anon := newConsoleClient(t, ui.base)
	for _, p := range []string{"/console/v1/overview", "/console/v1/sessions/" + paSession, "/console/v1/use-cases/" + paAgent + "/effective-policy"} {
		if status, _, _ := anon.do(http.MethodGet, p, "", nil); status != http.StatusUnauthorized {
			t.Fatalf("unpaired GET %s: %d, want 401", p, status)
		}
	}
	if st, _ := paCall(t, base, "talon-not-a-real-key-0000", "hr_aggregate_sql", paValidSQL, "corr-pa-badkey"); st != http.StatusUnauthorized {
		t.Fatalf("wrong workload key: HTTP %d, want 401", st)
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
	refs := map[string]string{} // client correlation id -> operation reference
	st, out := paCall(t, base, paKey, "hr_aggregate_sql", paValidSQL, "corr-pa-allowed")
	if st != http.StatusOK || out["result"] == nil {
		t.Fatalf("allowed call: %d %v", st, out)
	}
	refs["corr-pa-allowed"] = fmt.Sprint(govExt(out)["operationRef"])
	if n := up.count("hr_aggregate_sql"); n != 1 {
		t.Fatalf("allowed call: backend saw %d calls, want 1", n)
	}
	_, out = paCall(t, base, paKey, "hr_employee_export", "", "corr-pa-forbidden")
	if x := govExt(out); x["code"] != "policy_denied" || x["provenance"] != "not_dispatched" {
		t.Fatalf("forbidden call must be denied before dispatch: %v", out)
	}
	refs["corr-pa-forbidden"] = fmt.Sprint(govExt(out)["operationRef"])
	if n := up.count("hr_employee_export"); n != 0 {
		t.Fatalf("forbidden call reached the HR backend %d times", n)
	}
	_, out = paCall(t, base, paKey, "hr_aggregate_sql", paInvalidSQL, "corr-pa-invalid-sql")
	if x := govExt(out); x["code"] != "upstream_outcome_unknown" || x["decision"] != "unknown" {
		t.Fatalf("a query the backend rejected after dispatch is unknown, not a denial: %v", out)
	}
	if strings.Contains(fmt.Sprint(out), "invalid SQL or query shape") {
		t.Fatalf("the backend's own error text must not be relayed: %v", out)
	}
	refs["corr-pa-invalid-sql"] = fmt.Sprint(govExt(out)["operationRef"])
	if n, rej := up.count("hr_aggregate_sql"), up.rejections(); n != 2 || rej != 1 {
		t.Fatalf("invalid query: backend saw %d aggregate calls and rejected %d, want 2 and 1 (Talon allowed and dispatched it; the backend refused it)", n, rej)
	}

	// --- Console session = CLI session. Every lifecycle record of the three
	// operations joins the client's session; the final record of each says
	// what happened.
	var sd console.SessionDetail
	consoleGet(t, c, "/console/v1/sessions/"+paSession+"?agent="+paAgent, &sd)
	if sd.Timeline == nil || sd.Detail == nil {
		t.Fatalf("session detail: %+v", sd.Availability)
	}
	final := map[string]evidence.Index{} // client correlation id -> the operation's newest record
	perOp := map[string]int{}
	for _, r := range sd.Timeline.Records {
		if r.SessionID != paSession || r.AgentID != paAgent {
			t.Fatalf("record %s: session %q agent %q, want the asserted session and the key's use case", r.ID, r.SessionID, r.AgentID)
		}
		if r.Outcome == nil {
			t.Fatalf("record %s has no outcome", r.ID)
		}
		perOp[r.CorrelationID]++
		for corr, ref := range refs {
			if r.CorrelationID == ref && (final[corr].ID == "" || !r.Timestamp.Before(final[corr].Timestamp)) {
				final[corr] = r
			}
		}
	}
	want := map[string]struct {
		records int
		outcome [3]string
	}{
		"corr-pa-allowed":     {4, [3]string{"allowed", evidence.DispatchDispatched, evidence.DownstreamCompleted}},
		"corr-pa-forbidden":   {1, [3]string{"denied", evidence.DispatchNotDispatched, evidence.DownstreamNone}},
		"corr-pa-invalid-sql": {4, [3]string{"allowed", evidence.DispatchUnknown, evidence.DownstreamUnknown}},
	}
	for corr, w := range want {
		r, ok := final[corr]
		if !ok {
			t.Fatalf("no record of operation %s (%s) in the session: %+v", refs[corr], corr, sd.Timeline.Records)
		}
		if perOp[refs[corr]] != w.records {
			t.Fatalf("%s: %d lifecycle records in the session, want %d", corr, perOp[refs[corr]], w.records)
		}
		if got := [3]string{r.Outcome.Decision, r.Outcome.Dispatch, r.Outcome.Downstream}; got != w.outcome {
			t.Fatalf("%s: outcome %v, want %v (basis %q)", corr, got, w.outcome, r.Outcome.Basis)
		}
	}
	if len(sd.Timeline.Records) != 9 {
		t.Fatalf("session has %d records, want 9 (the wrong-key call is not this session's): %+v", len(sd.Timeline.Records), sd.Timeline.Records)
	}
	var cliTimeline session.Timeline
	talonJSON(t, dir, &cliTimeline, "audit", "list", "--json", "--session", paSession)
	if len(cliTimeline.Records) != len(sd.Timeline.Records) {
		t.Fatalf("CLI timeline has %d records, console %d", len(cliTimeline.Records), len(sd.Timeline.Records))
	}
	apiByID := map[string]evidence.Index{}
	for _, r := range sd.Timeline.Records {
		apiByID[r.ID] = r
	}
	for _, r := range cliTimeline.Records {
		a, ok := apiByID[r.ID]
		if !ok || *r.Outcome != *a.Outcome {
			t.Fatalf("CLI and console differ for %s:\nCLI %+v\nAPI %+v", r.ID, r.Outcome, a.Outcome)
		}
	}
	var cliDetail session.Detail
	talonJSON(t, dir, &cliDetail, "session", "show", paSession, "--json")
	if cliDetail.Summary.RecordCount != sd.Detail.Summary.RecordCount || cliDetail.Summary.RecordCount != 9 {
		t.Fatalf("session summaries differ: CLI %+v API %+v", cliDetail.Summary, sd.Detail.Summary)
	}

	// --- Every record verifies, in the console and with the CLI; every
	// operation's signed lifecycle verifies.
	for _, r := range sd.Timeline.Records {
		var ed console.EvidenceDetail
		consoleGet(t, c, "/console/v1/evidence/"+r.ID, &ed)
		if ed.Detail == nil || ed.Detail.Verification.State != "valid" {
			t.Fatalf("%s: console verification %+v", r.ID, ed.Detail)
		}
		var cliEd evidence.RecordDetail
		talonJSON(t, dir, &cliEd, "audit", "show", r.ID, "--json")
		if cliEd.Outcome != ed.Detail.Outcome || cliEd.Verification.State != "valid" {
			t.Fatalf("%s: CLI %+v vs API %+v", r.ID, cliEd.Outcome, ed.Detail.Outcome)
		}
		if _, stderr, code := RunTalon(t, dir, nil, "audit", "verify", r.ID); code != 0 {
			t.Fatalf("%s: talon audit verify: %d %s", r.ID, code, stderr)
		}
	}

	// --- Search by the forbidden operation's reference finds its record.
	var sr console.SearchResults
	consoleGet(t, c, "/console/v1/search?q="+refs["corr-pa-forbidden"]+"&tenant=default", &sr)
	if len(sr.Evidence) != 1 || sr.Evidence[0].ID != final["corr-pa-forbidden"].ID {
		t.Fatalf("correlation search: %+v", sr.Evidence)
	}

	// --- Effective policy: the running serve loaded the current agent file;
	// no gateway runs, so the gateway policy is compiled from the files and
	// not proven active. CLI = API.
	var ep console.EffectivePolicyDTO
	consoleGet(t, c, "/console/v1/use-cases/"+paAgent+"/effective-policy", &ep)
	if ep.Report == nil || ep.Report.Loaded.State != "loaded_matches_file" {
		t.Fatalf("the agent file must be proven loaded by the running serve: %+v", ep.Report)
	}
	if ep.Report.Effective.ProvenActive || ep.Report.Effective.Proof.State != "no_running_process" {
		t.Fatalf("no gateway runs: the gateway policy must not be proven active: %+v", ep.Report.Effective.Proof)
	}
	if ep.Report.LastDecision == nil || ep.Report.LastDecision.Verification != "valid" {
		t.Fatalf("last decision must be recorded and verified: %+v", ep.Report.LastDecision)
	}
	var cliEp effective.Report
	talonJSON(t, dir, &cliEp, "agents", "show", paAgent, "--effective", "--json")
	if cliEp.Loaded.State != ep.Report.Loaded.State || cliEp.CurrentFiles.PolicyDigest != ep.Report.CurrentFiles.PolicyDigest ||
		cliEp.LastDecision == nil || cliEp.LastDecision.EvidenceID != ep.Report.LastDecision.EvidenceID || len(cliEp.Effective.Rules) != len(ep.Report.Effective.Rules) ||
		cliEp.Effective.Proof.State != ep.Report.Effective.Proof.State {
		t.Fatalf("CLI and console effective policy differ:\nCLI %+v\nAPI %+v", cliEp, *ep.Report)
	}

	// --- Runtime and spend: the MCP endpoint runs, no gateway is configured,
	// no money was spent.
	s := waitRole(t, c, "mcp", "running", 15*time.Second)
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
		runLiveBrowser(t, dir, ui, final)
	}

	// --- Operational readiness (#533, #431): an MCP-only installation whose
	// serve runs the governed MCP endpoint, loaded the current files and
	// holds the use case's key is operational. The absent gateway is not an
	// incident, and the recorded denial of hr_employee_export is evidence,
	// not a runtime finding.
	var ready console.Overview
	consoleGet(t, c, "/console/v1/overview", &ready)
	if ready.Readiness.Overall != console.OverallOperational {
		t.Fatalf("readiness %q (%s), want operational: %+v", ready.Readiness.Overall, ready.Readiness.Summary, ready.Readiness.Dimensions)
	}
	if len(ready.Readiness.Findings) != 0 {
		t.Fatalf("installation findings on a ready MCP-only installation: %+v", ready.Readiness.Findings)
	}
	for _, d := range ready.Readiness.Dimensions {
		switch d.Key {
		case console.DimGateway:
			if d.State != console.ReadyNotConfigured {
				t.Fatalf("gateway dimension %+v, want not_configured", d)
			}
		case console.DimMCP:
			if d.State != console.ReadyOK {
				t.Fatalf("MCP endpoint dimension %+v, want ok", d)
			}
		case console.DimAgentKeys:
			if d.State != console.ReadyOK {
				t.Fatalf("agent keys %+v, want ok: the serve reports holding the use case's key", d)
			}
		}
	}

	// --- SIGKILL the data plane: stale, nothing reaches the backend, evidence stays readable.
	_, firstInstance := roleState(s, "mcp")
	if err := dp.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_, _ = dp.cmd.Process.Wait()
	before := up.total()
	if st, ok := tryPACall(base, paKey); ok {
		t.Fatalf("a killed data plane answered HTTP %d", st)
	}
	if up.total() != before {
		t.Fatal("a call reached the HR backend while the data plane was down")
	}
	waitRole(t, c, "mcp", "stale", 30*time.Second)
	// The killed serve: readiness degraded with a stale-runtime finding, and
	// its keys are no longer evidence of anything.
	consoleGet(t, c, "/console/v1/overview", &ready)
	if ready.Readiness.Overall != console.OverallDegraded || len(ready.Readiness.Findings) == 0 || ready.Readiness.Findings[0].Code != "runtime_stale" {
		t.Fatalf("after SIGKILL: readiness %q findings %+v, want degraded with runtime_stale first", ready.Readiness.Overall, ready.Readiness.Findings)
	}
	consoleGet(t, c, "/console/v1/sessions/"+paSession+"?agent="+paAgent, &sd)
	if sd.Timeline == nil || len(sd.Timeline.Records) != 9 {
		t.Fatalf("evidence must stay readable while the data plane is down: %+v", sd.Availability)
	}

	// --- Restart: a new instance continues the same session.
	dp = startDataPlane(t, dir, dpPort, nil)
	s = waitRole(t, c, "mcp", "running", 20*time.Second)
	if _, inst := roleState(s, "mcp"); inst == firstInstance || inst == "" {
		t.Fatalf("a restart must be a new instance (was %s, now %s)", firstInstance, inst)
	}
	if st, _ := paCall(t, base, paKey, "hr_aggregate_sql", paValidSQL, "corr-pa-after-restart"); st != http.StatusOK {
		t.Fatalf("call after restart: %d", st)
	}
	if n := up.count("hr_aggregate_sql"); n != 3 {
		t.Fatalf("after restart: backend saw %d aggregate calls, want 3", n)
	}
	consoleGet(t, c, "/console/v1/sessions/"+paSession+"?agent="+paAgent, &sd)
	if len(sd.Timeline.Records) != 13 {
		t.Fatalf("the restarted data plane must extend the same session: %d records", len(sd.Timeline.Records))
	}

	// --- Tamper: make the forbidden call look allowed in the database.
	_ = dp.cmd.Process.Signal(syscall.SIGTERM)
	_, _ = dp.cmd.Process.Wait()
	id := final["corr-pa-forbidden"].ID
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

// runLiveBrowser runs the People Analytics live spec against this
// installation.
func runLiveBrowser(t *testing.T, dir string, ui *uiProcess, final map[string]evidence.Index) {
	t.Helper()
	ids := map[string]string{
		"allowed":     final["corr-pa-allowed"].ID,
		"forbidden":   final["corr-pa-forbidden"].ID,
		"invalid_sql": final["corr-pa-invalid-sql"].ID,
	}
	runLiveBrowserSpec(t, dir, ui, "live/people-analytics.spec.js", nil,
		map[string]any{"use_case": paAgent, "session": paSession, "evidence": ids})
}

// runLiveBrowserSpec runs one spec of tests/browser/live in Chromium against
// a running console of this test's installation. It writes the state file
// the browser helpers read (installation dir, console log for pairing codes,
// the binary and environment for CLI parity) and the spec's fixture.
func runLiveBrowserSpec(t *testing.T, dir string, ui *uiProcess, spec string, env map[string]string, fixture map[string]any) {
	t.Helper()
	browserDir, err := filepath.Abs("../browser")
	if err != nil {
		t.Fatal(err)
	}
	port := strings.TrimPrefix(ui.base, "http://127.0.0.1:")
	stateEnv := map[string]string{"TALON_DATA_DIR": dir, "TALON_SIGNING_KEY": testSigningKey, "TALON_SECRETS_KEY": testSecretsKey}
	for k, v := range env {
		stateEnv[k] = v
	}
	state := map[string]any{"dir": dir, "uiLogPath": ui.log, "uiPort": port, "bin": binaryPath, "env": stateEnv, "fixture": fixture}
	raw, _ := json.Marshal(state)
	statePath := filepath.Join(dir, "browser-state.json")
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "npx", "playwright", "test", "--config", "playwright.live.config.js", spec)
	cmd.Dir = browserDir
	cmd.Env = append(os.Environ(), "TALON_BROWSER_STATE="+statePath, "TALON_CONSOLE_URL="+ui.base)
	out, err := cmd.CombinedOutput()
	t.Logf("live browser run (%s):\n%s", spec, out)
	if err != nil {
		t.Fatalf("live browser spec %s failed: %v", spec, err)
	}
}

//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Trusted action catalog proof (#427) against the built binary.
//
//   talon actions list/show/validate   candidate catalog: declared http action
//                                      + MCP-discovered action, one projection
//   talon serve                        catalog compiled INTO the runtime
//                                      generation; the Action Gateway serves it
//   mcp-sourced action                 catalogued, NOT executable (execution_unsupported),
//                                      zero upstream tools/call
//   source refresh (ttl)               changed upstream schema → new generation
//   source failure on refresh          rejected, last-known-good keeps serving
//   source recovery                    same facts → the SAME generation id again

const (
	acAgent    = "support-bot"
	acAgentKey = "talon-gw-catalog-e2e-0001"
	acAdminKey = "admin-e2e-key-catalog"
)

// catalogUpstream is a scriptable 2026-07-28 source. mode: ok | broken | v2.
type catalogUpstream struct {
	srv       *httptest.Server
	mode      atomic.Value
	toolCalls atomic.Int64
}

func startCatalogUpstream(t *testing.T) *catalogUpstream {
	t.Helper()
	u := &catalogUpstream{}
	u.mode.Store("ok")
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		var result string
		switch req.Method {
		case "server/discover":
			result = `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{"listChanged":true},"extensions":{"io.modelcontextprotocol/tasks":{}}},"instructions":"refunds only","ttlMs":1,"cacheScope":"public","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"refunds-upstream","version":"1"}}}`
		case "tools/list":
			// Two pages: the first advertises a long ttl, the second a short
			// one — the logical list must refresh on the SHORT one.
			if req.Params.Cursor == "" {
				result = `{"resultType":"complete","tools":[{"name":"ticket.lookup","inputSchema":{"type":"object"}}],"nextCursor":"p2","ttlMs":3600000,"cacheScope":"public"}`
				break
			}
			amount := `{"type":"number"}`
			if u.mode.Load() == "v2" {
				amount = `{"type":"integer"}`
			}
			hints := `,"ttlMs":1500,"cacheScope":"public"`
			if u.mode.Load() == "broken" {
				hints = ""
			}
			result = `{"resultType":"complete","tools":[{"name":"refund.create","title":"Create refund","description":"Create a refund","annotations":{"destructiveHint":false,"talon/approver_groups":["anyone"]},"inputSchema":{"type":"object","properties":{"ticket_id":{"type":"string"},"amount":` + amount + `,"region":{"type":"string","x-mcp-header":"Region"}},"required":["ticket_id","amount"]}}]` + hints + `}`
		default:
			u.toolCalls.Add(1)
			result = `{"resultType":"complete","content":[]}`
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + result + `}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

type fleetReply struct {
	Generation string `json:"generation"`
	Reload     *struct {
		ActiveGeneration  string   `json:"active_generation"`
		Rejected          bool     `json:"rejected"`
		SourcesRejected   bool     `json:"action_sources_rejected"`
		RejectedCauses    []string `json:"rejected_causes"`
		NextSourceRefresh string   `json:"next_action_source_refresh"`
	} `json:"reload"`
}

func readFleet(t *testing.T, base string) fleetReply {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/v1/agents/fleet", nil)
	req.Header.Set("X-Talon-Admin-Key", acAdminKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out fleetReply
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("fleet decode: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("fleet: %d", resp.StatusCode)
	}
	return out
}

// awaitFleet polls the fleet endpoint until cond holds (bounded).
func awaitFleet(t *testing.T, base, what string, cond func(fleetReply) bool) fleetReply {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	var last fleetReply
	for time.Now().Before(deadline) {
		last = readFleet(t, base)
		if cond(last) {
			return last
		}
		time.Sleep(200 * time.Millisecond)
	}
	raw, _ := json.Marshal(last)
	t.Fatalf("fleet never reached %q; last: %s", what, raw)
	return last
}

func TestE2E_ActionCatalog_TrustedSources(t *testing.T) {
	up := startCatalogUpstream(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", acAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	raw, _ := os.ReadFile(agentPath)
	yaml := strings.Replace(string(raw), "\npolicies:\n", `
actions:
  sources:
    refunds:
      type: mcp
      url: "`+up.srv.URL+`"
  definitions:
    create_refund_request:
      source: refunds
      upstream_name: refund.create
      review:
        fields: [ticket_id, amount]
        non_material: [region]
    notify_customer:
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id]
        properties:
          ticket_id: {type: string}
      destination: {type: http, url: "`+up.srv.URL+`/notify", success: {status_codes: [200]}}

policies:
  approvals:
    rules:
      refund-request:
        actions: [create_refund_request]
        approver_groups: [support-leads]
`, 1)
	if err := os.WriteFile(agentPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "validate"); code != 0 {
		t.Fatalf("talon validate (offline; sources not discovered) must accept the static catalog:\n%s", stderr)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", acAgent+"-talon-key", acAgentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}

	// 1. Operator inspection: one projection for both definitions.
	out, stderr, code := RunTalon(t, dir, nil, "actions", "list", "--json")
	if code != 0 {
		t.Fatalf("actions list: %d\n%s", code, stderr)
	}
	var listed struct {
		Candidate string `json:"candidate"`
		Catalog   struct {
			Digest  string `json:"catalog_digest"`
			Actions []struct {
				Name             string `json:"name"`
				UpstreamName     string `json:"upstream_name"`
				DefinitionDigest string `json:"definition_digest"`
				Verdict          string `json:"verdict"`
				Source           struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"source"`
			} `json:"actions"`
		} `json:"catalog"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("list json: %v\n%s", err, out)
	}
	if !strings.Contains(listed.Candidate, "Candidate catalog") || len(listed.Catalog.Actions) != 2 {
		t.Fatalf("list: %s", out)
	}
	refund := listed.Catalog.Actions[0]
	if refund.Name != "create_refund_request" || refund.UpstreamName != "refund.create" || refund.Source.Type != "mcp" || refund.Source.ID != "refunds" || refund.Verdict != "REQUIRE_APPROVAL" {
		t.Fatalf("discovered definition: %+v", refund)
	}
	if listed.Catalog.Actions[1].Source.Type != "declared" || listed.Catalog.Actions[1].Verdict != "ALLOW" {
		t.Fatalf("declared definition: %+v", listed.Catalog.Actions[1])
	}
	// Source facts (capabilities, extensions, tool hints) are presented as
	// metadata; the hostile annotation member never appears.
	if !strings.Contains(out, `"io.modelcontextprotocol/tasks"`) || !strings.Contains(out, `"destructive_hint": false`) || strings.Contains(out, "anyone") {
		t.Fatalf("source facts not represented safely:\n%s", out)
	}
	out, stderr, code = RunTalon(t, dir, nil, "actions", "show", "create_refund_request")
	if code != 0 || !strings.Contains(out, "Mcp-Param-Region <- region") || !strings.Contains(out, "Non-material:       region") {
		t.Fatalf("actions show: %d\n%s\n%s", code, out, stderr)
	}
	input := filepath.Join(dir, "in.json")
	_ = os.WriteFile(input, []byte(`{"ticket_id":"T-1","amount":50.00,"region":"eu"}`), 0o600)
	if out, stderr, code = RunTalon(t, dir, nil, "actions", "validate", "--action", "create_refund_request", "--input", input); code != 0 || !strings.Contains(out, "Arguments:          valid") {
		t.Fatalf("actions validate: %d\n%s\n%s", code, out, stderr)
	}
	_ = os.WriteFile(input, []byte(`{"ticket_id":"T-1","amount":50,"approver_group":"anyone"}`), 0o600)
	if _, _, code = RunTalon(t, dir, nil, "actions", "validate", "--action", "create_refund_request", "--input", input); code == 0 {
		t.Fatal("an undeclared field must fail validation")
	}
	if up.toolCalls.Load() != 0 {
		t.Fatalf("inspection must never call a tool: %d", up.toolCalls.Load())
	}

	// 2. serve: the catalog is part of the runtime generation.
	port := freePort(t)
	stop := startServeWithEnv(t, dir, port, map[string]string{"TALON_ADMIN_KEY": acAdminKey, "TALON_AGENTS_RELOAD_INTERVAL": "1s"})
	defer func() { stop() }()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	c := &agClient{t: t, base: base}
	boot := readFleet(t, base)
	if boot.Reload == nil || boot.Reload.NextSourceRefresh == "" || boot.Reload.Rejected {
		raw, _ := json.Marshal(boot)
		t.Fatalf("boot fleet: %s", raw)
	}
	g1 := boot.Generation

	// The declared action is served from the generation's catalog.
	st, res := c.do("POST", "/v1/action-operations", acAgentKey, `{"operation_id":"op-notify-1","action":"notify_customer","arguments":{"ticket_id":"T-1"}}`)
	if st != 201 || dig(res, "operation", "verdict") != "ALLOW" {
		t.Fatalf("declared action establish: %d %v", st, res)
	}
	// The mcp-sourced action is catalogued but has no executor before #431.
	st, res = c.do("POST", "/v1/action-operations", acAgentKey, `{"operation_id":"op-refund-1","action":"create_refund_request","arguments":{"ticket_id":"T-1","amount":50}}`)
	if st != 501 || errCode(res) != "execution_unsupported" {
		t.Fatalf("mcp-sourced establish: %d %v", st, res)
	}
	if st, res = c.do("GET", "/v1/action-operations/op-refund-1", acAgentKey, ""); st != 404 {
		t.Fatalf("nothing persisted for a refused establish: %d %v", st, res)
	}
	if up.toolCalls.Load() != 0 {
		t.Fatalf("zero upstream tools/call: %d", up.toolCalls.Load())
	}

	// 3. Source failure on refresh: rejected, last-known-good keeps serving.
	up.mode.Store("broken")
	rej := awaitFleet(t, base, "source rejection", func(f fleetReply) bool {
		return f.Reload != nil && f.Reload.Rejected && f.Reload.SourcesRejected
	})
	if rej.Generation != g1 || rej.Reload.ActiveGeneration != g1 {
		t.Fatalf("active generation changed under a failed refresh: %s vs %s", rej.Generation, g1)
	}
	if len(rej.Reload.RejectedCauses) == 0 || !strings.Contains(strings.Join(rej.Reload.RejectedCauses, " "), "ttlMs") {
		t.Fatalf("rejection causes: %v", rej.Reload.RejectedCauses)
	}
	st, _ = c.do("POST", "/v1/action-operations", acAgentKey, `{"operation_id":"op-notify-2","action":"notify_customer","arguments":{"ticket_id":"T-2"}}`)
	if st != 201 {
		t.Fatalf("last-known-good catalog must keep serving: %d", st)
	}
	// The CLI candidate is truthful about the failure.
	if _, stderr, code := RunTalon(t, dir, nil, "actions", "list"); code == 0 || !strings.Contains(stderr, "actions.sources.refunds") {
		t.Fatalf("CLI must report the failing source: %d\n%s", code, stderr)
	}

	// 4. Upstream schema changed AND the operator edits the overlay: the
	// config edit triggers an immediate candidate build (no wait for the
	// failed-refresh backoff, which the unit tests cover) and the complete
	// new generation activates.
	up.mode.Store("v2")
	edited := strings.Replace(yaml, "      upstream_name: refund.create\n", "      upstream_name: refund.create\n      description: Refund via the trusted refunds source\n", 1)
	if edited == yaml {
		t.Fatal("edit did not apply")
	}
	if err := os.WriteFile(agentPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	v2 := awaitFleet(t, base, "new generation", func(f fleetReply) bool {
		return f.Reload != nil && !f.Reload.Rejected && f.Generation != g1
	})
	g2 := v2.Generation
	out, _, code = RunTalon(t, dir, nil, "actions", "show", "create_refund_request", "--json")
	var shown map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &shown) != nil || dig(shown, "action", "schema", "properties", "amount", "type") != "integer" {
		t.Fatalf("candidate reflects the new schema: %d\n%s", code, out)
	}

	// 5. Source facts change again (ttl-driven refresh, no config edit) →
	// another generation; the SAME facts reproduce the SAME generation id:
	// a generation is a deterministic function of files + discovered facts.
	up.mode.Store("ok")
	g3 := awaitFleet(t, base, "refreshed generation", func(f fleetReply) bool {
		return f.Reload != nil && !f.Reload.Rejected && f.Generation != g2
	}).Generation
	up.mode.Store("v2")
	awaitFleet(t, base, "generation reproduced", func(f fleetReply) bool { return f.Generation == g2 })
	if g3 == g1 || g3 == g2 {
		t.Fatalf("generations must differ: %s %s %s", g1, g2, g3)
	}
	if up.toolCalls.Load() != 0 {
		t.Fatalf("discovery never calls a tool: %d", up.toolCalls.Load())
	}
}

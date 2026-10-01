//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

// MCP 2026-07-28 protocol smoke (#447): one deterministic, no-key run of the
// built binary with a counting mock upstream behind /mcp/proxy.
//
//	server/discover (both routes)   → 2026-07-28 only, tools capability, no extensions
//	tools/list                      → deterministic, filtered, cache hints
//	valid tools/call                → reaches the governed path; upstream count 1,
//	                                  outbound Mcp-* headers generated from the body
//	Mcp-Name ≠ body                 → -32020 / 400; upstream count still 1
//	legacy initialize               → rejected; no session minted
//	GET / DELETE                    → 405
//	notification                    → 202, no body, not forwarded

type mcpUpstream struct {
	srv     *httptest.Server
	calls   atomic.Int64
	headers http.Header
	body    map[string]any
}

func startMCPUpstream(t *testing.T) *mcpUpstream {
	t.Helper()
	u := &mcpUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params map[string]any  `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[{"name":"zeta_tool","inputSchema":{"type":"object"}},{"name":"ticket_lookup","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}},{"name":"delete_customer","inputSchema":{"type":"object"}}],"ttlMs":30000,"cacheScope":"public"}}`, req.ID)
		case "tools/call":
			u.calls.Add(1)
			u.headers = r.Header.Clone()
			u.body = req.Params
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":"ticket ok"}]}}`, req.ID)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"unknown"}}`, req.ID)
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

const mcpMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"talon-e2e","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}`

type mcpClient struct {
	t    *testing.T
	base string
	key  string
}

func (c *mcpClient) post(path, method, name, body string, extra map[string]string) (int, http.Header, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.key)
	if method != "" {
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", method)
	}
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp.StatusCode, resp.Header, out
}

func mcpErrCode(m map[string]any) float64 {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return c
}

func TestE2E_MCP_Protocol2026_07_28(t *testing.T) {
	up := startMCPUpstream(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", "mcp-e2e"); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	proxyCfg := filepath.Join(dir, "proxy.talon.yaml")
	if err := os.WriteFile(proxyCfg, []byte(`proxy:
  upstream:
    vendor: ticketing
    url: "`+up.srv.URL+`/mcp"
  allowed_tools:
    - name: ticket_lookup
      header_params:
        region: Region
    - name: zeta_tool
  forbidden_tools:
    - delete_customer
`), 0o600); err != nil {
		t.Fatal(err)
	}
	const agentKey = "talon-mcp-e2e-key-0001"
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "mcp-e2e-talon-key", agentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	port := freePort(t)
	stop := startServeWithEnv(t, dir, port, nil, "--proxy-config", proxyCfg)
	defer stop()
	c := &mcpClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port), key: agentKey}

	// 1. server/discover on both routes.
	for _, path := range []string{"/mcp", "/mcp/proxy"} {
		st, _, out := c.post(path, "server/discover", "", `{"jsonrpc":"2.0","id":"d1","method":"server/discover","params":{`+mcpMeta+`}}`, nil)
		res, _ := out["result"].(map[string]any)
		if st != 200 || res == nil {
			t.Fatalf("%s discover: %d %v", path, st, out)
		}
		if sv, _ := res["supportedVersions"].([]any); len(sv) != 1 || sv[0] != "2026-07-28" {
			t.Fatalf("%s supportedVersions: %v", path, res["supportedVersions"])
		}
		caps, _ := res["capabilities"].(map[string]any)
		if _, ok := caps["tools"]; !ok {
			t.Fatalf("%s: tools capability missing: %v", path, caps)
		}
		if _, ok := caps["extensions"]; ok {
			t.Fatalf("%s: no extension (Tasks) may be advertised: %v", path, caps)
		}
		if res["resultType"] != "complete" || res["cacheScope"] == nil || res["ttlMs"] == nil {
			t.Fatalf("%s discover shape: %v", path, res)
		}
	}

	// 2. tools/list through the proxy: filtered, deterministic, hints.
	st, _, out := c.post("/mcp/proxy", "tools/list", "", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+mcpMeta+`}}`, nil)
	res, _ := out["result"].(map[string]any)
	if st != 200 || res == nil {
		t.Fatalf("tools/list: %d %v", st, out)
	}
	var names []string
	for _, tl := range res["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	want := []string{"ticket_lookup", "zeta_tool"}
	if !sort.StringsAreSorted(names) || strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("tools/list names = %v, want %v (deterministic, forbidden excluded)", names, want)
	}
	if res["ttlMs"] != float64(30000) || res["cacheScope"] != "private" {
		t.Fatalf("cache hints: ttlMs=%v cacheScope=%v", res["ttlMs"], res["cacheScope"])
	}
	// Native route lists too (empty registry in a scaffolded install is fine).
	if st, _, out := c.post("/mcp", "tools/list", "", `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{`+mcpMeta+`}}`, nil); st != 200 || out["result"] == nil {
		t.Fatalf("native tools/list: %d %v", st, out)
	}

	// 3. Valid governed call: exactly one upstream dispatch with generated headers.
	call := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{` + mcpMeta + `,"name":"ticket_lookup","arguments":{"region":"eu-west1","ticket":"T-1"},"requestState":"rs-1"}}`
	var hdr http.Header
	st, hdr, out = c.post("/mcp/proxy", "tools/call", "ticket_lookup", call, map[string]string{"Mcp-Param-Region": "eu-west1", "Mcp-Session-Id": "legacy"})
	if st != 200 || out["result"] == nil {
		t.Fatalf("tools/call: %d %v", st, out)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls.Load())
	}
	if up.headers.Get("MCP-Protocol-Version") != "2026-07-28" || up.headers.Get("Mcp-Method") != "tools/call" || up.headers.Get("Mcp-Name") != "ticket_lookup" || up.headers.Get("Mcp-Param-Region") != "eu-west1" {
		t.Fatalf("outbound headers not generated from the authorized body: %v", up.headers)
	}
	if up.headers.Get("Mcp-Session-Id") != "" || hdr.Get("Mcp-Session-Id") != "" {
		t.Fatal("no MCP session may be forwarded or minted")
	}
	if up.body["requestState"] != "rs-1" {
		t.Fatalf("requestState lost on forward: %v", up.body)
	}
	if meta, _ := up.body["_meta"].(map[string]any); meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
		t.Fatalf("outbound _meta: %v", up.body["_meta"])
	}
	if out["result"].(map[string]any)["resultType"] != "complete" {
		t.Fatalf("result shape: %v", out["result"])
	}

	// 4. Mcp-Name says ticket_lookup, body says delete_customer: integrity failure, zero dispatch.
	smuggle := strings.Replace(call, `"name":"ticket_lookup"`, `"name":"delete_customer"`, 1)
	st, _, out = c.post("/mcp/proxy", "tools/call", "ticket_lookup", smuggle, map[string]string{"Mcp-Param-Region": "eu-west1"})
	if st != 400 || mcpErrCode(out) != -32020 {
		t.Fatalf("name mismatch: %d %v", st, out)
	}
	// Mcp-Param mismatch: integrity failure, zero dispatch.
	st, _, out = c.post("/mcp/proxy", "tools/call", "ticket_lookup", call, map[string]string{"Mcp-Param-Region": "us-east1"})
	if st != 400 || mcpErrCode(out) != -32020 {
		t.Fatalf("param mismatch: %d %v", st, out)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("integrity failures dispatched: upstream calls = %d", up.calls.Load())
	}

	// 5. Legacy initialize (no headers, no _meta): rejected with a modern error.
	legacy := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`
	for _, path := range []string{"/mcp", "/mcp/proxy"} {
		st, hdr, out := c.post(path, "", "", legacy, map[string]string{"Mcp-Session-Id": "legacy"})
		if st != 400 || out["error"] == nil {
			t.Fatalf("%s legacy initialize must be rejected: %d %v", path, st, out)
		}
		if hdr.Get("Mcp-Session-Id") != "" {
			t.Fatalf("%s minted a session", path)
		}
		if strings.Contains(fmt.Sprint(out["result"]), "2025") {
			t.Fatalf("%s echoed a legacy version", path)
		}
		// Modern-looking initialize is simply not a method.
		if st, _, out := c.post(path, "initialize", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{`+mcpMeta+`}}`, nil); st != 404 || mcpErrCode(out) != -32601 {
			t.Fatalf("%s initialize under 2026-07-28: %d %v", path, st, out)
		}
		// Legacy session transport.
		for _, m := range []string{http.MethodGet, http.MethodDelete} {
			req, _ := http.NewRequest(m, c.base+path, nil)
			req.Header.Set("Authorization", "Bearer "+c.key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s = %d, want 405", m, path, resp.StatusCode)
			}
		}
		// Notification: 202, no body.
		req, _ := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+c.key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted || len(raw) != 0 {
			t.Fatalf("%s notification: %d %q", path, resp.StatusCode, raw)
		}
	}
	if up.calls.Load() != 1 {
		t.Fatalf("legacy traffic reached the upstream: %d", up.calls.Load())
	}

	// 6. A governed denial on a VALID request is still a Talon denial with
	// evidence semantics: forbidden tool → -32000 + talon_code, zero upstream.
	deny := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{` + mcpMeta + `,"name":"delete_customer","arguments":{}}}`
	st, _, out = c.post("/mcp/proxy", "tools/call", "delete_customer", deny, nil)
	if st != 200 || mcpErrCode(out) != -32000 {
		t.Fatalf("forbidden tool: %d %v", st, out)
	}
	if data, _ := out["error"].(map[string]any)["data"].(map[string]any); data["talon_code"] != "TALON_TOOL_FORBIDDEN" {
		t.Fatalf("talon_code: %v", out["error"])
	}
	if up.calls.Load() != 1 {
		t.Fatalf("forbidden tool dispatched: %d", up.calls.Load())
	}
}

// Command crm-mcp-server is a synthetic CRM exposed as a real MCP server
// (the official Go SDK, protocol 2026-07-28, stateless Streamable HTTP) for
// the governed-MCP adoption example (#431). It is the business system Talon
// protects: it requires its own bearer token (which only Talon holds, in its
// vault), and it counts every tools/call it actually executes, so "nothing
// was sent" and "sent exactly once" are this server's own numbers, not
// Talon's.
//
//	CRM_MCP_ADDR   listen address (default 127.0.0.1:9180; loopback only)
//	CRM_MCP_TOKEN  the bearer token Talon must present (required)
//
//	POST /mcp      the MCP endpoint
//	GET  /calls    {"ticket.lookup":1,"voucher.issue":0,...} — executed calls
//	GET  /health   200 when serving
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type counters struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *counters) inc(tool string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n[tool]++
}

func (c *counters) snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.n))
	for k, v := range c.n {
		out[k] = v
	}
	return out
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func num(desc string) map[string]any { return map[string]any{"type": "number", "description": desc} }

// tool is one synthetic CRM operation.
type tool struct {
	name, title, desc string
	props             map[string]any
	required          []string
	answer            func(args map[string]any) string
}

func tools() []tool {
	return []tool{
		{
			"ticket.lookup", "Look up a ticket", "Read a support ticket (no side effect).",
			map[string]any{"ticket_id": str("ticket id, e.g. T-100")},
			[]string{"ticket_id"},
			func(a map[string]any) string {
				return fmt.Sprintf("ticket %v: open, customer c-42, order o-7781", a["ticket_id"])
			},
		},
		{
			"voucher.issue", "Issue a voucher", "Issue a goodwill voucher to the ticket's customer.",
			map[string]any{"ticket_id": str("ticket id"), "amount": num("voucher amount in EUR")},
			[]string{"ticket_id", "amount"},
			func(a map[string]any) string {
				return fmt.Sprintf("voucher of %v EUR issued for %v", a["amount"], a["ticket_id"])
			},
		},
		{
			"refund.create", "Create a refund", "Refund the ticket's order.",
			map[string]any{"ticket_id": str("ticket id"), "amount": num("refund amount in EUR")},
			[]string{"ticket_id", "amount"},
			func(a map[string]any) string {
				return fmt.Sprintf("refund of %v EUR created for %v", a["amount"], a["ticket_id"])
			},
		},
		{
			"customer.delete", "Delete a customer", "Delete a customer and all their data.",
			map[string]any{"customer_id": str("customer id")},
			[]string{"customer_id"},
			func(a map[string]any) string { return fmt.Sprintf("customer %v deleted", a["customer_id"]) },
		},
	}
}

func main() {
	addr := envOr("CRM_MCP_ADDR", "127.0.0.1:9180")
	token := os.Getenv("CRM_MCP_TOKEN")
	if token == "" {
		log.Fatal("CRM_MCP_TOKEN is required: the token Talon presents (talon secrets set crm-mcp-token ...)")
	}
	if host, _, err := net.SplitHostPort(addr); err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		log.Fatalf("CRM_MCP_ADDR %q: this synthetic server binds to loopback only", addr)
	}
	calls := &counters{n: map[string]int{}}
	srv := sdk.NewServer(&sdk.Implementation{Name: "synthetic-crm", Version: "1.0.0"}, &sdk.ServerOptions{
		SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs, c.CacheScope = 600000, "private" },
	})
	for _, tl := range tools() {
		tl := tl
		calls.n[tl.name] = 0
		srv.AddTool(&sdk.Tool{
			Name: tl.name, Title: tl.title, Description: tl.desc,
			InputSchema: map[string]any{"type": "object", "properties": tl.props, "required": tl.required, "additionalProperties": false},
		}, func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			calls.inc(tl.name)
			var args map[string]any
			_ = json.Unmarshal(req.Params.Arguments, &args)
			log.Printf("EXECUTED %s %s", tl.name, string(req.Params.Arguments))
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: tl.answer(args)}}}, nil
		})
	}
	mcpHandler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, &sdk.StreamableHTTPOptions{Stateless: true})

	mux := http.NewServeMux()
	mux.Handle("/mcp", requireToken(token, mcpHandler))
	mux.HandleFunc("/calls", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(calls.snapshot()) // map keys are encoded sorted
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	log.Printf("synthetic CRM MCP server on http://%s/mcp", addr)
	s := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(s.ListenAndServe())
}

// requireToken refuses any MCP request without the CRM's own token: only
// Talon, which reads it from its vault per attempt, can reach the tools.
func requireToken(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

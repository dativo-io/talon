// Command mcp-client is a STANDARD MCP client — the official Go SDK client,
// unmodified, protocol 2026-07-28 — used by the governed-MCP adoption
// example (#431) to show that an application needs no Talon-specific SDK:
// it connects to Talon's POST /mcp with the AI use case's key, exactly as it
// would connect to any remote MCP server that requires a bearer token.
//
//	TALON_MCP_URL        http://127.0.0.1:8080/mcp (default)
//	TALON_USE_CASE_KEY   the AI use case's key (required)
//
//	mcp-client list
//	mcp-client call <tool> '<json arguments>'
//	mcp-client execute <operation_id>        (calls talon_execute_operation)
//
// Each command prints the tool result's text, its structured content and
// Talon's governance answer (code, operation id, approval id) as plain
// KEY=VALUE lines, so a person or a script can follow the flow. Talon's
// refusals arrive as standard JSON-RPC errors carrying the same governance
// object; they are printed the same way and exit with status 2.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const governanceKey = "io.dativo.talon/governance"

type bearer struct{ key string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.key)
	return http.DefaultTransport.RoundTrip(r)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	key := os.Getenv("TALON_USE_CASE_KEY")
	if key == "" {
		fail("TALON_USE_CASE_KEY is required (the AI use case's key; the admin key is refused by /mcp)")
	}
	url := os.Getenv("TALON_MCP_URL")
	if url == "" {
		url = "http://127.0.0.1:8080/mcp"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "talon-example-mcp-client", Version: "1.0.0"}, nil)
	cs, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:   url,
		HTTPClient: &http.Client{Transport: bearer{key: key}, Timeout: 30 * time.Second},
		MaxRetries: -1,
	}, nil)
	if err != nil {
		fail("connect to " + url + ": " + err.Error())
	}
	defer func() { _ = cs.Close() }()

	switch os.Args[1] {
	case "list":
		res, err := cs.ListTools(ctx, &sdk.ListToolsParams{})
		if err != nil {
			fail("tools/list: " + err.Error())
		}
		for _, t := range res.Tools {
			ro := ""
			if t.Annotations != nil && t.Annotations.ReadOnlyHint {
				ro = " (read-only)"
			}
			fmt.Printf("TOOL=%s%s\n", t.Name, ro)
		}
	case "call":
		if len(os.Args) != 4 {
			usage()
		}
		var args map[string]any
		if err := json.Unmarshal([]byte(os.Args[3]), &args); err != nil {
			fail("arguments must be a JSON object: " + err.Error())
		}
		report(cs.CallTool(ctx, &sdk.CallToolParams{Name: os.Args[2], Arguments: args}))
	case "execute":
		if len(os.Args) != 3 {
			usage()
		}
		report(cs.CallTool(ctx, &sdk.CallToolParams{Name: "talon_execute_operation", Arguments: map[string]any{"operation_id": os.Args[2]}}))
	default:
		usage()
	}
}

// report prints a result or a Talon refusal as KEY=VALUE lines.
func report(res *sdk.CallToolResult, err error) {
	if err != nil {
		var werr *jsonrpc.Error
		if !errors.As(err, &werr) {
			fail(err.Error())
		}
		var data map[string]any
		_ = json.Unmarshal(werr.Data, &data)
		fmt.Printf("REFUSED=%s\n", werr.Message)
		governance(data[governanceKey])
		os.Exit(2)
	}
	for _, c := range res.Content {
		if t, ok := c.(*sdk.TextContent); ok {
			fmt.Printf("TEXT=%s\n", t.Text)
		}
	}
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		fmt.Printf("STRUCTURED=%s\n", b)
	}
	if res.IsError {
		fmt.Println("IS_ERROR=true")
	}
	governance(res.Meta[governanceKey])
}

func governance(v any) {
	g, _ := v.(map[string]any)
	for _, k := range []string{"code", "decision", "provenance", "operationId", "approvalId"} {
		if s, ok := g[k].(string); ok && s != "" {
			fmt.Printf("TALON_%s=%s\n", k, s)
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mcp-client list | call <tool> '<json>' | execute <operation_id>")
	os.Exit(64)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "mcp-client: "+msg)
	os.Exit(1)
}

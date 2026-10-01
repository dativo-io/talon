# MCP Proxy Minimal Example

The smallest working Talon MCP proxy. Governs vendor AI tool calls with PII
scanning, tool filtering, and evidence logging. Governed calls are always
intercepted (#442): allowed tools are forwarded with PII redacted per the
rules, forbidden tools are blocked and never forwarded, and every call lands
in signed evidence.

## Setup

```bash
# 1. Build Talon
make build

# 2. Start the proxy
bash examples/mcp-proxy-minimal/run.sh
```

## Use

Point your vendor AI (Zendesk, Intercom, etc.) at Talon's MCP proxy endpoint:

```
http://localhost:8080/mcp/proxy
```

Talon intercepts all MCP tool calls, scans for PII, checks against
allowed/forbidden tool lists, and generates evidence records. The proxy
speaks **MCP protocol version `2026-07-28` only**: no `initialize`
handshake, no MCP session — every request carries `MCP-Protocol-Version`,
`Mcp-Method` (and `Mcp-Name` for `tools/call`) and `params._meta`. It
serves `server/discover`, `tools/list` and `tools/call`; any other MCP
method (`resources/read`, `prompts/get`, …) is a protocol `-32601` /
HTTP 404, never forwarded. Use a 2026-07-28 MCP client or SDK.

```bash
curl -s -X POST http://localhost:8080/mcp/proxy \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" -H "Mcp-Method: server/discover" \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

## What's in the Config

```yaml
proxy:
  upstream:
    url: "http://vendor:9091/mcp"
  allowed_tools:             # name -> optional upstream_name mapping
    - name: ticket_search
    - name: ticket_create
  forbidden_tools:
    - user_delete
    - "admin_*"              # Trailing-* patterns supported

pii_handling:                # top-level, NOT under proxy:
  redaction_rules:
    - field: email
      method: hash
```

## Check the Audit Trail

```bash
bin/talon audit list
# Shows: tool calls with PII findings, allowed/forbidden decisions
```

## Next Steps

- Narrow `allowed_tools` once the evidence shows which tools the vendor
  actually needs (a tool on neither list is rejected)
- Add more redaction rules for your specific vendor's data fields
- See `examples/vendor-proxy/` for a full Zendesk integration example

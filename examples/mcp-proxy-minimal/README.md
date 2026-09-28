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
speaks the MCP lifecycle (`initialize` answered locally, never forwarded;
`notifications/initialized` accepted) and governs `tools/list` and
`tools/call` — any other MCP method (`resources/read`, `prompts/get`, …)
is rejected fail-closed with `error.data.talon_code:
TALON_METHOD_NOT_ALLOWED` and an evidence record, never forwarded
ungoverned.

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

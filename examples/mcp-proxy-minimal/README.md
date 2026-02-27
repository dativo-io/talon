# MCP Proxy Minimal Example

The smallest working Talon MCP proxy. Audits vendor AI tool calls with PII
scanning, tool filtering, and evidence logging. Shadow mode: logs everything,
blocks nothing.

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
allowed/forbidden tool lists, and generates evidence records.

## What's in the Config

```yaml
proxy:
  mode: shadow               # Audit only
  upstream:
    url: "http://vendor:9091/mcp"
  allowed_tools:
    - "ticket_search"
    - "ticket_create"
  forbidden_tools:
    - "user_delete"
    - "admin_*"              # Glob patterns supported
  pii_handling:
    redaction_rules:
      - field: "email"
        method: hash
```

## Check the Audit Trail

```bash
bin/talon audit list
# Shows: tool calls with PII findings, allowed/forbidden decisions
```

## Next Steps

- Switch to `mode: intercept` to block forbidden tool calls
- Add more redaction rules for your specific vendor's data fields
- See `examples/vendor-proxy/` for a full Zendesk integration example

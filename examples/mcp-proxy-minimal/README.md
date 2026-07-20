# MCP Proxy Minimal Example

The smallest working Talon MCP proxy. Audits vendor AI tool calls with PII
scanning, tool filtering, and evidence logging. Shadow mode: audits everything
and forwards; would-be policy denials are recorded in signed evidence, and
explicitly forbidden tools are still blocked (they are never forwarded outside
`passthrough` mode).

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
governs `tools/list` and `tools/call` only — any other MCP method
(`resources/read`, `prompts/get`, …) is rejected fail-closed with an
evidence record, never forwarded ungoverned.

## What's in the Config

```yaml
proxy:
  mode: shadow               # Audit; forbidden tools still blocked
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

- Switch to `mode: intercept` to also block policy and PII violations
  (forbidden tools are blocked in shadow mode already)
- Add more redaction rules for your specific vendor's data fields
- See `examples/vendor-proxy/` for a full Zendesk integration example

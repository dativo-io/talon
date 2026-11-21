# Governed MCP tools

One AI use case whose consequential tools live in an MCP server (here a CRM),
governed by Talon's Action Gateway through `POST /mcp` (#431). The MCP server
is a **trusted action source**; the MCP client never talks to it directly.

```bash
make build
talon secrets set support-assistant-talon-key "$(openssl rand -hex 24)"
talon secrets set crm-mcp-token "<token>" --tenant default --agent support-assistant
talon serve   # in this directory: POST /mcp on :8080
```

Point the MCP client at `http://127.0.0.1:8080/mcp` with
`Authorization: Bearer <support-assistant-talon-key>`.

| Tool | What happens |
|---|---|
| `lookup_ticket` (read-only) | one `tools/call`, executed when policy allows |
| `issue_voucher` | first call **prepares** (operation id, nothing sent); `talon_execute_operation` executes it once |
| `create_refund` above 50.00 | prepared, waits for a reviewer (`talon approvals approve`); executed by the next `talon_execute_operation` |
| `delete_customer` | not listed; called directly it is denied, the CRM receives nothing |

Every operation verifies with `talon audit verify --operation <operation_id>`.
Full guide: [governed MCP tools](../../docs/guides/mcp-governed-tools.md).

# Migrate existing integrations to MCP `2026-07-28`

**Audience:** teams upgrading an existing MCP integration. The MCP proxy (`/mcp/proxy`, `--proxy-config`) is removed (#431): its integrations move to the governed `POST /mcp` with [Governed MCP tools](mcp-governed-tools.md), which has the migration table. These are breaking changes on Talon main; check the [latest release](https://github.com/dativo-io/talon/releases/latest) before assuming a tagged binary includes them.

## What changed

| Old assumption | Supported contract now |
|---|---|
| `initialize` / `initialized` negotiation and older MCP versions | **Only `2026-07-28`**; `server/discover` replaces initialization and every request carries protocol metadata |
| Former MCP transport-session header, GET/DELETE lifecycle or stream resumption | **Removed and not supported.** Optional `X-Talon-Session-ID` is *application correlation* only, never MCP protocol state |
| Header-free `tools/call` | `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (for calls) and matching request-body `_meta` are required |
| Historical non-enforcing gateway/MCP/native runtime postures (removed in #442): `shadow`, `log_only`, `passthrough`, `audit.observation_only` | Active rules always enforce. Use `talon doctor`, `talon validate` and native `talon run --dry-run` before live rollout |
| Parse `error.data.talon_code` as a durable policy contract | Use versioned `io.dativo.talon/governance` extension; the flat alias is deprecated for one release |
| Treat all JSON-RPC errors as policy denials | Protocol failures have MCP-native codes and **no** governance extension or signed policy evidence |

## Upgrade checklist

1. **Upgrade the MCP client SDK.** Require a client that implements the `2026-07-28` wire. An old `initialize` request cannot be rescued with configuration. Confirm `server/discover` and `tools/list` work first.
2. **Remove obsolete configuration (migration from #442).** Delete `gateway.mode`, agent `audit.observation_only`, `tool_policies.*.schema_validation` and old `talon serve --gateway-mode` or `talon enforce` automation. Removed keys are rejected at load; there is no silent compatibility path. An MCP proxy config (with its former `proxy.mode`) is no longer read at all: `--proxy-config` is refused with a migration message (#431).
3. **Start with safe, deliberately permissive active policy**, then tighten one rule at a time in staging. A real denial causes **zero** upstream dispatch. Use `talon doctor` and `talon validate` before sending requests.
4. **Send the new protocol headers and metadata** on every request. `Mcp-Method` must match the JSON-RPC method; `Mcp-Name` must match `params.name` for `tools/call`. Header-annotated parameters (`Mcp-Param-*`) must agree with arguments where the tool schema declares them.
5. **Consume structured outcomes.** An allowed governed call has `result._meta["io.dativo.talon/governance"]`; a governance denial or Talon-shaped failure has `error.data["io.dativo.talon/governance"]`. Check `decision`, stable `code`, `retryable`, `provenance` and `evidence.committed`; do not treat a bare evidence ID as proof.
6. **Handle unknown effects conservatively.** `upstream_outcome_unknown` means a request may have reached the upstream: do not blindly replay it. Vendor JSON-RPC error messages/data are sanitized in the public envelope; do not depend on the former vendor body.
7. **Keep boundary expectations explicit.** A `tools/call` on `POST /mcp` to an MCP server declared as the use case's action source is an Action Gateway operation (#431): bound approval and at most one `talon_forwarded` dispatch. A consequential tool is first prepared (nothing is sent) and then executed with `talon_execute_operation`; a tool error after dispatch is `unknown`, never retried. Tools a client reaches without going through Talon are not governed. Tasks approval continuation is not advertised.

## Example: one current-protocol tool call

~~~bash
curl -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: lookup_ticket' \
  -H 'Authorization: Bearer <the use case key>' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"upgrade-check","version":"1.0"},"io.modelcontextprotocol/clientCapabilities":{}},"name":"lookup_ticket","arguments":{"ticket_id":"T-1"}}}'
~~~

The example requires the AI use case's key and an action definition with that canonical name on a declared MCP action source (`lookup_ticket` is the read-only action of the [governed MCP guide](mcp-governed-tools.md), so an allowed call executes once). An unknown tool is a protocol invalid-params error, not a policy-denial receipt. `/mcp` does not synthesize missing identities, and the admin key is refused.

## Verify the contract without provider keys

From a checkout of Talon main:

~~~bash
make test-mcp-smoke
make test-mcp-governance-smoke
~~~

The first checks discovery, calls, wire integrity and old-client rejection. The second checks allowed and denied outcomes, signed committed evidence and an ambiguous upstream effect against a built binary and mock. See the [MCP governance extension reference](../reference/mcp-governance-extension.md), [Governed MCP tools](mcp-governed-tools.md), and [limitations](../../LIMITATIONS.md).

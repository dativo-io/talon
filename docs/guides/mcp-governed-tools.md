# Governed MCP tools

Talon governs the consequential tools of an MCP server through **one governed MCP endpoint, `POST /mcp`** (MCP protocol `2026-07-28`). The MCP server is a **trusted action source** of an AI use case; an MCP client (Claude Code, an agent framework, an automation) talks to Talon, never to the MCP server. Every `tools/call` is an operation of the **Action Gateway**: the same company policy, approvals, at-most-once dispatch, `unknown` outcome handling, recovery hold and signed lifecycle evidence as [`/v1/action-operations`](../reference/action-gateway.md). There is no second execution or approval engine (#431).

What this does **not** cover: tools a client reaches without going through Talon (local shell, files, browsers, other MCP servers configured in the client), and actions that bypass Talon entirely. See [LIMITATIONS](../../LIMITATIONS.md).

## 1. Declare the MCP server and its tools

In the AI use case's `agent.talon.yaml`:

```yaml
agent:
  name: support-assistant
  key:
    secret_name: support-assistant-talon-key   # the use case's key: the only identity on /mcp

capabilities:
  forbidden_tools: [delete_customer]          # never listed, denied with zero calls

actions:
  sources:
    crm:
      type: mcp
      url: "https://crm.example.com/mcp"      # https, or http on loopback only
      auth:
        secret_name: crm-mcp-token            # vault entry, read per attempt under the use case's ACL
  definitions:
    lookup_ticket:                            # canonical Talon name (what the client calls)
      source: crm
      upstream_name: ticket.lookup            # the tool's name at the source
      read_only: true                         # trusted overlay: one call when allowed
      review: {fields: [ticket_id]}
    create_refund:
      source: crm
      upstream_name: refund.create
      review: {fields: [ticket_id, amount]}
```

- Talon discovers the source's tools (`server/discover`, `tools/list`) when the runtime generation is built and on its cache TTL. The schema comes from the source and is closed (`additionalProperties: false`); everything with authority (name, review fields, `read_only`, destination) comes from Talon's configuration. A schema change at the source is a new definition: a pending approval for the old one cannot be claimed (`approval_binding_stale`).
- Only tools mapped under `actions.definitions` exist for the client. A source's own annotations (`readOnlyHint`, `destructiveHint`) never decide anything; `read_only` is Talon's.
- Company constraints (`gateway.organization_policy`: forbidden actions, approval rules, argument rules) apply as to any action, and a use case cannot lift them.

`talon actions list` shows the catalog with each action's verdict; `talon validate` checks the file offline (sources are not contacted).

## 2. Connect the MCP client

| Setting | Value |
|---|---|
| Endpoint | `http://127.0.0.1:8080/mcp` (behind a TLS-terminating proxy for other hosts) |
| Authorization | `Bearer <the use case's key>` — the admin key is refused |
| Protocol | `2026-07-28` (no `initialize`, no session; every request carries `MCP-Protocol-Version` and `_meta`) |

`tools/list` returns the use case's governed tools under their canonical names, plus **`talon_execute_operation`**. A forbidden tool is not listed; listing authorizes nothing.

## 3. What a `tools/call` does

| Tool | First call | Then |
|---|---|---|
| read-only, allowed | executes once, returns the source's result | — |
| consequential, allowed | **prepares**: Talon establishes an operation bound to the use case, the tool and the canonical arguments, and returns its `operationId`. **Nothing is sent.** | `talon_execute_operation {"operation_id": …}` executes it, at most once |
| approval required | prepares; the result names the approval | a reviewer decides (`talon approvals approve`); the decision dispatches nothing; the next `talon_execute_operation` executes once |
| denied (policy or forbidden) | `policy_denied`, signed evidence, **zero calls** | — |

The prepared answer is a normal tool result (text plus `structuredContent` with `operationId`, `status`, `approvalId`, and the next call), so an unmodified client shows it to the model, which calls `talon_execute_operation`. Talon generates the operation id; it is never derived from the arguments or invented by the model.

**Repeat and concurrency.** `talon_execute_operation` on a succeeded operation returns `operation_already_succeeded` and sends nothing; concurrent executes of one operation send one request. Calling the original tool again prepares a *new* operation: each prepared operation is a separate action.

**Advanced clients** may send their own stable id: `params._meta["io.dativo.talon/operationId"]`. The call then executes in one step when allowed; a retry with the same id and arguments resolves the same operation (never a second dispatch), and changed arguments under that id are `operation_conflict`.

## 4. Outcomes

| Situation | Answer | Operation |
|---|---|---|
| the source answered a complete result without `isError` | the source's result, `_meta["io.dativo.talon/governance"].code = "allowed"`, provenance `observed` | `succeeded` |
| the request never left Talon (credential unavailable, source unreachable) | `upstream_auth_unavailable` / `upstream_tool_failed`, provenance `not_dispatched` | `failed`: `talon_execute_operation` may try again, with the same idempotency identity |
| anything else after the request was written: `isError: true`, a JSON-RPC error, `input_required`, a task, a malformed or lost answer, a timeout | `upstream_outcome_unknown`, provenance `unknown`, not retryable | `unknown`: never re-sent; reconcile with the source |
| any later execute of an unknown operation | `operation_outcome_unknown` | unchanged |

A tool-reported error after dispatch is **unknown, not failed**: the source may have done part of the work. The source's error text is never relayed to the client and never signed; the record keeps the JSON-RPC code and category (`upstream_jsonrpc_error: code=<n> category=<c>`), and the operator log line `mcp_action_outcome_unknown` carries only the typed outcome and the digest of the answer — reconcile with the source's own logs.

A result is a success only when it is a structurally valid `CallToolResult`: `resultType: "complete"`, a `content` array of valid blocks, `isError` a JSON boolean when present, `structuredContent` an object when present. Anything else after dispatch (a string `isError`, missing `content`, an unknown block type) is `unknown`. The client receives Talon's normalized copy: Talon's `serverInfo`, the source's under `io.dativo.talon/upstreamServerInfo`, and no other source `_meta` keys (vendor metadata and anything in Talon's namespace are dropped).

Talon sends one operation-scoped idempotency identity with every attempt: `_meta["io.dativo.talon/idempotencyKey"]` and the `Idempotency-Key` header, plus `io.dativo.talon/operationRef` and `io.dativo.talon/attemptId`. A source that deduplicates on it turns a safe retry into a no-op; Talon does not rely on it.

## 5. PII

The use case's effective company policy applies (the organization's `pii_action` / `response_pii_action`, which a use case can only tighten):

- **arguments**, before anything is bound: `block` refuses with zero calls and signed evidence; `redact` binds the redacted arguments, so the approval covers and Talon sends exactly what was redacted; `warn` and `allow` pass them.
- **results**: everything forwarded is scanned as one document, `_meta` included; `redact` redacts the result returned to the client; `block` withholds it (the action itself was executed: provenance `observed`, the operation stays `succeeded`).

The company baseline is the `gateway.organization_policy` of the gateway config file (`--gateway-config`, `TALON_GATEWAY_CONFIG`, else `talon.config.yaml`), in every serve mode: a native `talon serve` with no LLM gateway applies it to `/mcp` exactly as a gateway serve does, and records which file it read so the console can prove it.

A scanner failure fails closed.

## 6. Sessions and correlation

A client may send `X-Talon-Session-ID`, `X-Correlation-ID` and the orchestration headers (`X-Talon-Agent-ID`, `X-Talon-Parent-Agent-ID`, `X-Talon-Client`). Talon validates their shape (malformed: HTTP 400, nothing evaluated) and links them to the operation when it is **established**, as untrusted attribution: every lifecycle record of that operation carries the session id (the console's session pages and `talon audit list --session`), the orchestration identity, and the client's correlation id (`action_lifecycle.client_correlation_id`). The record's own correlation id stays the operation reference. Attribution is never authentication, never part of the digest, and a later call cannot change it. The asserted ids are echoed in the response headers.

## 7. Evidence and investigation

```bash
talon audit list --agent support-assistant
talon audit verify --operation <operation_id>    # every record's signature and the lifecycle: Lifecycle: VALID
talon approvals list                              # as a reviewer
```

The console shows the operations under the use case and the session; its System page shows the **MCP endpoint** of each `talon serve` (running, stale, offline, or not configured when no use case declares an MCP source). A restore holds dispatch on `/mcp` as on `/v1/action-operations` (`recovery_hold`).

## 8. Migrating from the MCP proxy (`--proxy-config`, `/mcp/proxy`)

The MCP proxy is removed. `talon serve --proxy-config`, `talon ui serve --proxy-config` and `talon agents show --proxy-config` refuse with a migration message.

| Proxy config | Governed MCP |
|---|---|
| `agent.name` | the AI use case (`agent.talon.yaml`) whose key the client presents |
| `proxy.upstream.url`, `.auth` | `actions.sources.<id>.url`, `.auth` (same `secret_name` / `header` / `scheme` contract) |
| `proxy.allowed_tools[]` (`name`, `upstream_name`) | one `actions.definitions.<name>` per tool (`source`, `upstream_name`, `review`; `read_only` for tools without a side effect) |
| `proxy.forbidden_tools` | `capabilities.forbidden_tools`, or a company constraint |
| `pii_handling.redaction_rules` | the company `pii_action` / `response_pii_action` |
| `rate_limits`, `compliance` | not carried (they were parsed but not enforced) |
| `POST /mcp/proxy` | `POST /mcp` with the use case's key |

Behaviour that changes: a consequential tool is prepared and then executed by `talon_execute_operation` (unless read-only, or the client sends its own operation id); a vendor error after dispatch is `unknown`, not `failed`; records are `action_lifecycle` operations instead of `proxy_*` records (earlier `proxy_*` records stay readable and verifiable).

## Verify

```bash
go test ./internal/action/ -run 'TestMCP'
go test ./internal/mcp/
make test-mcp-smoke test-mcp-governance-smoke
```

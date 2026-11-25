# How to choose your integration path

Use this guide to pick a real enforcement boundary: model API gateway, HTTP Action Gateway, governed MCP endpoint, native Talon runtime, or delegated enforcement through OpenShell. These are different execution surfaces with different guarantees.

---

## Decision table

| Your situation | Talon path | Auth | Where to go next |
|----------------|------------|------|-------------------|
| **An MCP client calls consequential tools of an MCP server** (CRM, ticketing, internal tools) | Governed MCP endpoint `POST /mcp`: the MCP server is a trusted action source of the use case; every `tools/call` is an Action Gateway operation (company policy, approvals, at most one dispatch, signed lifecycle evidence); `tools/list` lists only the use case's governed tools | The use case's agent key (`Authorization: Bearer <agent-key-value>`); the admin key is refused | [Governed MCP tools](mcp-governed-tools.md) |
| **Your app calls LLM APIs** (an OpenAI or Anthropic SDK app, n8n AI nodes, Slack bot, desktop app, OpenClaw, CoPaw, script) | LLM API gateway at `POST /v1/proxy/{provider}/v1/...`. Response-path PII scanning, kill switch, tool-aware redaction | Agent key (`Authorization: Bearer <agent key>`) | [Connect an existing application](add-talon-to-existing-app.md) (including [n8n](add-talon-to-existing-app.md#n8n)), [OpenClaw](openclaw-integration.md), [CoPaw](copaw-integration.md), [Slack bot](slack-bot-integration.md), [Desktop apps](desktop-app-governance.md) |
| **Consequential HTTP business action** (refund, publish, mutation, including from an n8n workflow) | HTTP Action Gateway (`POST /v1/action-operations`, `/v1/approvals`) — immutable exact payload, authenticated reviewer decision and at-most-once Talon-forwarded HTTP attempt | Agent key for the action operation; separate tenant-scoped approver principal for decisions | [Action Gateway](../reference/action-gateway.md), [n8n refund approvals](n8n-refund-approvals.md) |
| **Contained agent in OpenShell** | OpenShell delegates model-policy decisions at `HTTP_REQUEST / PRE_CREDENTIALS`; optional `HTTP_RESPONSE / PRE_RETURN` governance observes usage and applies response policy; a verified sandbox hop can reach Talon's own HTTP Action Gateway | OpenShell-issued gateway-signed token verified by Talon; action hop uses short-lived, request-bound workload assertion (no Talon secret in sandbox) | [OpenShell integration](../integration/openshell.md) |
| **New agent from scratch** | Native Talon (`talon run`, `POST /v1/agents/run`, `POST /v1/chat/completions`) | Agent key (`Authorization: Bearer <agent-key-value>`) | [Your first governed agent](../tutorials/first-governed-agent.md), [QUICKSTART](../QUICKSTART.md) |

---

These paths are ways to connect **one AI use case** (one `agent.talon.yaml`, one identity, one Talon key), not kinds of application: a use case registered with `talon agents add` can use the LLM gateway, the Action Gateway and the governed MCP endpoint with the same key. `talon agents show <name> --effective` reports per boundary whether an authenticated request of the use case has been observed there.

## In short

- **HTTP Action Gateway** — Binds the exact operation identity, normalized payload and trusted destination. The runtime establishes the operation and later claims an attempt; an authorized approver can decide without dispatching it. MCP-discovered action definitions execute on the same spine through the governed MCP endpoint (#431).
- **OpenShell** — The runtime contains the agent, holds provider credentials and enforces model-traffic decisions returned by Talon's middleware. Talon signs request decisions as `delegated_expected`, **not** proof the runtime honored them. With opt-in `gateway.openshell.response_governance`, Talon can inspect supported provider responses, enforce preventive output policy and settle observed usage; without it, responses and usage remain estimate-only. A separate verified sandbox-to-Action-Gateway hop governs Talon-forwarded HTTP actions, not arbitrary local effects. Talon does not observe local containment effects and does not retry/fallback on delegated model traffic. See the [validation matrix](../integration/openshell.md) before relying on an external runtime version.
- **Governed MCP endpoint** — Governs **tool-level** MCP traffic to an MCP server declared as a trusted action source of the use case (`actions.sources`, `actions.definitions`). The MCP client talks to Talon's `POST /mcp`, never to the MCP server. Every `tools/call` is an Action Gateway operation: a consequential tool is first prepared (nothing is sent) and executed with `talon_execute_operation`; a trusted read-only tool runs in one call. PII on arguments and results follows the use case's effective company policy. Every `talon serve` serves it. See [Governed MCP tools](mcp-governed-tools.md).
- **LLM API gateway** — Intercepts **request-level** LLM API traffic from your own apps. Your app changes only the base URL and presents its agent key; Talon enforces the agent's effective model and cost policy, scans responses for PII (redact/block/warn), supports tool-aware redaction per argument, provides a kill switch (programmatic via `ActiveRunTracker.Kill()`), and records evidence. Enable with `talon serve --gateway --gateway-config <path>`.
- **Native Talon** — You run agents via `talon run` or the REST API. Full policy-as-code, triggers, memory, and audit. No proxy; Talon is the agent runtime.

**MCP compatibility:** `POST /mcp` speaks `2026-07-28` only. Older handshakes (`initialize`) and protocol sessions are not supported. See the [MCP migration guide](mcp-2026-migration.md). A governed MCP call has the Action Gateway's bound-approval/at-most-once execution contract; tools a client reaches without going through Talon are not governed. **Policy posture:** there is no global shadow/log-only/observe-and-forward runtime mode; active rules are enforced (#442).

You can use **both** the governed MCP endpoint and the LLM gateway on the same server: every `talon serve` serves `POST /mcp`, and `--gateway` adds the LLM gateway.

---

## Before you start a server for any of these

The recipes linked above show the shortest command that demonstrates their path. For anything beyond an experiment on your own machine, start Talon the way [connect an existing application](add-talon-to-existing-app.md#1-prepare-talon-once) does:

- generate `TALON_SECRETS_KEY`, `TALON_SIGNING_KEY` and `TALON_ADMIN_KEY` into a file only you can read and load it into the server's environment. Without `TALON_ADMIN_KEY` the server is in development mode and its administrative endpoints accept every request;
- bind the listener: `talon serve --host 127.0.0.1 …`. Without `--host` the server listens on every network interface;
- `talon serve` does not terminate TLS. Applications on other machines reach it through a TLS-terminating proxy that forwards only the application routes;
- give secrets to `talon secrets set <name>` on stdin, never as an argument.

---

## You're done

You now know which Talon path fits your situation (governed MCP endpoint, LLM gateway, Action Gateway, or native). Pick the doc from the table above and follow it.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Register an existing application, connect it and verify it | [Connect an existing application](add-talon-to-existing-app.md) (`talon agents add`, then `talon agents show <name> --effective`) |
| Route OpenClaw or CoPaw through Talon | [OpenClaw](openclaw-integration.md), [CoPaw](copaw-integration.md) |
| Govern the consequential tools of an MCP server | [Governed MCP tools](mcp-governed-tools.md) |
| Authorize a high-impact HTTP action | [Action Gateway](../reference/action-gateway.md) |
| Govern a contained OpenShell agent | [OpenShell integration](../integration/openshell.md) |
| Build a new agent from scratch | [Your first agent with Talon](../tutorials/first-governed-agent.md) |

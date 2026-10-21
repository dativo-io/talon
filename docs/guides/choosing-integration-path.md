# How to choose your integration path

Use this guide to pick a real enforcement boundary: model API gateway, HTTP Action Gateway, MCP proxy/native tool exposure, native Talon runtime, or delegated enforcement through OpenShell. These are different execution surfaces with different guarantees.

---

## Decision table

| Your situation | Talon path | Auth | Where to go next |
|----------------|------------|------|-------------------|
| **Third-party SaaS** (Zendesk AI, Intercom, HubSpot) | MCP proxy at `POST /mcp/proxy`. Response PII scanning, `tools/list` filtering (agents only see allowed tools) | Agent key (`Authorization: Bearer <agent-key-value>`) | [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md) |
| **Your app calls LLM APIs** (Slack bot, desktop app, OpenClaw, CoPaw, script) | LLM API gateway at `POST /v1/proxy/{provider}/v1/...`. Response-path PII scanning, kill switch, tool-aware redaction | Agent key (`Authorization: Bearer <agent key>`) | [OpenClaw](openclaw-integration.md), [CoPaw](copaw-integration.md), [Slack bot](slack-bot-integration.md), [Desktop apps](desktop-app-governance.md) |
| **Consequential HTTP business action** (refund, publish, mutation) | HTTP Action Gateway (`POST /v1/action-operations`, `/v1/approvals`) — immutable exact payload, authenticated reviewer decision and at-most-once Talon-forwarded HTTP attempt | Agent key for the action operation; separate tenant-scoped approver principal for decisions | [Action Gateway](../reference/action-gateway.md) |
| **Contained agent in OpenShell** | OpenShell delegates model-policy decisions at `HTTP_REQUEST / PRE_CREDENTIALS`; optional `HTTP_RESPONSE / PRE_RETURN` governance observes usage and applies response policy; a verified sandbox hop can reach Talon's own HTTP Action Gateway | OpenShell-issued gateway-signed token verified by Talon; action hop uses short-lived, request-bound workload assertion (no Talon secret in sandbox) | [OpenShell integration](../integration/openshell.md) |
| **New agent from scratch** | Native Talon (`talon run`, `POST /v1/agents/run`, `POST /v1/chat/completions`) | Agent key (`Authorization: Bearer <agent-key-value>`) | [Your first governed agent](../tutorials/first-governed-agent.md), [QUICKSTART](../QUICKSTART.md) |

---

## In short

- **HTTP Action Gateway** — Binds the exact operation identity, normalized payload and trusted destination. The runtime establishes the operation and later claims an attempt; an authorized approver can decide without dispatching it. MCP-discovered action definitions can be catalogued, but MCP execution is not yet wired into this path (#431); the HTTP adapter refuses those definitions.
- **OpenShell** — The runtime contains the agent, holds provider credentials and enforces model-traffic decisions returned by Talon's middleware. Talon signs request decisions as `delegated_expected`, **not** proof the runtime honored them. With opt-in `gateway.openshell.response_governance`, Talon can inspect supported provider responses, enforce preventive output policy and settle observed usage; without it, responses and usage remain estimate-only. A separate verified sandbox-to-Action-Gateway hop governs Talon-forwarded HTTP actions, not arbitrary local effects. Talon does not observe local containment effects and does not retry/fallback on delegated model traffic. See the [validation matrix](../integration/openshell.md) before relying on an external runtime version.
- **MCP proxy** — Intercepts **tool-level** MCP traffic from vendors. You point the vendor at Talon; Talon logs, redacts PII (request and response path), enforces policy before forwarding, and filters `tools/list` so agents only see allowed tools. Enable with `talon serve --proxy-config <path>`.
- **LLM API gateway** — Intercepts **request-level** LLM API traffic from your own apps. Your app changes only the base URL and presents its agent key; Talon enforces the agent's effective model and cost policy, scans responses for PII (redact/block/warn), supports tool-aware redaction per argument, provides a kill switch (programmatic via `ActiveRunTracker.Kill()`), and records evidence. Enable with `talon serve --gateway --gateway-config <path>`.
- **Native Talon** — You run agents via `talon run` or the REST API. Full policy-as-code, triggers, memory, and audit. No proxy; Talon is the agent runtime.

**MCP compatibility:** `/mcp` and `/mcp/proxy` speak `2026-07-28` only. Older handshakes (`initialize`) and protocol sessions are not supported. See the [MCP migration guide](mcp-2026-migration.md). MCP interception does not currently provide Action Gateway's bound-approval/at-most-once execution contract. **Policy posture:** there is no global shadow/log-only/observe-and-forward runtime mode; active rules are enforced (#442).

You can use **both** MCP proxy and LLM gateway on the same server (e.g. MCP proxy for Zendesk, gateway for internal Slack bot).

---

## You're done

You now know which Talon path fits your situation (MCP proxy, LLM gateway, or native). Pick the doc from the table above and follow it.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Route my existing app through Talon | [Add Talon to your existing app](add-talon-to-existing-app.md) |
| Route OpenClaw or CoPaw through Talon | [OpenClaw](openclaw-integration.md), [CoPaw](copaw-integration.md) |
| Wrap a third-party AI vendor (Zendesk, Intercom) | [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md) |
| Authorize a high-impact HTTP action | [Action Gateway](../reference/action-gateway.md) |
| Govern a contained OpenShell agent | [OpenShell integration](../integration/openshell.md) |
| Build a new agent from scratch | [Your first agent with Talon](../tutorials/first-governed-agent.md) |

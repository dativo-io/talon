# How to choose your integration path

Use this guide to pick the right Talon entry point for your situation: MCP proxy (third-party vendors), LLM API gateway (your apps calling LLM APIs), or native Talon (new agents from scratch).

---

## Decision table

| Your situation | Talon path | Auth | Where to go next |
|----------------|------------|------|-------------------|
| **Third-party SaaS** (Zendesk AI, Intercom, HubSpot) | MCP proxy at `POST /mcp/proxy`. Response PII scanning, `tools/list` filtering (agents only see allowed tools) | Talon API key (`X-Talon-Key`) for the server; vendor talks to Talon | [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md) |
| **Your app calls LLM APIs** (Slack bot, desktop app, OpenClaw, script) | LLM API gateway at `POST /v1/proxy/{provider}/v1/...`. Response-path PII scanning, kill switch, tool-aware redaction | Gateway caller API key (`Authorization: Bearer <caller-key>`) | [OpenClaw](openclaw-integration.md), [Slack bot](slack-bot-integration.md), [Desktop apps](desktop-app-governance.md) |
| **New agent from scratch** | Native Talon (`talon run`, `POST /v1/agents/run`, `POST /v1/chat/completions`) | Talon API key (`X-Talon-Key`) | [Your first governed agent](../tutorials/first-governed-agent.md), [QUICKSTART](../QUICKSTART.md) |

---

## In short

- **MCP proxy** — Intercepts **tool-level** MCP traffic from vendors. You point the vendor at Talon; Talon logs, redacts PII (request and response path), enforces policy before forwarding, and filters `tools/list` so agents only see allowed tools. Enable with `talon serve --proxy-config <path>`.
- **LLM API gateway** — Intercepts **request-level** LLM API traffic from your own apps. Your app changes only the base URL and sends a caller API key; Talon enforces per-caller model and cost policy, scans responses for PII (redact/block/warn), supports tool-aware redaction per argument, provides a kill switch (programmatic via `ActiveRunTracker.Kill()`), and records evidence. Enable with `talon serve --gateway --gateway-config <path>`.
- **Native Talon** — You run agents via `talon run` or the REST API. Full policy-as-code, triggers, memory, and audit. No proxy; Talon is the agent runtime.

You can use **both** MCP proxy and LLM gateway on the same server (e.g. MCP proxy for Zendesk, gateway for internal Slack bot).

# How to choose your integration path

Use this guide to pick a real enforcement boundary: model API gateway, HTTP Action Gateway, governed MCP endpoint, native Talon runtime, or delegated enforcement through OpenShell. These are different execution surfaces with different guarantees.

---

## Decision table

| Your situation | Talon path | Auth | Where to go next |
|----------------|------------|------|-------------------|
| **An MCP client calls consequential tools of an MCP server** (CRM, ticketing, internal tools) | Governed MCP endpoint `POST /mcp`: the MCP server is a trusted action source of the use case; every `tools/call` is an Action Gateway operation (company policy, approvals, at most one dispatch, signed lifecycle evidence); `tools/list` lists only the use case's governed tools | The use case's agent key (`Authorization: Bearer <agent-key-value>`); the admin key is refused | [Governed MCP tools](mcp-governed-tools.md) |
| **Your app calls LLM APIs** (Slack bot, desktop app, OpenClaw, CoPaw, script) | LLM API gateway at `POST /v1/proxy/{provider}/v1/...`. Response-path PII scanning, tool-aware redaction | Agent key (`Authorization: Bearer <agent key>`) | [OpenClaw](openclaw-integration.md), [CoPaw](copaw-integration.md), [Slack bot](slack-bot-integration.md), [Desktop apps](desktop-app-governance.md) |
| **Consequential HTTP business action** (refund, publish, mutation) | HTTP Action Gateway (`POST /v1/action-operations`, `/v1/approvals`) — immutable exact payload, authenticated reviewer decision and at-most-once Talon-forwarded HTTP attempt | Agent key for the action operation; separate tenant-scoped approver principal for decisions | [Action Gateway](../reference/action-gateway.md) |
| **Contained agent in OpenShell** | OpenShell delegates model-policy decisions at `HTTP_REQUEST / PRE_CREDENTIALS`; optional `HTTP_RESPONSE / PRE_RETURN` governance observes usage and applies response policy; a verified sandbox hop can reach Talon's own HTTP Action Gateway | OpenShell-issued gateway-signed token verified by Talon; action hop uses short-lived, request-bound workload assertion (no Talon secret in sandbox) | [OpenShell integration](../integration/openshell.md) |
| **New agent from scratch** | Native Talon (`talon run`, `POST /v1/agents/run`, `POST /v1/chat/completions`) | Agent key (`Authorization: Bearer <agent-key-value>`) | [Your first governed agent](../tutorials/first-governed-agent.md), [QUICKSTART](../QUICKSTART.md) |

---

These paths are ways to connect **one AI use case** (one `agent.talon.yaml`, one identity, one Talon key), not kinds of application: a use case registered with `talon agents add` can use the LLM gateway, the Action Gateway and the governed MCP endpoint with the same key. `talon agents show <name> --effective` reports per boundary whether an authenticated request of the use case has been observed there.

## In short

- **HTTP Action Gateway** — Binds the exact operation identity, normalized payload and trusted destination. The runtime establishes the operation and later claims an attempt; an authorized approver can decide without dispatching it. MCP-discovered action definitions execute on the same spine through the governed MCP endpoint (#431).
- **OpenShell** — The runtime contains the agent, holds provider credentials and enforces model-traffic decisions returned by Talon's middleware. Talon signs request decisions as `delegated_expected`, **not** proof the runtime honored them. With opt-in `gateway.openshell.response_governance`, Talon can inspect supported provider responses, enforce preventive output policy and settle observed usage; without it, responses and usage remain estimate-only. A separate verified sandbox-to-Action-Gateway hop governs Talon-forwarded HTTP actions, not arbitrary local effects. Talon does not observe local containment effects and does not retry/fallback on delegated model traffic. See the [validation matrix](../integration/openshell.md) before relying on an external runtime version.
- **Governed MCP endpoint** — Governs **tool-level** MCP traffic to an MCP server declared as a trusted action source of the use case (`actions.sources`, `actions.definitions`). The MCP client talks to Talon's `POST /mcp`, never to the MCP server. Every `tools/call` is an Action Gateway operation: a consequential tool is first prepared (nothing is sent) and executed with `talon_execute_operation`; a trusted read-only tool runs in one call. PII on arguments and results follows the use case's effective company policy. Every `talon serve` serves it. See [Governed MCP tools](mcp-governed-tools.md).
- **LLM API gateway** — Intercepts **request-level** LLM API traffic from your own apps. Your app changes only the base URL and presents its agent key; Talon enforces the agent's effective model and cost policy, scans responses for PII (redact/block/warn), supports tool-aware redaction per argument,  and records evidence. Enable with `talon serve --gateway --gateway-config <path>`.
- **Native Talon** — You run agents via `talon run` or the REST API. Full policy-as-code, triggers, memory, and audit. No proxy; Talon is the agent runtime.

**MCP compatibility:** `POST /mcp` speaks `2026-07-28` only. Older handshakes (`initialize`) and protocol sessions are not supported. See the [MCP migration guide](mcp-2026-migration.md). A governed MCP call has the Action Gateway's bound-approval/at-most-once execution contract; tools a client reaches without going through Talon are not governed. **Policy posture:** there is no global shadow/log-only/observe-and-forward runtime mode; active rules are enforced (#442).

You can use **both** the governed MCP endpoint and the LLM gateway on the same server: every `talon serve` serves `POST /mcp`, and `--gateway` adds the LLM gateway.

---

## Compatibility for v1.17.0

Find your stack before installing. Support describes a product boundary; verification describes evidence for a specific environment. **Supported route** does not mean every client or deployment is certified. **Release verified** below means the named scenario passed against a distributed artifact, not a real paid provider or an entire framework. **Documented / not independently verified here** means a guide exists but this inventory makes no exact-version test claim. **Experimental** is limited qualification; **unsupported** is outside the released contract. Unknown combinations require your own pilot.

Release evidence: [v1.17.0 pilot acceptance](https://github.com/dativo-io/talon/actions/runs/45429574176/job/138573998621), [release verification](https://github.com/dativo-io/talon/actions/runs/45429574176/job/138577644428), [limitations](../../LIMITATIONS.md). The pilot used deterministic local model responses and synthetic business data; the optional paid-provider request was not run.

### Model providers and application SDKs

| Stack / profile | Support boundary | Verification at v1.17.0 | Start here / validate |
| --- | --- | --- | --- |
| OpenAI-compatible application, Node SDK 7.59.0 | Supported model gateway route; use-case bearer key | Release verified: two use cases, permitted response, PII denial, independent upstream counts | [Connect an existing app](add-talon-to-existing-app.md); validate actual endpoint, model, request shape and provider credentials |
| Python OpenAI-compatible SDK, other HTTP clients | Documented model gateway route; use-case bearer key | No exact client-version release receipt identified in this inventory | [Existing application guide](add-talon-to-existing-app.md); run the positive and negative checks with your SDK |
| Anthropic Messages API applications | Documented provider-compatible model route; use-case key | No general client/provider release compatibility receipt claimed | [Claude Code integration](claude-code-integration.md); validate headers, endpoint, streaming and model |
| OpenAI, Anthropic, Azure OpenAI, Bedrock, Mistral, Ollama, Vertex, Qwen, Cohere, generic OpenAI | Registered native router providers; this is not a list of gateway wire protocols | Provider registry, not a certification of all provider/region/model combinations | [Provider registry](../reference/provider-registry.md); check native vs gateway configuration, pricing and actual endpoint |
| Streaming model responses | Supported response-policy semantics for tested model gateway paths | Release verified: allow and warn early delivery, redact preventive buffering | [Request lifecycle](../explanation/what-talon-does-to-your-request.md); measure latency and verify your stream shape; warn is observation, not prevention |

A client that implements an OpenAI-compatible API is not automatically compatible with every OpenAI endpoint. The [proxy quickstart](../tutorials/proxy-quickstart.md) is a separate local quickstart profile, not the authenticated company gateway contract. Do not assume embeddings, retrieval endpoints or every provider-native feature are supported merely because chat works.

### n8n and HTTP workflows

| Stack / profile | Support boundary | Verification at v1.17.0 | Start here / validate |
| --- | --- | --- | --- |
| Self-hosted n8n 2.48.5, importable refund reference | HTTP Action Gateway; separate use-case and reviewer credentials; orchestration remains in n8n | Release verified: real imported workflow, authenticated webhook, synthetic counting refund service, approval/deny and claim behavior | [n8n refund approval](n8n-refund-approvals.md); validate business adapter eligibility, destination and credentials |
| Existing n8n model inference workflow / stock model nodes | Model gateway protocol where node and credential shape match; not blanket n8n compatibility | No stock-node version receipt established by the refund test | [Connect an existing app](add-talon-to-existing-app.md); validate credential discovery, base URL, model listing, node operation and streaming before adoption |
| Other n8n versions, n8n Cloud, queue mode | Qualification of these deployment/client combinations is not established by the reference | Untested in the cited release receipt | Validate topology, credentials, network reachability and workflow behavior before claiming support |
| Custom HTTP automation | Supported declared HTTP Action Gateway operation contract | Release verified: exact-action lifecycle using a counted synthetic destination, not every automation client | [Exact-action reference](../reference/action-gateway.md); separate reviewer authority, stable operation identity and unknown-outcome reconciliation |

The n8n refund test verifies action orchestration, not native AI model nodes, credential discovery, or real payment correctness. Do not infer those from this receipt. Approval is not dispatch; n8n must use the documented claim flow.

### MCP, agent runtimes and coding assistants

| Stack / profile | Support boundary | Verification at v1.17.0 | Start here / validate |
| --- | --- | --- | --- |
| Official MCP Go SDK v1.8.0 | Governed POST /mcp; authenticated use-case key; trusted declared action sources | Release verified: standard SDK client, real MCP server, governance lifecycle | [Governed MCP tools](mcp-governed-tools.md); verify prepare/execute and trusted tool declarations |
| MCP clients using 2026-07-28 | Supported wire contract; client must implement stateless protocol and governed tool flow | Only the named release SDK profile is established by the above receipt | [MCP migration](mcp-2026-migration.md); validate actual client and version |
| Legacy MCP initialize/session handshake or /mcp/proxy | Unsupported in this release | Not a supported route | [MCP migration](mcp-2026-migration.md) |
| Claude Code and Codex CLI through model gateway | Documented API-key integrations; not subscription login or local tool control | No blanket release compatibility claim for all client versions | [Claude Code](claude-code-integration.md), [Codex CLI](codex-cli-integration.md); verify credential and actual traffic |
| OpenClaw, CoPaw, desktop applications, Slack bots | Documented routed model integrations | Exact-version release verification not claimed here | [OpenClaw](openclaw-integration.md), [CoPaw](copaw-integration.md), [desktop apps](desktop-app-governance.md), [Slack](slack-bot-integration.md) |
| OpenShell v0.1.3 / v0.1.4 | v0.1.3 validated baseline; v0.1.4 experimental per the integration contract | Separate live/fixture lanes and release showcase bundle; not blanket runtime certification | [OpenShell validation matrix](../integration/openshell.md); delegated decisions, response governance and the action hop have distinct evidence |
| Native Talon | Supported native run boundary; no external workflow lifecycle ownership | Released native runtime; test your own tools, provider and policy | [First governed agent](../tutorials/first-governed-agent.md) |
| GitHub Copilot CLI | Historical integration guide; no current support assertion in this inventory | Exact current profile not established | [Historical guide](github-copilot-cli-governance.md); validate current client before use |

### Deployment and operational integrations

| Profile | Support boundary | Verification at v1.17.0 | Start here / validate |
| --- | --- | --- | --- |
| Linux amd64 single node | Supported self-hosted pilot profile; operator supplies TLS and host protection | Release verified binary, recovery/upgrade and console acceptance | [Single-node production](single-node-production.md), [production pilot](production-pilot.md) |
| Published Docker image / local Compose | Supported documented evaluation path; loopback demo is not production | Published image quickstart verified; console and Compose smoke are distinct checks | [Quickstart](../tutorials/quickstart-demo.md); use secure production profile for remote traffic |
| macOS amd64 / arm64 | Best-effort release archives, present in v1.17.0 with checksums | Release build and checksum evidence; not the Linux pilot acceptance profile | [Release assets](https://github.com/dativo-io/talon/releases/tag/v1.17.0) |
| Linux arm64 / source build | Documented source installation; no published Linux arm64 archive | Source install/build is not distributed-artifact pilot acceptance | [Installation reference](../QUICKSTART.md); verify toolchain, build and workload |
| Kubernetes / multi-replica active-active | No supported HA profile established by the single-node release | Untested as a production HA profile in this inventory | [Single-node production](single-node-production.md), [limitations](../../LIMITATIONS.md); do not infer distributed state consistency |
| Presidio-compatible external scanner | Documented HTTP or Unix socket result contract | Verify exact engine, entity coverage, offsets and failure policy; not a certification of every scanner | [External scanners](../reference/external-scanners.md), [scanner matrix](../reference/presidio-compatibility-matrix.md) |

For any unqualified combination, first register a dedicated synthetic use case, send an allowed request and a known denied request, verify evidence and an independent upstream count, test failure behavior and document the exact client version. Only expand to production after evaluating the [production pilot](production-pilot.md). Do not use a provider key as a Talon use-case credential or assume traffic bypassing Talon is governed.

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

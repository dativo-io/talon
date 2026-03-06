# Why not just a PII proxy?

A "PII proxy" here means a service that sits in front of your LLM API and scans request (or response) bodies for personal data — e.g. Presidio behind LiteLLM, CloakLLM, or a DIY FastAPI proxy that runs regex and forwards. This doc explains what that approach misses and how Talon differs. Each section: naive approach → what it misses → what Talon does → the exact Rego rule or CLI command that proves it.

**Alternatives in the wild:** LiteLLM + Presidio (logging/redaction, no pre-call policy or tool visibility), CloakLLM (PII redaction, no tool-level interception), DIY FastAPI proxy (you own auth, rate limits, cost aggregation, and evidence integrity). Talon is a single binary that does PII scan, policy (including cost and tools), and signed evidence in one place.

---

## 1. Tool calls are invisible to a body-only proxy

**Naive approach:** You put a proxy in front of the LLM API. It sees the HTTP request body (e.g. a chat completion request with `messages`). It does not see the *tool layer*: which tools the agent is allowed to call, or the fact that the model just returned "I will call `bulk_delete_users`" and your backend is about to execute it.

**What it misses:** The proxy never sees tool names or arguments. It only sees the JSON that goes to the LLM and comes back. So you cannot block a tool call before it runs. You can log the response after the fact and see "the model asked for bulk_delete_users" — but by then your backend may have already run it. A PII-only proxy cannot deny `tools/call` or filter `tools/list` because it is not in the path of MCP or your tool-execution layer.

**What Talon does:** Talon sits in front of both the LLM and the tool layer. For the LLM API gateway, it inspects the `tools` array in the request and strips or allows per policy; for MCP, it intercepts `tools/call` and `tools/list`. Forbidden tools are denied before execution. Every allowed or denied tool call is recorded.

**Proof:** Gateway: configure `default_policy.forbidden_tools` or per-caller `policy_overrides.allowed_tools` / `forbidden_tools` in your gateway config. Send a request that includes a forbidden tool; the request is denied and evidence shows the reason. MCP: use `allowed_tools` in the proxy policy; call a tool not in the list and see it blocked. CLI: `talon audit list` shows rows with `blocked:tool` when a tool was denied.

---

## 2. Cost is enforced after the fact

**Naive approach:** You use LiteLLM (or similar) to log usage and maybe send an alert when spend exceeds a threshold. The flow is: request → proxy → LLM → response → log cost → maybe alert. The decision to allow or deny is made before the call; the cost is known only after the call.

**What it misses:** Alerts do not stop the next request. By the time you get "Team X has spent $500 today," the money is already spent. You need a *pre-call* check: "If I allow this request, will the caller exceed their budget?" If yes, deny the request and do not forward to the provider. No post-spend alert can do that.

**What Talon does:** The gateway keeps a running cost total per caller (daily and optionally monthly). Before every forward, it estimates the cost of the request and checks whether the caller would exceed their limit. If they would, the request is denied and no call is made to the LLM. Evidence is still written (decision: denied, reason: budget).

**Proof:** Rego in `internal/policy/rego/gateway_access.rego`: `deny` when `input.daily_cost + input.estimated_cost > input.caller_max_daily_cost`. Set `policy_overrides.max_daily_cost` for a caller to a small value (e.g. 0.01), send a request that would exceed it; the response is a denial and `talon audit list` shows the denied decision and reason.

---

## 3. PII in the prompt is only logged, not blocked

**Naive approach:** Your proxy runs a PII detector (e.g. Presidio) on the request body and logs "PII found: email, IBAN." It may redact before sending to the LLM, or it may only log. Often the default is "log and forward" so the app keeps working; blocking is an extra step and may break flows that intentionally send masked or test data.

**What it misses:** If the proxy is not configured to *block* when PII is present, or to route to an EU-only model when the data tier is high, the request still reaches the provider. You get a log line, but the model still sees the data (or you rely on the provider's terms). For strict compliance you need: detect PII → classify tier → apply policy (block / redact / route to EU only) *before* the call. A proxy that only logs does not enforce.

**What Talon does:** Talon scans input (and optionally response) with EU-focused recognizers (IBAN, BSN, NIR, NIF, PESEL, VAT IDs, etc.). It classifies the request into a data tier. Policy can then block the request, redact, or restrict to EU-only models. The decision is made before the LLM call; if the decision is block, the request never reaches the provider.

**Proof:** Set gateway `default_policy.default_pii_action: "block"` (or a caller override). Send a request with an IBAN in the message body. The request is denied; `talon audit list` shows `blocked:pii` and the evidence record includes `pii_detected`. For verification: `talon audit show <evidence-id>` shows classification and policy reasons.

---

## 4. The "audit log" can be edited

**Naive approach:** You write request/response or metadata to a log file or database. Anyone with access to that store can alter or delete rows. There is no cryptographic binding between the record and the event, so you cannot prove to an auditor that the log was not tampered with.

**What it misses:** Compliance (e.g. GDPR Art. 30, NIS2) often requires that you can demonstrate what was processed, when, and by whom. If the log is mutable, the demonstration is weak. You need a record that is signed at creation time so that any later change invalidates the signature.

**What Talon does:** Every evidence record is signed with HMAC-SHA256 at creation time. The signature covers all fields (timestamp, caller, model, cost, policy decision, PII flags, etc.). You can run `talon audit verify <evidence-id>` to recompute the HMAC and compare; if any field was modified, verification fails.

**Proof:** `talon audit verify <evidence-id>` — output is either `signature VALID` or an error. Edit the SQLite row (e.g. change cost or timestamp) and run verify again; it fails. See [Evidence store](evidence-store.md) for the exact fields included in the signature.

---

## 5. Third-party AI vendors are out of scope

**Naive approach:** You have a vendor (Zendesk AI, Intercom, HubSpot) that calls LLMs and tools on their side. Your PII proxy only sees traffic that *you* send to an LLM API. It never sees the vendor's internal calls or their tool invocations. You cannot enforce policy or get a signed record for what the vendor did.

**What it misses:** You are still liable for what the vendor does with your data. A proxy in front of *your* app does not help with *their* app. You need a way to put their traffic through the same pipeline: PII scan, tool filter, policy, signed evidence. That means the vendor must send their traffic through your proxy (e.g. they point their MCP client at your endpoint).

**What Talon does:** Talon's MCP proxy is an endpoint the vendor can use. They point their agent at Talon; Talon intercepts MCP (including `tools/list` and `tools/call`), runs policy, redacts or blocks, and writes evidence. You get the same controls and tamper-proof record for vendor traffic. No vendor code change required beyond configuration (endpoint URL and key).

**Proof:** Configure `talon serve --proxy-config <path>` with a proxy policy that has `allowed_tools` and PII settings. Point the vendor at your Talon `/mcp/proxy` endpoint. Trigger the vendor; `talon audit list` shows evidence for MCP requests and tool calls. See [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md) and [Architecture: MCP proxy](../ARCHITECTURE_MCP_PROXY.md).

---

## Three questions to ask any tool in this category

1. **Does it see tool calls?** If it only inspects LLM request/response bodies, it cannot block or allow specific tools before they run. Ask: "Where does it sit in the request path? Can it deny a `tools/call` or filter `tools/list`?"

2. **When is cost enforced?** If the tool alerts or logs after the request is sent, you have already spent. Ask: "Does it deny the request when the caller would exceed their budget, or only notify after the fact?"

3. **Can you prove the log was not altered?** If the audit store is a normal database or log file, anyone with write access can change it. Ask: "Is each record cryptographically signed? Can I run a single command to verify that a given record has not been modified?"

If the answer to any of these is "no," that tool does not cover the same ground as Talon for that dimension. Use this doc to decide what you need (PII only, cost only, tools, evidence integrity, vendor coverage) and pick or combine tools accordingly.

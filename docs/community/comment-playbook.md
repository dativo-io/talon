# Community comment playbook (internal)

Use this as a thinking aid, not a script. Replies should be written by a human for the specific thread.

Principles:

- Lead with the user's problem, not the project name.
- Explain failure modes in concrete technical terms.
- Link only to proof pages/commands that directly support your claim.
- For Hacker News: no generated/template comments. Keep responses personal, direct, and technical.

---

## 1. "How do I stop my agent calling wrong tools?"

**Opening:** The agent is calling tools you never intended it to use (e.g. `bulk_delete_users`, `run_sql`). That happens because the tool layer sits behind the LLM — a normal HTTP proxy only sees the chat request body, not which tools the model is about to invoke.

**Why the naive approach fails:** If you only put a PII proxy or log-and-forward in front of the LLM API, you never see tool names or arguments. The model returns "I'll call tool X" and your backend executes it. By the time you log the response, the tool has already run. You need something that sits in front of both the LLM call and the tool execution path so it can deny the call before it happens.

**What works:** Use a proxy that understands the LLM protocol and the tool-call payload. It should evaluate policy (allowlist/blocklist of tool names, optionally argument checks) before the tool is executed, and write a record of every allowed/denied call. MCP-aware proxies can filter `tools/list` so the agent only sees allowed tools and can block `tools/call` for forbidden ones.

**Optional link (only if they want an open-source option that does this):** [Talon](https://github.com/dativo-io/talon) does this: it intercepts MCP `tools/call` and gateway LLM requests, runs policy (OPA) before forwarding, and logs every decision. Quick check: `git clone https://github.com/dativo-io/talon && cd talon/examples/docker-compose && docker compose up` — then send a request and run `docker compose exec talon talon audit list` to see tool-level decisions.

---

## 2. "PII proxy for EU patterns (IBAN, BSN)?"

**Opening:** You need to detect (and optionally block or redact) EU PII like IBAN, BSN, NIR, NIF, PESEL in prompts or responses.

**Why the naive approach fails:** Generic regex or a single library often misses locale-specific formats (e.g. Dutch BSN, French NIR, Spanish NIF) or gets false positives. You also need to decide: block the request, redact before sending to the model, or log and warn. Doing that consistently across all your apps means a single place that sees every request.

**What works:** Use a proxy in front of your LLM provider that has recognizers for the EU patterns you care about, classifies the request (e.g. tier by sensitivity), and applies a policy (block / redact / warn). You want one binary or service that every app talks to so you don't reimplement detection in each codebase.

**Optional link:** [Talon](https://github.com/dativo-io/talon) ships 25+ EU PII patterns (IBAN, BSN, NIR, NIF, PESEL, VAT IDs, etc.), runs policy before the call, and writes a tamper-proof record per request. No API key needed to try: `git clone https://github.com/dativo-io/talon && cd talon/examples/docker-compose && docker compose up` — then curl a request with an IBAN in the body and run `docker compose exec talon talon audit list` to see PII detected and the decision.

---

## 3. "LLM costs out of control"

**Opening:** Spend is blowing up because teams or apps can call the API without any hard limit.

**Why the naive approach fails:** Alerting after the fact (e.g. "you've hit $500 today") doesn't stop the next request. By the time you get the alert, the money is spent. You need a hard cap that is evaluated **before** the LLM call is made, and a single place that all traffic goes through so one team can't bypass it.

**What works:** Put a gateway in front of the LLM API that identifies the caller (e.g. by API key or source IP), keeps a running cost total per caller, and denies the request if the caller would exceed their budget. The call never reaches the provider, so no spend. Tools like LiteLLM can log and alert, but if they don't enforce before the call, you still need something that does the deny at the gateway.

**Optional link:** [Talon](https://github.com/dativo-io/talon) evaluates cost limits before forwarding: per-request, daily, and monthly caps per caller. When the limit is hit, the request is denied and logged. Demo: `git clone https://github.com/dativo-io/talon && cd talon/examples/docker-compose && docker compose up` — then `docker compose exec talon talon audit list` shows cost per request and decision.

---

## 4. "How do I audit what my agent did?"

**Opening:** You need a verifiable record of what the agent did (which model, what was sent, what was returned, whether PII was present, whether a tool was called).

**Why the naive approach fails:** Logs in your app or in the LLM provider's dashboard can be edited or deleted. For compliance (e.g. GDPR Art. 30, NIS2) you need something that is tamper-evident: a record that can be verified so you can prove it wasn't changed after the fact.

**What works:** Use a proxy that writes every request/response (or a hash and metadata) to a store and signs each record (e.g. HMAC-SHA256). You then have a chain of records you can verify with a single command. The proxy must be the only path to the LLM so nothing bypasses it.

**Optional link:** [Talon](https://github.com/dativo-io/talon) writes an HMAC-signed evidence record per request to SQLite; you run `talon audit verify <id>` to confirm integrity. Export to CSV for auditors. Try it: `git clone https://github.com/dativo-io/talon && cd talon/examples/docker-compose && docker compose up` — send a request, then `docker compose exec talon talon audit list` and `talon audit verify <evidence-id>`.

---

## 5. "Open-source Portkey/Helicone alternative?"

**Opening:** You're looking for an open-source way to proxy LLM traffic with logging, cost tracking, and optional PII/tool controls.

**Why the naive approach fails:** Portkey and Helicone are hosted; you may want self-hosted, on-prem, or a single binary with no external services. Rolling your own means maintaining auth, rate limits, cost aggregation, and evidence storage — and it's easy to leave gaps (e.g. no pre-call budget check, or logs that can be altered).

**What works:** An open-source proxy that: (1) sits in front of OpenAI/Anthropic/Bedrock, (2) identifies callers and enforces limits before the call, (3) scans for PII and can block/redact, (4) writes a signed record per request. Single binary and SQLite-by-default keeps deployment simple.

**Link:** [Talon](https://github.com/dativo-io/talon) is Apache 2.0, single Go binary, SQLite evidence store, OPA for policy. You change your app's base URL and use a caller key; Talon does the rest. No API key needed to run the demo: `git clone https://github.com/dativo-io/talon && cd talon/examples/docker-compose && docker compose up` — then curl a request and `docker compose exec talon talon audit list`.

---

## Rules of thumb

- **Never** lead with the product name. Lead with the problem and why common approaches fail.
- **Only** link when the thread is asking for exactly what Talon does (tool blocking, EU PII, cost caps, verifiable audit, or open-source proxy).
- **Always** include the one-command demo when you link (`docker compose up` in the docker-compose example).
- **Do not** paste the same reply in multiple threads; adapt the opening and supporting evidence.
- **Do not** use AI-generated or AI-edited community comments on HN.

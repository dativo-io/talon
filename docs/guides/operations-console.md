# Operations console

The operations console is a read-only browser view of one Talon installation. It answers the questions an operator asks about the AI use cases Talon governs: which need attention and why, what they cost against their caps, what Talon decided for a request and what happened to it, what is configured, and how far the shown data can be trusted.

Every number on a page comes from the same Go projections the `talon` CLI prints. The browser formats and lays out; it does not compute health, budgets, decisions or sessions. When a source could not be read, or a figure is not a measurement, the page says so instead of showing a zero.

## Start it and sign in

With the default Docker Compose stack the console runs as the `talon-ui` service on `http://127.0.0.1:8787/`. Without Compose:

```bash
talon ui                     # starts the console and opens the browser
talon ui serve               # headless; prints the pairing code to stdout
talon ui serve --proxy-config proxy.talon.yaml   # also show the MCP proxy configuration
```

The browser asks for a one-time pairing code. Read it from the console's own output (`docker compose logs talon-ui`, or the terminal running `talon ui`); `talon ui pair` prints a fresh one. Codes are single use and expire within ten minutes. The browser then holds a read-only session cookie; no admin, agent or vault key ever reaches it. When the session ends (expiry, logout, console restart), the page asks for a new code and returns to where you were. Details and the threat model: [console access](../reference/console-access.md).

## The six pages

| Page | Question it answers | Source |
|---|---|---|
| **Overview** | Which AI use cases need attention right now, and why? | `talon agents` fleet projection, today's counters, request-class activity buckets, recent operational events |
| **AI Use Cases** | What AI use cases do we operate, how are they doing, how are they governed? | the same fleet rows, unchanged order; detail adds costs, 24-hour activity and recent sessions |
| **Sessions** | What happened in this session, what did Talon decide, and was anything sent? | session store rows and evidence-observed session ids, summary and timeline from `talon session show` |
| **Costs** | How much, where, and are budgets respected? | `talon costs --json` (`costs.Build`) |
| **Configuration** | What is configured, and what can be proven active? | the gateway, agent and MCP proxy files, summarised server-side |
| **System** | Can I trust the sources behind this console? | the console process and the evidence store file |

Evidence records open from any timeline, event or search result (`/evidence/<id>`).

## Reading the pages correctly

- **Unavailable is not zero.** A section that could not be read, or a figure the backend marks as not a measurement, is shown as *unavailable* with the reason. A zero is shown only when the source was read and holds nothing.
- **Health is projected; liveness is the process's own heartbeat.** Use-case health is evaluated from recorded evidence and the configuration files. Whether the MCP proxy and the LLM gateway are running comes from the status record each `talon serve` process writes into the data directory every 5 seconds: *running* while it is fresh, *stale* after three missed heartbeats, *offline* after twelve or a recorded shutdown, *not configured* when this installation does not use that runtime. The System page lists each process with version, active configuration generation and any rejected reload; sessions and evidence stay readable whatever the process state.
- **Counter windows are stated.** Requests, denials and fallbacks in the use-case table cover the last hour and failed sessions the last 24 hours: the windows Talon's health evaluation uses. Spend uses the UTC day and calendar month. The activity chart's range selector moves only the chart.
- **Decision and outcome are separate facts.** Each timeline row shows Talon's decision, then whether the request left Talon, then what the destination did. *Talon denied → Not dispatched* (a forbidden MCP tool), *Talon allowed → Dispatched → Destination rejected* (the HR backend refused the SQL), and *Talon allowed → Dispatched → Attempt failed* (a provider error before a fallback) are different rows, and a cache hit reads *Talon allowed → Not dispatched → Answered from Talon's cache*. A failed attempt counts as dispatched only when the provider's HTTP status was recorded; a bare transport error reads *Dispatch unknown*. These come from `evidence.OutcomeOf`, which reads only facts the writer recorded and says *not recorded* otherwise; "Why this outcome" names the fact.
- **Sessions are never invented.** Managed sessions (with a lifecycle Talon tracks) and session ids seen only on evidence are listed separately. A record without a session id is shown as standalone. Two AI use cases that assert the same external session id are separate sessions; pick the use case to see each.
- **Verification is a real check.** The evidence page verifies the HMAC signature for each read and shows *Signature valid* or *Signature invalid*. Evidence is tamper-evident, not immutable.
- **Unpriced calls do not change health.** The Costs page counts model calls without a pricing-table price and warns that amounts understate spend; fleet health does not use that count, so a healthy use case can still have unpriced calls.
- **Fleet spend in another currency is not a number.** When a use case's priced records in a period are not all in the pricing currency, its spend shows *unavailable* and its budget is *not evaluated* (cause `budget_not_comparable`), as in `talon agents`.
- **Amounts keep their currency.** Amounts are in the active pricing table's currency. Fields named `*_eur` in the API are historical names, not euros. When priced records in a window are in another currency, or the currency check failed, those amounts and the budget utilization are shown as unavailable with the warning; no exchange rate is ever applied.
- **Configuration is file contents.** The Configuration page shows what the files say now, built from an allowlist of fields: URLs are reduced to scheme and host, webhook URLs are only reported as configured, and secret values never leave the server (vault secret names are shown). Whether a running process loaded these exact bytes is shown separately, proved by digests the process reports: each use case reads *Yes: this file is loaded*, *A different version is loaded*, *Not in the active generation* or *Not proven*. Each AI use case's page has an **Effective policy** section (the same report as `talon agents show <name> --effective`) in four layers: the current files, whether a running process loaded them, the effective policy compiled by the gateway's own resolver with the winning layer and every layer's value per rule, and the last recorded decision with whether it was made under the current policy. The values are labeled *Compiled from current files, not proven active* unless a running process reports the current file's digest. The MCP proxy's pre-dispatch decision per tool (for example `hr_employee_export` denied at `forbidden_tools`) is shown with it.

## Search

The search box accepts an AI use case name (prefix), an exact session id, an exact evidence id or an exact correlation id. It searches one tenant for every kind of result: the tenant in the header, or `default` when it is empty; the dropdown names the tenant searched. Explanation codes are not searchable yet: they live inside the signed record and have no index. Search never loads the evidence store into the browser.

## Scope

The tenant field in the header scopes every page (`?tenant=` in the URL). Empty means all tenants on Overview, including its activity chart, and on AI Use Cases; Sessions, Costs and search use `default`. Each page states the scope it shows. Filters and scope live in the URL, so a link to an investigation can be shared; no code, cookie or key is ever placed in a URL.

## What the console does not do

It changes nothing: no configuration edits, no approvals, no budget changes, no runs. It shows only traffic and actions Talon intercepted; local shell commands, file edits and calls that bypass Talon are invisible to it. Client-asserted identities (session ids, clients) are attribution, not authentication.

## Related

- [Console access and pairing](../reference/console-access.md)
- [Console read contract](../reference/console-read-contract.md)
- [Explanation catalog](../explanation/explanation-catalog.md)

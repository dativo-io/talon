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
- **Health is projected, not live.** Until the runtime probe exists (#538), health is evaluated from recorded evidence and the configuration files. A *Healthy* use case does not prove the gateway or MCP proxy process is running; the Overview and System pages say so.
- **Counter windows are stated.** Requests, denials and fallbacks in the use-case table cover the last hour and failed sessions the last 24 hours: the windows Talon's health evaluation uses. Spend uses the UTC day and calendar month. The activity chart's range selector moves only the chart.
- **Decision and outcome are separate facts.** Each timeline row shows Talon's decision, then whether the request left Talon, then what the destination did. *Talon denied → Not dispatched* (a forbidden MCP tool), *Talon allowed → Dispatched → Destination rejected* (the HR backend refused the SQL), and *Talon allowed → Dispatched → Attempt failed* (a provider error before a fallback) are different rows. These come from `evidence.OutcomeOf`, which reads only facts the writer recorded and says *not recorded* otherwise; "Why this outcome" names the fact.
- **Sessions are never invented.** Managed sessions (with a lifecycle Talon tracks) and session ids seen only on evidence are listed separately. A record without a session id is shown as standalone. Two AI use cases that assert the same external session id are separate sessions; pick the use case to see each.
- **Verification is a real check.** The evidence page verifies the HMAC signature for each read and shows *Signature valid* or *Signature invalid*. Evidence is tamper-evident, not immutable.
- **Amounts keep their currency.** Amounts are in the active pricing table's currency. Fields named `*_eur` in the API are historical names, not euros. When priced records in a window are in another currency, or the currency check failed, those amounts and the budget utilization are shown as unavailable with the warning; no exchange rate is ever applied.
- **Configuration is file contents.** The Configuration page shows what the files say now, built from an allowlist of fields: URLs are reduced to scheme and host, webhook URLs are only reported as configured, and secret values never leave the server (vault secret names are shown). It does not claim a running process loaded these values: the active generation stays *unknown* until #538 and effective-policy provenance stays *not available* until #305.

## Search

The search box accepts an AI use case name (prefix), an exact session id, an exact evidence id or an exact correlation id, within the current tenant. Explanation codes are not searchable yet: they live inside the signed record and have no index. Search never loads the evidence store into the browser.

## Scope

The tenant field in the header scopes every page (`?tenant=` in the URL; empty means all tenants where the projection supports it, otherwise `default`). Filters and scope live in the URL, so a link to an investigation can be shared; no code, cookie or key is ever placed in a URL.

## What the console does not do

It changes nothing: no configuration edits, no approvals, no budget changes, no runs. It shows only traffic and actions Talon intercepted; local shell commands, file edits and calls that bypass Talon are invisible to it. Client-asserted identities (session ids, clients) are attribution, not authentication.

## Related

- [Console access and pairing](../reference/console-access.md)
- [Console read contract](../reference/console-read-contract.md)
- [Explanation catalog](../explanation/explanation-catalog.md)

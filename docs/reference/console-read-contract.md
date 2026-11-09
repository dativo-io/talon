# Operations console read contract

**Status:** current contract of the read-only operations console (#533). Section 2 describes shipped code and the tests that pin it. Section 3 lists contracts that are **pending**; nothing in section 3 is shipped. The console introduces no policy, health, cost, session or decision logic: every value it shows is produced by a Go projection the CLI also uses, and a value no projection can produce is shown as unknown or unavailable.

Companion documents: [operations console guide](../guides/operations-console.md), [console access and pairing](console-access.md), [legacy dashboard migration map](legacy-dashboard-migration-map.md), [authentication and key scopes](authentication-and-key-scopes.md).

## 1. Principles

1. **One Go implementation per concept.** `internal/console` calls the shared projections (`fleet.Project`, `costs.Build`, `session.LoadDetail` / `LoadTimelinePage`, `evidence.Store.Detail`, `evidence.Store.ActivityBuckets`, `events.FromEvidence`, `evidence.OutcomeOf`); the CLI calls the same functions. The browser (`internal/console/frontend`) formats and lays out only.
2. **Durable facts come from the shared store, read-only.** The console process opens the evidence and session stores with `mode=ro` (`evidence.OpenReadOnly`, `session.OpenReadOnly`). Live process facts (liveness, active generation, reload state) are not readable from the store and are reported `unknown` until #538.
3. **Unknown is a value.** Every DTO section carries `availability {state: ok|partial|empty|unavailable|unknown, source, as_of, error, note, unavailable[]}`. A failed query, a missing source or a figure that is not a measurement yields that state with the reason, never a zero and never healthy.
4. **Windows and units are explicit.** Cost and today's figures use UTC day, last 7 days and UTC calendar month (`costs.Window`). Fleet counters use the rolling windows of `fleet.DefaultThresholds` and say so (`counter_windows`). Amounts are in the active pricing table's currency; `*_eur` field names are historical. Amounts are never converted between currencies.
5. **Bounded reads.** Every list has a server maximum and a keyset cursor with documented order; search is exact or prefix and bounded; no request decodes the evidence table in full.
6. **The browser credential reaches only the console.** `/console/v1/*` is served by the console process behind the read-only browser session; the process mounts no data-plane route, and the data plane ignores the console cookie ([console access](console-access.md)).

## 2. Shipped contract

All routes are `GET` under `/console/v1`, behind the browser session, `contract_version: "1"`, each response headed by `meta {contract_version, generated_at, tenant_scope: tenant|all_tenants, tenant_id}`.

| Route | DTO | Produced by | CLI with the same facts | Pinned by |
|---|---|---|---|---|
| `overview?tenant=` | `use_cases` (fleet rows, attention subset, issues, `health_basis: projected_from_store`, `runtime: unknown`, `counter_windows`), `today` (request-class counts, spend over all record classes with a day-window currency check), `recent_events` | `fleet.Project` via `fleetview.ProjectOffline`; `ActivityBuckets`-class counts; `events.FromEvidence` | `talon agents --json`, `talon costs --json` | `TestConsoleParity_UseCases`, `TestOverview_HandExpectations`, `TestToday_ForeignCurrencyIsPartial`, browser journeys |
| `use-cases`, `use-cases/{name}` | fleet rows; detail adds `costs`, 24 h `activity`, `recent_sessions`, `effective_policy: unknown` | as above, `costs.Build` | `talon agents show <name> --json` | `TestUseCaseDetail_SessionsCostsActivity`, `TestUseCases_StateTheirCounterWindows` |
| `sessions?tenant=&agent=&status=&limit=&before=&before_id=&observed_before=&observed_before_id=&observed_before_agent=` | managed rows (`session.Store.ListRecent`, cursor `created_at+id`) and evidence-observed ids with no row (`ListObservedSessions`, cursor `last_seen+session_id+agent_id`), each with its own availability | session and evidence stores | `talon session list --json` | `TestSessionsPaging`, `TestSessions_RowBackedSessionIsNotAlsoObserved`, `TestRoutes_ObservedCursorLosslessAcrossAgents` |
| `sessions/{id}?agent=&timeline_limit=&timeline_after=&timeline_after_id=`, `sessions/{id}/timeline` | `detail` (row, ambiguity, `evidence.SessionSummary` with `currencies`, `cost_comparable`) plus one timeline page; `/timeline` pages without recomputing the summary; partial on `detail.summary.total_cost` when not comparable | `session.LoadDetailFor`, `evidence.Store.SessionSnapshotRead`, `TimelinePageRead` | `talon session show <id> [--agent] --json`, `talon audit list --session --json` | `TestSessionDetail_EvidenceOnlySessionAndTenantScope`, `TestSession_CostNotComparableIsPartial`, `TestTimelinePageRead_RepeatedPagingIsIndexedNotAScan`, `TestConsoleParity_SessionCurrencyFlag` |
| `evidence/{id}` | `detail {record, verification {state: valid|invalid, checked_at}, outcome}` | `evidence.Store.Detail` (HMAC verified per read), `evidence.OutcomeOf` | `talon audit show <id> --json`, `talon audit verify <id>` | `TestEvidenceDetail_VerificationAndTenantScope`, browser tamper test |
| `costs?tenant=&agent=&breakdown=agents|model|provider|team` | `costs.Report` with `window`, per-window `currencies`, `unpriced_records`, `warnings`, `unavailable_fields`, budgets with `status`; partial when any field is unavailable | `costs.Build` | `talon costs --json` | `TestBuild_*`, `TestCostsCLI_JSONParityWithSharedProjection`, browser cost parity |
| `activity?tenant=&agent=&from=&to=&bucket=5m|1h|24h` | request-class buckets (requests, denied, errors, cost), at most 2016 | `evidence.Store.ActivityBuckets` | — | `TestActivityBuckets_HandExpectations` |
| `configuration?tenant=` | `organization`, `use_cases.items[]`, `mcp_proxy`: allowlisted fields of the gateway, agent and MCP proxy files (`talon ui serve --gateway-config`, `--proxy-config`, `agents_dir`); URLs reduced to `scheme://host`; webhook URLs only as `*_configured`; secret values never copied (vault secret names are); `effective_policy` and `active_generation` always `unknown` | `console.Configuration` over `gateway.LoadGatewayConfig`, `fleetview.Scan`, `mcp.LoadProxyConfig` | `talon validate`, `talon agents show` | `TestConfiguration_*` (including planted-secret leak checks on the DTO and on load errors) |
| `search?q=&tenant=` | use-case names by prefix; exact evidence id; exact correlation id (tenant filter applied in SQL before the bound); exact session id; `unsupported: ["explanation_code"]` | `console.Search`, `evidence.Store.ListByCorrelationIDLimit` | `talon audit show`, `talon session show` | `TestSearch_BoundedExactLookups`, `TestSearch_TenantFilterBeforeLimit` |
| `system` | console version, commit, start; store path, read-only, size, record count, newest record; `runtime: unknown` | the console process and the store file | `talon doctor` | `TestSystem_StoreFactsAndUnknownRuntime` |

### 2.1 Decision, dispatch and downstream (`evidence.OutcomeOf`)

Timeline rows (`records[].outcome`, also on `talon audit list --json`) and evidence detail (`detail.outcome`) carry three separate facts: `decision` (allowed | denied), `dispatch` (not_dispatched | dispatched | unknown | not_recorded), `downstream` (none | completed | rejected | failed | unknown | cache | not_recorded), plus `response_withheld`, `tool` and `basis` (the recorded fact each axis was read from). The rules use only what the writing code records:

| Record | Dispatch | Downstream | Because |
|---|---|---|---|
| `proxy_tool_blocked` | not_dispatched | none | written on the MCP proxy's pre-dispatch deny path |
| `proxy_tool_call` allowed / denied | dispatched | completed (answer withheld when denied) | forwarded and answered; a denied one failed output scanning after the answer |
| `proxy_upstream_error` with a vendor JSON-RPC error | dispatched | rejected | the upstream executed the call and returned its own error |
| `proxy_upstream_error` with status `unknown` | unknown | unknown | handed to the transport, no trustworthy answer |
| `proxy_upstream_error`, other | not_dispatched | none | failed before the transport |
| `gateway` with `cache_hit` | not_dispatched | cache | served from Talon's semantic cache; no provider call |
| `gateway` allowed, no error | dispatched | completed | forwarded and answered |
| `gateway` allowed with an error, or `gateway_failover_attempt` | dispatched only with a recorded provider HTTP status (`failover.upstream_status`), else unknown | failed / unknown | a transport error alone does not prove delivery |
| `gateway` denied | not_dispatched at stage `policy_evaluation` / `pre_execution`; dispatched with the answer withheld at `output_validation`; not_recorded otherwise | | primary explanation stage |
| `action_lifecycle` | from `result_provenance` (observed / not_dispatched / unknown) and `attempt_status`; `authorization_refused` is not_dispatched | | action dispatcher facts |
| anything else | not_recorded | not_recorded | the record type carries no such fact |

Pinned by `TestOutcomeOf_SeparatesDecisionDispatchAndDownstream` (constructed records) and `TestOutcomeOf_RealGatewayRecords` (records the gateway writes: cache hit with the provider call counter unchanged, provider 503 before a fallback, connection failure).

### 2.2 Numbers kept for compatibility

A field listed in a report's `unavailable_fields`, a fleet row's `unavailable_fields` (`spend_day`, `spend_month` when that period's priced records are not all in the row's currency), or a partial section's `availability.unavailable` keeps its historical value only so existing scripts keep parsing. The console renders it as unavailable with its reason (`internal/console/frontend/src/lib/availability.ts`, `lib/costs.ts`, unit-tested); `talon agents` prints `n/a (currencies differ)`. A fleet budget period whose records are not comparable is not evaluated: the row carries the cause `budget_not_comparable` and needs attention instead of being blocked or healthy on a mixed sum (`TestProject_ForeignCurrencyIsNotComparedWithCaps`).

### 2.3 Tests

- **Go:** service and route tests per DTO; CLI ↔ console parity (`internal/cmd/console_parity_test.go`) over one seeded store; real-binary e2e (`tests/e2e/console_e2e_test.go`, `make test-console-smoke`, smoke section 43).
- **Browser:** `tests/browser` (Playwright, Chromium, CI job `browser`) against the built binary over a fixture written through the production store (`tests/browser/seed`): pairing and session expiry, every page's journey, CLI ↔ browser value parity for fleet counters and costs (including a foreign-currency use case and the unavailable tenant month total), and delayed-response tests for evidence, tenant, timeline-paging and cursor changes.
- **Frontend:** type-check, unit tests and a rebuild that must equal the committed embedded assets (CI job `console-frontend`).

## 3. Pending contracts (not shipped)

| Contract | Owner | Until it ships, the console shows |
|---|---|---|
| Runtime facts: process liveness, version and listen address per process, active catalog generation, last reload and rejection, collector freshness | #538 | `runtime.availability.state: unknown`; `active_generation: unknown`; health basis `projected_from_store` |
| Effective policy with per-rule source and precedence | #305 | `effective_policy: unknown` ("Effective policy provenance not available") |
| Session lifecycle `open|completed` and `managed_by` | #401 | today's six session-store states; evidence-observed sessions have no lifecycle |
| Cross-process People Analytics conformance with real MCP proxy and HR backend processes and independent execution counters | #545 | the browser fixture is written through the store, not by running processes |
| Explanation-code search | needs an indexed column | `unsupported: ["explanation_code"]` |
| Raw configuration file view with server-side redaction | not scheduled | semantic summaries only |

## 4. Discrepancies found while defining the contract (historical record)

| # | Where | What differed | Disposition |
|---|---|---|---|
| D1 | `/v1/status` vs fleet | `/v1/status` counts every record class, the fleet counts request-class records | both declared: `/v1/status` carries `counts_scope: all_record_classes` |
| D2 | `talon metrics` | server errors, including 401, fell back silently to a local projection | errors name the cause; only an unreachable default URL falls back, with a warning |
| D3 | `/v1/sessions/{id}` vs `talon session show` | raw row vs row plus evidence summary | the console uses the CLI shape; `/v1/sessions/{id}` unchanged |
| D4 | `/v1/costs/report` | `total_eur` label regardless of currency | console uses the explicit `currency`; endpoint unchanged |
| D5 | `metrics.BudgetStatus` vs `/v1/costs/budget` | summed caps vs one agent's resolved caps | console shows per-use-case budgets only |
| D6 | drift (`talon monitor`) | unsorted map order | sorted; `talon monitor --json` emits rows |
| D7 | session status vocabulary | six states today, #401 plans two | today's states; #401 lands additively |
| D8 | effective-policy provenance | none shipped | owned by #305 |
| D9 | fleet spend | sums ignored currency, so a currency change could block or warn on a mixed sum | fleet rows mark non-comparable periods unavailable and do not evaluate their budgets (#553 review) |

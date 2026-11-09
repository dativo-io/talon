# Operations console read contract

**Status:** current contract of the read-only operations console (#533). Section 2 describes shipped code and the tests that pin it. Section 3 lists contracts that are **pending**; nothing in section 3 is shipped. The console introduces no policy, health, cost, session or decision logic: every value it shows is produced by a Go projection the CLI also uses, and a value no projection can produce is shown as unknown or unavailable.

Companion documents: [operations console guide](../guides/operations-console.md), [console access and pairing](console-access.md), [legacy dashboard migration map](legacy-dashboard-migration-map.md), [authentication and key scopes](authentication-and-key-scopes.md).

## 1. Principles

1. **One Go implementation per concept.** `internal/console` calls the shared projections (`fleet.Project`, `costs.Build`, `session.LoadDetail` / `LoadTimelinePage`, `evidence.Store.Detail`, `evidence.Store.ActivityBuckets`, `events.FromEvidence`, `evidence.OutcomeOf`); the CLI calls the same functions. The browser (`internal/console/frontend`) formats and lays out only.
2. **Durable facts come from the shared store, read-only; live facts come from each process's own runtime record.** The console process opens the evidence and session stores with `mode=ro` (`evidence.OpenReadOnly`, `session.OpenReadOnly`). Live process facts (liveness, version, active catalog generation, reload rejection, loaded config digests) come from the runtime record each `talon serve` writes into the data directory (§2.4); they are never inferred from the store.
3. **Unknown is a value.** Every DTO section carries `availability {state: ok|partial|empty|unavailable|unknown, source, as_of, error, note, unavailable[]}`. A failed query, a missing source or a figure that is not a measurement yields that state with the reason, never a zero and never healthy.
4. **Windows and units are explicit.** Cost and today's figures use UTC day, last 7 days and UTC calendar month (`costs.Window`). Fleet counters use the rolling windows of `fleet.DefaultThresholds` and say so (`counter_windows`). Amounts are in the active pricing table's currency; `*_eur` field names are historical. Amounts are never converted between currencies.
5. **Bounded reads.** Every list has a server maximum and a keyset cursor with documented order; search is exact or prefix and bounded; no request decodes the evidence table in full.
6. **The browser credential reaches only the console.** `/console/v1/*` is served by the console process behind the read-only browser session; the process mounts no data-plane route, and the data plane ignores the console cookie ([console access](console-access.md)).

## 2. Shipped contract

All routes are `GET` under `/console/v1`, behind the browser session, `contract_version: "1"`, each response headed by `meta {contract_version, generated_at, tenant_scope: tenant|all_tenants, tenant_id}`.

| Route | DTO | Produced by | CLI with the same facts | Pinned by |
|---|---|---|---|---|
| `overview?tenant=` | `use_cases` (fleet rows, attention subset, issues, `health_basis: projected_from_store`, `runtime: unknown`, `counter_windows`), `today` (request-class counts, spend over all record classes with a day-window currency check), `recent_events` | `fleet.Project` via `fleetview.ProjectOffline`; `ActivityBuckets`-class counts; `events.FromEvidence` | `talon agents --json`, `talon costs --json` | `TestConsoleParity_UseCases`, `TestOverview_HandExpectations`, `TestToday_ForeignCurrencyIsPartial`, browser journeys |
| `use-cases`, `use-cases/{name}` | fleet rows; detail adds `costs`, 24 h `activity`, `recent_sessions`, `effective_policy` (points at the route below) | as above, `costs.Build` | `talon agents show <name> --json` | `TestUseCaseDetail_SessionsCostsActivity`, `TestUseCases_StateTheirCounterWindows` |
| `use-cases/{name}/effective-policy?tenant=` | `report` (§2.5): `current_files`, `loaded`, `effective` (values, `rules[]` with `winner`, `precedence`, `candidates[]`; per-provider `effective_digest`), `mcp_boundary.tools[]`, `last_decision`, `notes`; `partial` naming `report.effective.proven_active` unless a running process proves it loaded the current file; `404` for an unknown use case | `effective.Build` over `fleetview.Scan`, `gateway.ExplainEffectivePolicy` (the resolver itself), `mcp.EvaluateToolAccess`, `runtimestatus.ProveLoaded`, `evidence.Store` | `talon agents show <name> --effective [--proxy-config] --json` | `TestConsoleParity_EffectivePolicy`, `TestBuild_*` (`internal/effective`), `TestExplainEffectivePolicy`, `TestEvaluateToolAccess`, `TestProveLoaded`, browser use-case journey |
| `sessions?tenant=&agent=&status=&limit=&before=&before_id=&observed_before=&observed_before_id=&observed_before_agent=` | managed rows (`session.Store.ListRecent`, cursor `created_at+id`) and evidence-observed ids with no row (`ListObservedSessions`, cursor `last_seen+session_id+agent_id`), each with its own availability | session and evidence stores | `talon session list --json` | `TestSessionsPaging`, `TestSessions_RowBackedSessionIsNotAlsoObserved`, `TestRoutes_ObservedCursorLosslessAcrossAgents` |
| `sessions/{id}?agent=&timeline_limit=&timeline_after=&timeline_after_id=`, `sessions/{id}/timeline` | `detail` (row, ambiguity, `evidence.SessionSummary` with `currencies`, `cost_comparable`) plus one timeline page; `/timeline` pages without recomputing the summary; partial on `detail.summary.total_cost` when not comparable | `session.LoadDetailFor`, `evidence.Store.SessionSnapshotRead`, `TimelinePageRead` | `talon session show <id> [--agent] --json`, `talon audit list --session --json` | `TestSessionDetail_EvidenceOnlySessionAndTenantScope`, `TestSession_CostNotComparableIsPartial`, `TestTimelinePageRead_RepeatedPagingIsIndexedNotAScan`, `TestConsoleParity_SessionCurrencyFlag` |
| `evidence/{id}` | `detail {record, verification {state: valid|invalid, checked_at}, outcome}` | `evidence.Store.Detail` (HMAC verified per read), `evidence.OutcomeOf` | `talon audit show <id> --json`, `talon audit verify <id>` | `TestEvidenceDetail_VerificationAndTenantScope`, browser tamper test |
| `costs?tenant=&agent=&breakdown=agents|model|provider|team` | `costs.Report` with `window`, per-window `currencies`, `unpriced_records`, `warnings`, `unavailable_fields`, budgets with `status`; partial when any field is unavailable | `costs.Build` | `talon costs --json` | `TestBuild_*`, `TestCostsCLI_JSONParityWithSharedProjection`, browser cost parity |
| `activity?tenant=&agent=&from=&to=&bucket=5m|1h|24h` | request-class buckets (requests, denied, errors, cost), at most 2016; tenant "" spans every tenant, the same scope as `overview` with no tenant | `evidence.Store.ActivityBuckets` | — | `TestActivityBuckets_HandExpectations`, `TestOverviewAndActivityShareOneScope` |
| `configuration?tenant=` | `organization`, `use_cases.items[]`, `mcp_proxy`: allowlisted fields of the gateway, agent and MCP proxy files (`talon ui serve --gateway-config`, `--proxy-config`, `agents_dir`); URLs reduced to `scheme://host`; webhook URLs only as `*_configured`; secret values never copied (vault secret names are); `active` (per current process: generation, whether the agent files match it, reload rejection, loaded vs current proxy and gateway config digests) and per use case `active` (`loaded_matches_file` / `loaded_differs_from_file` / `not_in_active_generation` / `unknown`, proved by policy digests); `effective_policy` points at the per-use-case route | `console.Configuration` over `gateway.LoadGatewayConfig`, `fleetview.Scan`, `mcp.LoadProxyConfig` | `talon validate`, `talon agents show` | `TestConfiguration_*` (including planted-secret leak checks on the DTO and on load errors, and `TestConfiguration_ActiveVersusFiles`) |
| `search?q=&tenant=` | one tenant for every result type (tenant "" = `default`, reported in `meta`); use-case names by prefix; exact evidence id; exact correlation id (tenant filter applied in SQL before the bound); exact session id; `unsupported: ["explanation_code"]` | `console.Search`, `evidence.Store.ListByCorrelationIDLimit` | `talon audit show`, `talon session show` | `TestSearch_BoundedExactLookups`, `TestSearch_TenantFilterBeforeLimit`, `TestSearch_OneScopeForEveryResultType` |
| `system` | console version, commit, start; store path, read-only, size, record count, newest record; `runtime` (roles, processes, rejected records, §2.4) | the console process, the store file, `runtimestatus.Reader.Assess` | `talon doctor` | `TestSystem_StoreFactsAndUnknownRuntime`, `TestRuntime_*`, `TestE2E_ConsoleRuntime_ProcessTruth` |

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

A field listed in a report's `unavailable_fields`, a fleet row's `unavailable_fields` (`spend_day`, `spend_month` when that period's priced records are not all in the row's currency), or a partial section's `availability.unavailable` keeps its historical value only so existing scripts keep parsing. The console renders it as unavailable with its reason (`internal/console/frontend/src/lib/availability.ts`, `lib/costs.ts`, unit-tested); `talon agents` prints `n/a (currencies differ)`. Unpriced model calls are different: the cost report counts them (`unpriced_records`) and says the amounts understate spend, but fleet health does not use that count as a signal, so a use case can read healthy while some of its calls carry no price. A fleet budget period whose records are not comparable is not evaluated: the row carries the cause `budget_not_comparable` and needs attention instead of being blocked or healthy on a mixed sum (`TestProject_ForeignCurrencyIsNotComparedWithCaps`).

### 2.4 Runtime records (#538)

Each `talon serve` process publishes `<data_dir>/runtime/<instance>.json` (`internal/runtimestatus`) on start, every 5 s, and once more with `state: stopped` on graceful shutdown. Writes are atomic (temp file + rename). The record holds: instance id, roles (`mcp_proxy`, `gateway`, `native`), version and commit, pid and host, start and write time, a per-instance `sequence`, the installation fingerprint (HMAC of a fixed label under the evidence signing key; the key itself is never written), and, from the process's reloader, the active catalog generation, scan digest, activation time, reload rejection with causes and the per-agent policy digests; plus the path, sha256 and load time of `--proxy-config` / `--gateway-config`.

The console reads the directory read-only. `runtimestatus.Reader.Assess` derives, in Go:

| State | When |
|---|---|
| `running` | heartbeat younger than 3 heartbeats |
| `stale` | older than 3, younger than 12 heartbeats (hung, overloaded or killed) |
| `offline` | a recorded graceful shutdown, a heartbeat older than 12 beats, or a role the configuration expects that no process has reported |
| `not_configured` | a role neither expected by the console's configuration (`--proxy-config`, an enabled gateway config) nor reported |
| `unknown` | the runtime directory cannot be read, the console was started without its data directory and signing key, or the role's configuration exists but cannot be parsed (a broken gateway config is never read as `not_configured`) |

Records with another installation's fingerprint, an unknown schema, malformed JSON or over 64 KiB are listed as `rejected`, never combined. Every running instance is `current`; a role reports its most relevant instance (running before stale before offline, newest first within a state), so a newer instance that stopped never hides an older one that still serves. Instances that neither run nor represent a role stay listed as history with their own state. A record with a lower `sequence` than one already seen never replaces it. The console has no network path to the data plane, no Docker socket and no new listener; the store's sessions and evidence are read independently of runtime state.

### 2.5 Effective policy (#305)

`effective.Build` reports four layers that are never merged into one claim:

1. **Current files**: the agent file (canonical policy digest: comments and formatting are not policy), the gateway config and the MCP proxy config, each with its sha256 or why it is unusable.
2. **Loaded**: `runtimestatus.ProveLoaded` compares the current file's policy digest with what the current *running* processes report (§2.4): `loaded_matches_file`, `loaded_differs_from_file`, `not_in_active_generation`, or `unknown` (records unreadable, no running process reports a catalog, processes disagree, or a digest is missing). A stale or history instance proves nothing.
3. **Effective**: `gateway.ExplainEffectivePolicy` calls `ResolveEffectivePolicy`, the function the gateway enforces with, and explains caps (daily, monthly, session: use case replaces the organization default when > 0, the organization ceiling binds too, tightest positive wins), `pii_action` (organization floor, use case only tightens), `forbidden_tools` (union of organization, provider and use-case lists), `tool_policy_action` (provider over organization default, use case only tightens) and `allowed_models` (use-case list plus organization and provider hard constraints). Every rule's effective value is the resolver's; `TestExplainEffectivePolicy` pins that the explanation never disagrees with it. `providers[].effective_digest` is the digest the gateway signs into evidence as `policy_digests.effective` for that provider. Proof is per enforcement boundary (`runtimestatus.ProveGateway`, `ProveProxy`): `effective.proven_active` is true only when every running **gateway** reports the current agent file's policy digest *and* loaded the current gateway config (sha256 of the bytes it read at start); otherwise `effective.proof` says why (`no_running_process`, `loaded_differs_from_files`, `unknown`) and `basis` says the values are compiled from the current files. A running MCP proxy proves nothing about the gateway policy, and a gateway config edited without a restart is never called active.
4. **MCP boundary**: for each tool the proxy config or the agent names, `mcp.EvaluateToolAccess` runs the proxy's own pre-dispatch checks (`forbidden_tools` match, then the proxy policy) and says where a denial happens. A config that cannot be loaded yields an error and no decisions. `mcp_boundary.proven_active` is proved on its own: every running **MCP proxy** loaded the current proxy config.
5. **Last decision**: the newest evidence record of the use case, re-read through the verifying path (`evidence.Store.Detail`, `verification: valid|invalid`); a record whose signature fails is still pointed at but reads `unverified` for both digest comparisons and is never presented as authenticated. Otherwise: its decision and dispatch outcome, and whether its recorded agent and effective digests equal the current ones (`same` / `different` / `not_recorded`; `matches_current:<provider>` / `differs_from_current` / `not_recorded`). MCP proxy records carry no policy digests and read `not_recorded`, never assumed equal.

The report is read-only: files, runtime records and the store. It is not a dry run of a request (no model, prompt or PII content is evaluated) and does not cover OPA rules beyond what the proxy policy decides for a bare tool name.

### 2.3 Tests

- **Go:** service and route tests per DTO; CLI ↔ console parity (`internal/cmd/console_parity_test.go`) over one seeded store; real-binary e2e (`tests/e2e/console_e2e_test.go`, `make test-console-smoke`, smoke section 43).
- **Browser:** `tests/browser` (Playwright, Chromium, CI job `browser`) against the built binary over a fixture written through the production store (`tests/browser/seed`): pairing and session expiry, every page's journey, CLI ↔ browser value parity for fleet counters and costs (including a foreign-currency use case and the unavailable tenant month total), and delayed-response tests for evidence, tenant, timeline-paging and cursor changes.
- **Cross-process (People Analytics, #545):** `TestE2E_PeopleAnalytics_CrossProcess` (`tests/e2e/people_analytics_e2e_test.go`, CI job `e2e`; with the browser leg `make test-people-analytics-live` and the CI `browser` job) runs an HR MCP backend that counts the calls it receives, the production `talon serve --proxy-config` and `talon ui serve`. The backend's counters prove a valid `hr_aggregate_sql` query was dispatched once, `hr_employee_export` never reached it, and an `hr_aggregate_sql` query with invalid SQL (the backend accepts only an aggregate `SELECT … GROUP BY`) was allowed by Talon, reached the backend once and is shown as rejected by the destination, not as a Talon denial. The effective policy reads MCP decisions proven by the running proxy and the gateway policy not proven (no gateway runs); the last decision's signature is verified. It also checks client-asserted session and correlation ids, signature verification in the console and with `talon audit verify`, console = CLI for the session, evidence, search, effective policy and runtime, zero spend with no gateway configured, 401 without a console session, a wrong workload key reaching nothing, SIGKILL (stale, nothing dispatched, evidence readable), restart (a new instance extending the same session), and a record edited in the database after signing reading as invalid. `tests/browser/live` checks the same installation in Chromium while the data plane runs.
- **Frontend:** type-check, unit tests and a rebuild that must equal the committed embedded assets (CI job `console-frontend`).

## 3. Pending contracts (not shipped)

| Contract | Owner | Until it ships, the console shows |
|---|---|---|
| Session lifecycle `open|completed` and `managed_by` | #401 | today's six session-store states; evidence-observed sessions have no lifecycle |
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
| D8 | effective-policy provenance | none shipped | shipped in #305 (§2.5) |
| D9 | fleet spend | sums ignored currency, so a currency change could block or warn on a mixed sum | fleet rows mark non-comparable periods unavailable and do not evaluate their budgets (#553 review) |

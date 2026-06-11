# Governance Control Matrix

Every request that passes through Talon enters through one of five entry
paths. This matrix is the single source of truth for which governance
controls run on each path, which limitations are **by design** (and why),
and how parity across paths is enforced so the posture cannot silently
drift.

Audience: operators preparing audits, contributors adding new entry paths,
and reviewers assessing claims made in RoPA / Annex IV exports.

## Entry paths

| # | Path | How it is invoked | What Talon sees |
|---|------|-------------------|-----------------|
| 1 | **Agent runner** | `talon run`, cron triggers, webhooks | Full prompt, attachments, tool calls, response |
| 2 | **LLM gateway** | `talon serve --gateway` (OpenAI-compatible HTTP proxy) | Full request/response bodies in transit |
| 3 | **MCP server** | `talon serve` → `POST /mcp` (embedded tools) | Full tool arguments and results; tools execute in-process |
| 4 | **MCP proxy** | `talon serve --proxy-config` (upstream MCP vendors) | Full tool arguments and results in transit |
| 5 | **Graph adapter** | `POST /v1/graph/events` (LangGraph, LangChain, SDKs) | **Governance events only** — content never transits Talon |

## Control × path matrix

Legend: ✅ enforced · ⚠️ limited by design (see notes) · — not applicable

| Control | Agent runner | LLM gateway | MCP server | MCP proxy | Graph adapter |
|---|---|---|---|---|---|
| Policy evaluation (OPA) | ✅ | ✅ | ✅ | ✅ | ✅ |
| PII classification — input | ✅ prompt + attachments | ✅ request body | ✅ tool args | ✅ tool args | ⚠️ N/A (1) |
| PII classification — output | ✅ response | ✅ response body | ✅ tool result | ✅ tool result | ⚠️ N/A (1) |
| Data-flow evidence (`data_flow`) | ✅ every egress | ✅ every egress | ✅ every tools/call | ✅ every proxied call | ⚠️ orchestrator-reported (2) |
| Destination region resolution | ✅ provider registry | ✅ provider registry | ✅ `LOCAL` (in-process) | ✅ declared upstream region, else `unknown` | ⚠️ always `unknown` (3) |
| Cost tracking / budgets | ✅ | ✅ | — no LLM call | — no LLM call | ⚠️ self-reported cost (4) |
| Signed evidence (HMAC) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Explanations on every record | ✅ | ✅ | ✅ | ✅ | ✅ |
| Blocked traffic also recorded | ✅ `blocked` disposition | ✅ | ✅ | ✅ | ✅ denied run/step records |

### By-design notes

1. **Graph adapter — no content classification.** External runtimes
   (LangGraph etc.) call their model providers directly; only governance
   events reach Talon. No prompt or response content is available to
   classify. Records on this path carry an empty `detector` and no entity
   types — they never claim a scan that did not run.
2. **Graph adapter — orchestrator-reported flows.** When the runtime
   reports a model (or non-zero cost), Talon records one
   `prompt → external:<framework>` flow item marked
   `source_detail: orchestrator-reported`. When there is no sign any model
   call happened (no model, zero cost), **no** flow is recorded — claiming
   one would overstate. Routing the traffic through the Talon gateway
   upgrades this path to fully observed, classified data flow.
3. **Graph adapter — region `unknown`.** Talon never guesses
   jurisdictions. The external runtime's provider region is not declared
   anywhere Talon can verify, so it is `unknown` — which surfaces in RoPA
   Section 6 as an unresolved transfer, deliberately prompting the operator
   to gateway the traffic or accept the gap.
4. **Graph adapter — self-reported cost.** Cost arrives in run events from
   the orchestrator. Talon signs what was reported; it cannot independently
   meter calls it does not proxy.
5. **MCP server / proxy — no cost tracking.** Tool calls involve no LLM
   spend on Talon's side; cost controls are exercised on the runner and
   gateway paths.

## The parity contract

Every record stored through `evidence.Store.Store` must satisfy:

1. `tenant_id` and `correlation_id` are set.
2. `explanations` is non-empty (hard requirement — store fails otherwise).
3. **Model call ⇒ data flow**: any record with `execution.model_used` set
   carries a `data_flow` section saying where the data went (or that it was
   blocked). Exemptions: the graph adapter's `unknown_graph_model`
   placeholder when no model call was observed, and control-plane
   `mode_change:` markers (no data egresses on a mode change).
4. A present `data_flow` section has at least one item.

Enforced in three layers:

| Layer | Mechanism | Failure mode |
|---|---|---|
| Runtime | `evidence.ValidateGovernedRecord` runs on every store; violations log `governance_parity_violation` warnings (fail-open — evidence is never dropped) | Drift visible in logs/OTel immediately |
| Unit tests | `TestGovernanceParity_EntryPathContract` (`internal/evidence/parity_test.go`) enumerates all entry paths; per-path packages assert their own data-flow shape | CI fails |
| Smoke tests | Section 29 verifies black-box that model-call records in the live evidence DB carry `data_flow` | Release gate fails |

## Adding a new entry path

A new evidence-producing path (e.g. A2A in Phase 2) must, before merge:

1. Evaluate policy before any egress or execution.
2. Classify input and output content **if the content transits Talon**;
   otherwise document the by-design limitation here.
3. Record `data_flow` on every record that represents data movement,
   including blocked movement (`disposition: blocked`).
4. Resolve destination region from declared/registered facts only — never
   guess; use `unknown` otherwise.
5. Add a row to `TestGovernanceParity_EntryPathContract` and to the matrix
   above.

The runtime guardrail will flag any path that ships without step 3.

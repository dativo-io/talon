# Gateway error contract

**Status:** stable · **Scope:** every error the Talon gateway returns to a client, on both wire families.

This is the machine-code contract clients build retry logic against (#142). The codes below are **public API**: they are stable identifiers, additive-only, and travel in the provider-native error envelope of the route's wire family — the OpenAI family (`error.type` and `error.code`) and the Anthropic family (`error.type`) — via the documented `code: message` prefix convention. A denial reason whose text begins with a registered code renders that code as the error type; anything else falls back to the family's status-mapped type (OpenAI: `invalid_request_error`; Anthropic: the [status-mapped enum](https://docs.anthropic.com/en/api/errors) — `invalid_request_error`, `authentication_error`, `permission_error`, `not_found_error`, `request_too_large`, `rate_limit_error`, `overloaded_error`, `api_error`).

Talon never returns a stack trace or internal error dump in any envelope. Upstream provider errors pass through in the provider's own shape.

## Contract table

| HTTP status | Machine code | Trigger | Retriable? |
|---|---|---|---|
| 401 | `invalid_agent_key` | Missing/unknown Talon agent key | No — fix the credential |
| 403 | `agent_disabled` | The agent is disabled (`enabled: false`, #268) | No — operator action required |
| 403 | `model_not_allowed` | Model outside the agent/org/provider allow- or block-lists | No — change model or policy |
| 403 | `provider_not_allowed` | Provider outside the agent/org provider allowlist | No — change route or policy |
| 401 | `workload_identity_required` | Delegated path (#482): no verified workload identity — the runtime's caller token was missing, forged, expired or for the wrong issuer/audience; the message names the stable `workload_identity_*` failure code | No — fix the runtime's identity configuration |
| 403 | `workload_identity_unbound` | Delegated path: the verified subject is bound to no Talon AI use case (`agent.workload_identity.bindings`) | No — bind the subject in the agent file |
| 403 | `destination_not_governed` | Delegated path: no enabled provider `base_url` matches the destination host the runtime asked about (fail closed) | No — configure the provider or unbind Talon from that host in the runtime policy |
| 403 | `data_tier_exceeded` | Request data tier above the agent/org maximum | No — content/policy decision |
| 403 | `tool_policy_violation` | Request declares forbidden tools and the effective action is `block` | No — remove the tools or change policy |
| 403 | `budget_exceeded` | Agent/org daily or monthly cost cap would be exceeded (deny before provider; carries `cost_budget` evidence, #144) | Not until the budget window resets or the cap changes |
| 403 | `session_budget_exceeded` | Session cap: settled + reserved spend + estimate exceeds `max_session_cost` (#144 atomic reservation) | Not within this session |
| 403 | `pricing_unavailable` | A spending cap binds the agent and `pricing/models.yaml` has no entry for the requested (provider, model) — the request cannot be priced, so it is not admitted against the cap; applies to failover candidates too | No — in `pricing/models.yaml` add the model under the provider, `inherit: <catalog provider>` for an aliased endpoint, or `models: {}` for a self-hosted zero-cost endpoint ([provider registry](provider-registry.md#cost-estimation)) |
| 503 | `budget_unavailable` | A spending cap binds the agent and the state it is checked against could not be read: the evidence-store spend read, or the session-store read/reservation. Fail-closed, nothing dispatched; the signed deny carries `agent_budget_unavailable` / `session_budget_unavailable` naming the store | **Yes** — retriable once the store recovers |
| 403 | `egress_tier_destination_disallowed` (and the `egress_*` family) | Egress policy denies this data tier × destination | No — policy decision |
| 400 | `pii_policy_violation` | PII block, or recognized PII remains after redaction (#209) | No — the content is the problem |
| 400 | `model_required_for_policy_evaluation` | Request omits `model` while a model policy is active | No — send a model |
| 429 | `rate_limited` | Gateway rate limit (global or per-agent) exceeded | **Yes** — back off and retry |
| 502 | `scanner_unavailable` | PII scanner outage, redaction failure, or unverifiable redaction — fail-closed (#209) | **Yes** — retriable once the scan engine recovers |

Statuses without a machine code (unreadable body, invalid orchestration header, method not allowed, unknown provider) keep the family's status-mapped type; they indicate a malformed call, not a policy decision.

## One registry across surfaces

The machine codes above are canonical entries of Talon's governance-code registry (`internal/govcode`), shared with the Action Gateway (`error.code` / `operation.outcome_code`, [Action Gateway](action-gateway.md)) and the MCP governance extension (`error.data["io.dativo.talon/governance"]`, [MCP governance extension](mcp-governance-extension.md)). The same denial carries the same code on every surface; only the envelope differs. `TestErrorContract_CodesRegisteredInGovcode` pins the registration.

## Semantics clients may rely on

- **Retriability is a property of the code, not the status.** A 403 `budget_exceeded` and a 403 `tool_policy_violation` are both permanent for the request as sent; a 502 `scanner_unavailable`, a 503 `budget_unavailable` and a 429 `rate_limited` are transient. Talon's own same-provider retry logic (#139) classifies by exactly this split.
- **Exhaustion and system failure are different codes.** `budget_exceeded` / `session_budget_exceeded` mean the cap was reached (the deny record carries the `cost_budget` / `session_budget` detail); `budget_unavailable` means Talon could not establish the state a binding cap needs and refused to guess (no detail, a store annotation instead); `pricing_unavailable` means the request could not be priced at all. A client must not treat the last two as "over budget".
- **One normalization layer, two families.** The same machine code appears on both wire families for the same denial; only the envelope shape differs. Pre-forward denials on `stream: true` requests return a non-streaming JSON error body with the status — protocol-correct for both vendors. Mid-stream failures terminate with the family's terminal event (`event: error` / `response.failed`), never a fabricated success.
- **Denial codes match evidence.** The code in the wire envelope is the same machine code recorded in the signed evidence record's policy reasons and projected into session summaries (`denied_by_reason`) and the dashboard — one vocabulary end to end.
- **Additive evolution.** New codes may appear; existing codes keep their meaning and status class. Clients should treat an unrecognized code by its status class.

## Where it is enforced in code

`normalizeGatewayError` (internal/gateway/errors.go) lifts the `code:` prefix into the envelope; deny reasons carry their codes at the source — the Rego rules (`internal/policy/rego/gateway_access.rego`) for policy denials, and the gateway deny sites for auth, rate-limit, provider-allowlist, tool, scanner failures and the budget preconditions (`budget_unavailable`, `pricing_unavailable` in internal/gateway/decision.go). The contract is asserted by `TestErrorContract_DocumentedCodes` (internal/gateway/errors_test.go).

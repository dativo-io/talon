# LLM gateway invariants

These rules apply when changing `internal/gateway/**` (the `/v1/proxy` data plane and the delegated OpenShell evaluation path).

## One decision, two surfaces

- `decidePreDispatch` (`decision.go`) is the single pre-dispatch decision for the HTTP proxy (`ServeHTTP`) and the delegated path (`EvaluateDelegated`). A new gate, precondition or annotation goes there once; never add it to one surface only.
- The deny closure releases every claim the decision took (agent in-flight reservation, session reservation). Any new reservation must be released on every exit: deny, policy error, candidate refusal, after the record committed, and on panic-free early returns in the caller.

## Budget governance is preventive and fails closed

- A configured cap is a declaration; the state it is checked against is a precondition, not an input with a default of zero. When a cap binds and that state cannot be read (evidence-store spend read, session-store read or reservation), deny `budget_unavailable` (503, retriable) with nothing dispatched and the store annotation (`agent_budget_unavailable` / `session_budget_unavailable`) on the signed deny. Exhaustion (`budget_exceeded`, `session_budget_exceeded`) and unavailability are different codes; never blur them.
- The organization baseline always binds a daily/monthly cap (100/2000 when unset), so "a cap binds" is effectively always true for gateway agents; reason about every request as capped.
- A request that cannot be priced (provider or model absent from the pricing table) is denied `pricing_unavailable` (403) under a binding cap, on the primary route and for every failover candidate. Never substitute a fallback price; `models: {}` and `inherit:` in the table are the only ways to make a provider priceable.
- Admission accounting: the session cap is enforced by atomic reservation in the session store (#144: reserve, settle, release); the agent daily/monthly caps by the process-local in-flight ledger (`agent_reserve.go`, reserve-then-read). A failover candidate is admitted at its own estimate: adjust the agent claim, re-read settled spend, reserve a dearer candidate's difference in the session store before the session rule runs, and hand both back if refused. Do not reintroduce "the primary's estimate stands for the fallback".
- Exactly one settlement per request across streaming, same-provider retries and failover. When the evidence record fails to commit after dispatch, the session is still settled and the charge is remembered in-process (`noteUnrecorded`) and logged as `gateway_settled_cost_unrecorded`; this is a documented, process-local limitation, not a promise that every charge is counted.
- What a cap guarantees is stated in `LIMITATIONS.md` §7 (admission, not the provider's invoice; estimate-based; process-local ledger). Change the code and that paragraph together.

## Registries that drop what they do not know

- Evidence annotations are allowlisted in `evidence.go`; an unlisted annotation is dropped with `dropping_unsupported_gateway_annotation`. Register before you emit.
- Machine codes come from `internal/govcode`; deny reasons carry `code: message` and `normalizeGatewayError` lifts the code into the OpenAI and Anthropic envelopes. Follow `.claude/rules/contract-surfaces.md` for the registration set.
- External runtimes wrap Talon denials in their own vocabulary (OpenShell: `middleware_denied`). The Talon code in evidence is the truth; debug from there.

## Pricing in tests

- Black-box fixtures (`internal/server`, `tests/integration`, `tests/e2e`) use the production estimator over the embedded catalog: `gateway.PricingTableEstimator(pricing.LoadOrDefault(""))`. In that catalog `ollama` is explicitly zero-cost; a test that asserts positive spend must route through a metered catalog provider.
- `testTableEstimator` (gateway unit helpers) is a known-price stand-in for synthetic providers only. A test that validates pricing behaviour uses the real table; never fake `PricingKnown`.
- `defaultCostEstimator` reports `PricingKnown=false`; a fixture that passes a nil estimator is denied `pricing_unavailable` by design.

## Proof standards

- Preventive claims count the upstream (`budgetUpstream` and similar counting handlers) and assert dispatch counts, not only status codes.
- Concurrency tests are deterministic: a fixed burst released behind a barrier, fixed estimates, separate or shared sessions as the claim requires, no sleeps. Before merging a race fix, show the test fails with the fix disabled.
- Failure-injection hooks (`budgetReadHook`, `evidenceWriteHook`) exist for the unit suite only; they must stay unexported and unset in production wiring.

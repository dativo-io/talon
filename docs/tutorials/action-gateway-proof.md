# Prove exact-action authorization before business execution

**Five-minute evaluator proof (no provider API key).** This exercises the shipped **HTTP Action Gateway**, not MCP `tools/call` or native tool-execution convergence. It uses an in-process counting mock as the downstream business API; no real refund or mutation is performed.

## Run

From the Talon repository root, with Go and the dependencies needed to build the binary:

~~~bash
bash scripts/action-smoke.sh
~~~

The script runs the built-binary end-to-end test `TestE2E_ActionGateway` using `go test -tags=e2e` and prints the assertions. It requires neither a provider key nor an external action service. The same proof is part of the [Action Gateway reference](../reference/action-gateway.md).

## What is checked

| Scenario | Expected business effect | Evidence expectation |
|---|---|---|
| **Policy DENY** for a prohibited action | **0** calls to the mock target | Signed denial with the operation identity |
| **REQUIRE_APPROVAL** established | **0** calls | Approval pending, exact action and arguments bound |
| Authorized human reviewer decides `approve` | Still **0** calls | Authorization recorded, not treated as execution |
| Runtime later claims one permitted attempt | Exactly **1** call | Revalidated current policy and an evidenced attempt/result |
| Exact replay or unchanged claim after dispatch | Still **1** total | Idempotent operation state; no duplicate effect |
| Same operation ID with changed payload | No additional call | Conflict rather than changed authorized subject |
| Ambiguous post-dispatch outcome | No blind retry | `unknown`, preserving possible-effect truth |
| Restart and evidence verification | No duplicate call | Lifecycle survives restart; signatures valid until deliberately tampered in the test |

The smoke includes `talon audit verify --operation <operation-id>` and a deliberate database-tamper negative case. A valid signature proves integrity of a Talon record; it does **not** prove that an external service behaved correctly or that all possible actions were intercepted.

## Try it with your own application

1. Declare one trusted HTTP action and its input schema in `agent.talon.yaml`; use the [Action Gateway reference](../reference/action-gateway.md) for the exact configuration shape and route/auth contracts.
2. Establish the exact logical operation at `POST /v1/action-operations` using the agent key. Check `DENY`, `REQUIRE_APPROVAL` or `ALLOW`.
3. If approval is required, let a separate **tenant-scoped local approver** decide at `POST /v1/approvals/{id}/decisions`; the decision performs no dispatch.
4. Let the authorized runtime later claim `POST /v1/action-operations/{operation_id}/attempts`; Talon revalidates and dispatches the HTTP action at most once.
5. Inspect `talon audit list`, `talon audit show <evidence-id>` and `talon audit verify --operation <operation-id>`.

**Current limits:** only the `talon_forwarded` HTTP adapter has bound approvals and at-most-once Talon dispatch. MCP-discovered definitions are catalogued but not executable by that adapter. MCP/native action convergence, Tasks continuation, SSO reviewer identities, external execution profiles and operator reconciliation of `unknown` are not shipped. Read [LIMITATIONS §10](../../LIMITATIONS.md).

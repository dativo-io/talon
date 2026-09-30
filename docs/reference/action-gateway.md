# Action Gateway — exact governed actions (#458 minimum proof)

**Status:** shipped first spine (`talon_forwarded` profile, public HTTP adapter). Contracts: #429 (API), #426 (state), #427 (catalog/binding), #428 (approver), #146 (evidence). Not yet converged onto this spine: MCP proxy, native runner tool calls, Plan Review (#431/#430). See `LIMITATIONS.md` §10.

Talon governs one **consequential action** as one immutable **operation**: the caller names a catalogued action and its arguments plus a stable `operation_id`; Talon validates against the trusted catalog, binds the complete normalized payload into an exact digest, evaluates the authoritative verdict, and persists the operation together with its signed evidence. A human approval, when required, binds that exact digest. Only a runtime claim can release an effect, and Talon releases it at most once.

```text
runtime ── POST /v1/action-operations ──▶ validate catalog + schema
                                          canonical payload → exact digest
                                          verdict: DENY | REQUIRE_APPROVAL | ALLOW
                                          persist operation (+ pending approval)      [evidence #1..2]
reviewer ─ POST /v1/approvals/{id}/decisions ─▶ authorized decision, ZERO dispatch    [evidence]
runtime ── POST /v1/action-operations/{id}/attempts ─▶ revalidate current catalog/policy
                                          claim ONE attempt (committed first)          [evidence]
                                          mark dispatch boundary (committed first)     [evidence]
                                          dispatch once → observed result | UNKNOWN    [evidence]
```

## Declaring actions (`agent.talon.yaml`)

```yaml
capabilities:
  forbidden_tools: [delete_customer]        # DENY source for actions and gateway tools

actions:
  definitions:
    create_refund_request:
      description: Create a refund request for a support ticket
      input_schema:                          # JSON Schema; must describe an object
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: number}
          currency: {type: string, enum: [EUR, USD]}
      review:
        fields: [ticket_id, amount, currency] # reviewer projection; ALL fields stay bound
      destination: {type: http, url: "https://refunds.internal/v1/refunds", method: POST}

policies:
  approvals:
    expires_after: 30m                       # pending decision + first-attempt usability
    rules:
      refund-request:
        actions: [create_refund_request]     # exact names or trailing-* prefix
        approver_groups: [support-leads]
```

Rules: `DENY > REQUIRE_APPROVAL > ALLOW`. An action absent from the catalog is `action_not_found` (never executed). Plaintext `http` destinations are accepted for loopback only. Credentials never appear in a definition; the destination identity (`method + URL`) is bound into the digest.

## Binding and identity

The operation digest binds tenant, agent, canonical action name, the **complete canonical argument payload** (sorted keys, source-literal numbers so `50` ≠ `50.0`, explicit `null` ≠ absent, no exclusions in v1), the schema digest, binding profile `talon/whole-payload/v1`, the approval-relevant policy digest, execution profile `talon_forwarded` and the destination identity.

- `operation_id` is caller-provided (`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`), unique per tenant + agent. Volatile request/trace/tool-call ids are not operation identity.
- Same id + same digest → the existing operation and state (`created: false`), never a new effect.
- Same id + different digest → `409 operation_conflict`, nothing mutated, conflict evidenced on the existing operation.

## Endpoints

Runtime routes take the AI use case's **agent key** (`Authorization: Bearer <agent key>`); admin keys are refused. The decision route takes an **approver credential** only.

| Route | Result |
|---|---|
| `POST /v1/action-operations` `{operation_id, action, arguments}` | `201` allowed (`operation_status: authorized`), `202` approval pending, `403` denied (persisted, replay-stable), `200` exact replay, `409 operation_conflict`, `404 action_not_found`, `422 action_schema_invalid` / `operation_id_required` |
| `GET /v1/action-operations/{operation_id}` | safe projection (verdict, statuses, approval, latest attempt, reviewer projection — never raw arguments) |
| `POST /v1/action-operations/{operation_id}/attempts` | claim + dispatch; `200` with `attempt.status` `succeeded` / `failed` / `unknown`; `409 approval_pending` (with `Retry-After`), `409 operation_already_succeeded`, `409 operation_outcome_unknown`, `409 attempt_already_in_progress`, `409 approval_binding_stale`, `409 approval_expired`, `403 policy_denied` / `approval_required` / `approval_rejected` |
| `GET /v1/approvals/{approval_id}` | approval + operation projection (owner agent key) |
| `POST /v1/approvals/{approval_id}/decisions` `{decision: approve\|reject, reason}` | `200` decided; `401 approval_not_authorized` (no/unknown approver credential, admin key, agent key, or a group not named by the matched rule — refusals are evidenced); `409 approval_already_decided`; `409 approval_expired` |

Error envelope: `{"error": {"code", "message", "operation"?}}`. The code is the contract; HTTP status alone is insufficient.

## Semantics that are tested

- **DENY** → zero downstream calls; a denied operation cannot be claimed.
- **REQUIRE_APPROVAL** → zero calls while pending; a claim returns `approval_pending`.
- **Decision ≠ execution.** An approved decision changes approval state only; dispatch count stays 0 until a runtime claim. Reject/expire close the operation (`cancelled`).
- **Revalidation at claim.** Current catalog definition and approval-relevant policy digest must match the bound operation (`approval_binding_stale` otherwise); a current DENY blocks even an approved operation; first-attempt claim checks approval expiry.
- **At most one effect.** Concurrent claims yield exactly one attempt (version-guarded conditional update); a succeeded operation is permanently closed.
- **Known failure vs UNKNOWN.** A transport error before the request is written is `failed / not_dispatched` and retryable by a new claim with the same idempotency key. A response lost after the request was written, a timeout after send, or a truncated body is `unknown`: the operation closes and every further claim returns `operation_outcome_unknown`. Talon never retries automatically.
- **Restart.** Attempts interrupted after the dispatch marker recover as `unknown`; before it as retryable `failed`.
- **Evidence.** Every transition is a signed `action_lifecycle` record (spec 1.12). `talon audit verify --operation <id>` verifies signatures and lifecycle consistency; a tampered digest, reviewer, attempt id, dispatch state or terminal result fails, and individually valid records in an impossible order fail.

## Verify locally

```bash
scripts/action-smoke.sh            # built binary, mock downstream, no keys
go test ./internal/action          # domain, repository, concurrency, verifier
```

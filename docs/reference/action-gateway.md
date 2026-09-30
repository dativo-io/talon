# Action Gateway — exact governed actions (#458 minimum proof)

**Status:** shipped first spine (`talon_forwarded` profile, public HTTP adapter). Contracts: #429 (API), #426 (state, sealed payloads), #427 (catalog/binding/projection, JSON Schema 2020-12 offline), #428 (tenant-scoped local approver principals), #146 (evidence). Not yet converged onto this spine: MCP proxy, native runner tool calls, Plan Review (#431/#430). See `LIMITATIONS.md` §10.

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

Every action needs a **closed** object schema (`additionalProperties: false`) so each argument field is a declared, classified property; a **reviewer projection** that classifies every top-level field exactly once (`review.fields` shown verbatim, `review.masked` shown as `{masked,type,length}`, `review.non_material` omitted but still digest-bound; absent `review` = every field shown); and a **destination** with an optional **trusted success contract** (`success.status_codes`). The whole definition — schema, projection, destination, success contract, execution and binding profiles — has one `definition_digest`; any change makes prior authorization unusable.

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
        fields: [ticket_id, amount, currency] # every top-level field must be classified exactly once
        masked: [iban]                        # material, shown as {masked:true,type,length}
        non_material: [note]                  # omitted from the reviewer view, still in the digest
      destination:
        type: http
        url: "https://refunds.internal/v1/refunds"
        method: POST
        success: {status_codes: [201]}        # ONLY these observed statuses mean "effect completed"

policies:
  approvals:
    expires_after: 30m                       # pending decision + first-attempt usability
    rules:
      refund-request:
        actions: [create_refund_request]     # exact names or trailing-* prefix
        approver_groups: [support-leads]
```

Rules: `DENY > REQUIRE_APPROVAL > ALLOW`. An action absent from the catalog is `action_not_found` (never executed). Plaintext `http` destinations are accepted for loopback only. Credentials never appear in a definition; the destination identity (`method + URL`) is bound into the digest.

**Schemas** are JSON Schema **2020-12** compiled **offline** (santhosh-tekuri/jsonschema v6): any `$ref` outside the document (`http`, `https`, `file`, URNs) and any `$id` are rejected at catalog compile; nothing is ever fetched or read during compilation or validation. Supported subset covered by conformance tests: `type`, `properties`, `required`, `additionalProperties`, `enum`, `const`, `minimum`/`maximum`, `minLength`/`maxLength`, `pattern`, `items`/`maxItems`, nested objects, in-document `$ref`/`$defs`.

## Binding and identity

The operation digest binds tenant, agent, canonical action name, the **complete canonical argument payload** (sorted keys, source-literal numbers so `50` ≠ `50.0`, explicit `null` ≠ absent, no exclusions), the **definition digest** (schema, projection, destination, success contract, `talon_forwarded`, `talon/whole-payload/v1`) and the approval-relevant policy digest. Every claim and every decision revalidates the current definition digest: a changed schema, projection, destination or success contract invalidates a pending approval (`invalidated`) and refuses an approved one (`approval_binding_stale`), always before dispatch.

**Payload at rest.** The operation row keeps only the digest, the reviewer projection and lifecycle metadata. The canonical arguments live in `action_payloads`, sealed with AES-256-GCM under a key derived (HKDF, explicit `key_version`) from the vault key, with the operation ref and digest as authenticated data. A missing or rotated key, or a tampered record, fails closed before any attempt is claimed (`payload_unavailable`). The payload is purged when the operation reaches a terminal state; digest, projection and signed lifecycle stay verifiable.

- `operation_id` is caller-provided (`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`), unique per tenant + agent. Volatile request/trace/tool-call ids are not operation identity.
- Same id + same digest → the existing operation and state (`created: false`), never a new effect.
- Same id + different digest → `409 operation_conflict`, nothing mutated, conflict evidenced on the existing operation.

## Endpoints

Runtime routes take the AI use case's **agent key** (`Authorization: Bearer <agent key>`); admin keys are refused. The decision route takes a **tenant-scoped approver credential** only (`talon approver add --name <subject> --tenant <tenant> --groups <g1,g2>`): a 256-bit credential of the form `talon_appr_<credential_id>.<secret>` whose raw value is stored nowhere. A decision is authorized when the principal's tenant scope equals the operation's tenant, one of its groups is an approver group of the matched rule, and the principal and credential are active — rechecked inside the decision transaction. Admin keys, agent keys, workload identities and legacy role approvers (`--role`, no tenant scope) are refused. Evidence records the principal id, tenant, subject, matched group, credential id and version — never a token or hash.

| Route | Result |
|---|---|
| `POST /v1/action-operations` `{operation_id, action, arguments}` | `201` allowed (`operation_status: authorized`), `202` approval pending, `403` denied (persisted, replay-stable), `200` exact replay, `409 operation_conflict`, `404 action_not_found`, `422 action_schema_invalid` / `operation_id_required` |
| `GET /v1/action-operations/{operation_id}` | safe projection (verdict, statuses, approval, latest attempt, reviewer projection — never raw arguments) |
| `POST /v1/action-operations/{operation_id}/attempts` | claim + arm + dispatch; `200` with `attempt.status` `succeeded` / `failed` / `unknown` and the observation facts `dispatch_armed`, `request_written`, `response_observed`, `http_status`; `409 approval_pending` (with `Retry-After`), `409 operation_already_succeeded`, `409 operation_outcome_unknown`, `409 attempt_already_in_progress`, `409 approval_binding_stale`, `409 approval_expired`, `403 policy_denied` / `approval_required` / `approval_rejected`, `409 payload_unavailable` |
| `GET /v1/approvals/{approval_id}` | approval + operation projection (owner agent key) |
| `POST /v1/approvals/{approval_id}/decisions` `{decision: approve\|reject, reason}` | `200` decided; `401 approval_not_authorized` (no/unknown approver credential, admin key, agent key, or a group not named by the matched rule — refusals are evidenced); `409 approval_already_decided`; `409 approval_expired` |

Error envelope: `{"error": {"code", "message", "operation"?}}`. The code is the contract; HTTP status alone is insufficient.

## Dispatch and outcome truth table

An HTTP status is never a business outcome by itself. What Talon observed and what it may conclude are separate facts:

| Observed | `attempt.status` | `result_provenance` | Retry |
|---|---|---|---|
| request never left Talon (pre-connect failure) | `failed` | `not_dispatched` | explicit unchanged retry allowed, same idempotency key |
| request written, response status ∈ `success.status_codes` | `succeeded` | `observed` | operation permanently closed |
| request written, any other status (500 after the effect, 409, 202 not declared, a 3xx) | `unknown` | `unknown` | blocked |
| request written, connection lost / timeout after send / truncated body | `unknown` | `unknown` | blocked |
| no `success` contract declared, any response | `unknown` | `unknown` | blocked |

Redirects are never followed: the approved destination is the only destination an attempt may contact, and a 3xx from it is an observed non-success (`dispatch_redirect_refused`, `unknown`).

**Arm vs. observe.** Before dispatch Talon commits `attempt_armed` (`dispatch_armed: true`), the durable pre-effect marker meaning "a dispatch may now occur"; after it a crash recovers as `unknown`. `request_written` and `response_observed` are the dispatcher's own observations and are recorded only at completion; after a crash they are false, because Talon did not durably observe them.

## Semantics that are tested

- **DENY** → zero downstream calls; a denied operation cannot be claimed.
- **REQUIRE_APPROVAL** → zero calls while pending; a claim returns `approval_pending`.
- **Decision ≠ execution.** An approved decision changes approval state only; dispatch count stays 0 until a runtime claim. Reject/expire/invalidate close the operation (`cancelled`) and purge the payload.
- **Tenant-scoped approval.** A `support-leads` credential of tenant A cannot decide a tenant-B approval requiring `support-leads`: refused, evidenced, approval stays pending, zero dispatch.
- **Revalidation at claim and at decision.** Current definition digest and approval-relevant policy digest must match; a current DENY blocks even an approved operation; first-attempt claim checks approval expiry; the sealed payload must open.
- **At most one effect.** Concurrent claims yield exactly one attempt; a succeeded operation is permanently closed; the dispatcher never replays at the transport level.
- **Crash recovery.** Interrupted after claim but before arm → retryable `failed/not_dispatched`; after arm (before the call, after the write, or after the response) → `unknown`, payload purged, no retry.
- **Evidence.** Every transition is a signed `action_lifecycle` record (spec 1.12); `talon audit verify --operation <id>` verifies signatures and lifecycle consistency (arm before completion, observed write + response for success, no attempt after close, reviewer tenant = operation tenant); tampered fields and impossible orders fail.

## Verify locally

```bash
scripts/action-smoke.sh            # built binary, mock downstream, no keys
go test ./internal/action          # domain, repository, concurrency, verifier
```

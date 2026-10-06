# Action Gateway — exact governed actions (#458 minimum proof)

**Status:** shipped first spine (`talon_forwarded` profile, public HTTP adapter) plus the trusted action catalog with MCP-discovered definitions (#427). Contracts: #429 (API), #426 (state, sealed payloads), #427 (catalog/sources/binding/projection, JSON Schema 2020-12 offline), #428 (tenant-scoped local approver principals), #146 (evidence). Not yet converged onto this spine: MCP proxy, native runner tool calls, Plan Review (#431/#430); MCP-sourced definitions are catalogued but not executable until #431. See `LIMITATIONS.md` §10.

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

Every action needs a **closed** object schema (`additionalProperties: false`) so each argument field is a declared, classified property; a **reviewer projection** that classifies every top-level field exactly once (`review.fields` shown verbatim — the exact value that will be dispatched — or `review.non_material` omitted from the reviewer view but still digest-bound; absent `review` = every field shown); and a **destination** with an optional **trusted success contract** (`success.status_codes`). There is no masked representation: `review.masked` is refused at catalog compile, because a reviewer who sees `{masked, type, length}` has not seen the material effect they are approving. The whole definition — schema, projection, destination, success contract, execution and binding profiles — has one `definition_digest`; any change makes prior authorization unusable.

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
        fields: [ticket_id, amount, currency] # every top-level field must be classified exactly once; shown exactly
        non_material: [note]                  # omitted from the reviewer view, still in the digest
                                              # review.masked is refused: no masked stand-in for a material field
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

**Schemas** are JSON Schema **2020-12** compiled **offline** (santhosh-tekuri/jsonschema v6). The dialect is pinned: an absent `$schema` compiles as 2020-12, the canonical `https://json-schema.org/draft/2020-12/schema` URI is accepted, and any other dialect (`draft-07`, `2019-09`, a custom URI) is refused at catalog compile. Any `$ref` outside the document (`http`, `https`, `file`, URNs) and any `$id` are rejected at catalog compile; nothing is ever fetched or read during compilation or validation. Supported subset covered by conformance tests: `type`, `properties`, `required`, `additionalProperties`, `enum`, `const`, `minimum`/`maximum`, `minLength`/`maxLength`, `pattern`, `items`/`maxItems`, nested objects, in-document `$ref`/`$defs`.

## Trusted MCP sources (`actions.sources`)

A definition may be **discovered** from a trusted MCP source instead of declared with its own schema. Everything with authority stays Talon-configured: the source id, the endpoint, the credential reference, the canonical action name, the upstream-name mapping and the reviewer classification. The upstream supplies **bounded source metadata** only — tool name, description, `inputSchema`, `x-mcp-header` declarations, cache hints, informational `serverInfo` — and can never define approval requirements, approver groups, materiality, execution posture, tenant, agent, source URL, credentials or a destination outside its configured source.

```yaml
actions:
  sources:
    refunds:
      type: mcp
      url: https://refunds.internal/mcp       # https, or http for loopback; redirects are never followed
      auth: {secret_name: refunds-mcp-key}    # vault-backed; header/scheme as for the MCP proxy
      timeout: 15s                            # discovery deadline (default 15s, max 2m)
  definitions:
    create_refund_request:                    # canonical name — the ONLY callable identity
      source: refunds
      upstream_name: refund.create            # default: the canonical name; one-to-one per source
      review:
        fields: [ticket_id, amount, currency]
        non_material: [note]
```

**Discovery** (`internal/action/mcpsource`, the one implementation; the proxy's protocol capture shares its wire client): `server/discover` must report `2026-07-28` and the `tools` capability; every `tools/list` page is followed (bounded, loop-detected) and validated strictly (`resultType`, required `ttlMs`/`cacheScope`); each tool's `x-mcp-header` declarations are parsed with the #447 parser and the annotations are stripped from the business schema; a tool with an invalid definition is **excluded** with its reason (a mapped exclusion fails the build, an unmapped one is inspectable); duplicate upstream names, nameless tools, oversized lists/definitions, redirects, timeouts and malformed replies fail the source. Discovery is all-or-nothing per agent: one failing source means no candidate catalog.

**Overlay compile** (`action.CompileCatalog`, no I/O): a discovered schema must be a 2020-12 object (other dialects, `$id`, external `$ref` are refused); an absent `additionalProperties` is closed by normalization, any permissive value is unsupported. The reviewer projection must classify every top-level field exactly as for a declared action. Rejected: duplicate canonical names, duplicate source ids, an upstream tool mapped twice, a missing or excluded mapped tool, an unknown source, `input_schema`/`destination` together with `source`, `upstream_name` without `source`, an incomplete classification, `review.masked`. A static defect is never reported as "source not discovered".

**Shape:** declared and discovered definitions are the same `action.Definition`: `source` (`declared` or `mcp:<id>` with its config digest and discovered generation), `upstream_name`, canonical schema and digest, reviewer classification and projection digest, mirrored parameters (protocol metadata), binding profile, execution profile, destination (`http` method+URL or `mcp` source endpoint) and the definition digest.

## Binding and identity

The operation digest binds tenant, agent, canonical action name, the **complete canonical argument payload** (sorted keys, source-literal numbers so `50` ≠ `50.0`, explicit `null` ≠ absent, no exclusions), the **definition digest** and the approval-relevant policy digest.

The **definition digest** covers: canonical name, source type and trusted source id, the source **config digest** (type, id, endpoint, credential *reference* — header, scheme, secret name; never secret bytes, so a rotation under the same connector identity changes nothing), upstream name, schema digest, projection digest, destination id (`http:<METHOD> <URL>` or `mcp:<source id> <URL>`), success contract, execution profile and binding profile. Deliberately **not** bound: description, `x-mcp-header` mirrors, `serverInfo`, cache hints, the discovered generation as such, request/JSON-RPC/session ids, `clientInfo`, progress tokens. Drift classification: a schema, upstream-name, source/destination or review change is a **new definition identity** (pending approvals invalidate, approved ones are refused at claim); a description or `x-mcp-header` change updates the definition's **metadata digest** and therefore the catalog generation, but authorizes nothing and invalidates nothing; a `serverInfo` display-name change changes nothing — it is never a trusted identity. Every claim and every decision revalidates the current definition digest: a changed schema, projection, destination or success contract invalidates a pending approval (`invalidated`) and refuses an approved one (`approval_binding_stale`), always before dispatch.

**Payload at rest.** The operation row keeps only the digest, the reviewer projection (the shown material fields, in plaintext, because that is what the reviewer must see) and lifecycle metadata. The canonical arguments live in `action_payloads`, sealed with AES-256-GCM under a key derived (HKDF, explicit `key_version`) from the vault key, with the operation ref and digest as authenticated data. A missing or rotated key, or a tampered record, fails closed before any attempt is claimed (`payload_unavailable`). The payload is purged when the operation reaches a terminal state; digest, projection and signed lifecycle stay verifiable.

- `operation_id` is caller-provided (`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`), unique per tenant + agent. Volatile request/trace/tool-call ids are not operation identity.
- Same id + same digest → the existing operation and state (`created: false`), never a new effect.
- Same id + different digest → `409 operation_conflict`, nothing mutated, conflict evidenced on the existing operation.

## Catalog in the runtime generation

The catalog is compiled into each `RuntimeAgent` of the atomic runtime generation (`agentcatalog`): discover every configured source → compile the complete candidate catalog → compile the approval policy → build the rest of the generation → one atomic publish. A request resolves its Action Gateway service from the generation it captured, so the catalog never changes under an in-flight operation. Cold start fails closed on any discovery or compile error. The reloader rebuilds a candidate when agent-file bytes change **or** when the earliest upstream `ttlMs` of the active generation expires (floored to one tick, capped at 24h); a candidate whose generation equals the active one activates nothing. A failed refresh keeps last-known-good serving, records one signed `config_reload` rejection per distinct cause set, exposes `action_sources_rejected`/`next_action_source_refresh` in `GET /v1/agents/fleet`, and retries after 30s. Generations are deterministic: the same files and the same discovered facts reproduce the same generation id.

## Operator inspection (`talon actions`)

```bash
talon actions list     --agent support-bot            # sources + actions: source, upstream identity, digests, verdict, rules
talon actions show     --agent support-bot create_refund_request
talon actions validate --agent support-bot --action create_refund_request --input args.json
```

All three read the one shared projection (`action.CatalogView`) the runtime generation is built from, with `--json` for machines. Shown: canonical action, source type/id and config digest, upstream identity, schema and schema digest, definition and metadata digests, binding and execution profiles, review fields and non-material fields, mirrored parameters, the safe destination reference, source generation, informational `serverInfo`, matching approval rules and groups. Never shown: secret values or references, sealed payloads, protected data. `validate` canonicalizes the document, validates it against the trusted schema and prints the canonical arguments digest, the exact reviewer projection and the verdict; it creates no operation and exits non-zero on an invalid document. The CLI compiles a **candidate** in its own process and labels it so: the generation a running server applies is reported by `GET /v1/agents/fleet`.

An MCP-sourced definition presented to this HTTP adapter is refused with `501 execution_unsupported` before anything is bound or persisted (its execution is #431).

## Endpoints

Runtime routes take the AI use case's **agent key** (`Authorization: Bearer <agent key>`); admin keys are refused. The decision route takes a **tenant-scoped approver credential** only (`talon approver add --name <subject> --tenant <tenant> --groups <g1,g2>`): a 256-bit credential of the form `talon_appr_<credential_id>.<secret>` whose raw value is stored nowhere. A decision is authorized when the principal's tenant scope equals the operation's tenant, one of its groups is an approver group of the matched rule, and the principal and credential are active — rechecked inside the decision transaction. Admin keys, agent keys, workload identities and legacy role approvers (`--role`, no tenant scope) are refused. Evidence records the principal id, tenant, subject, matched group, credential id and version — never a token or hash.

| Route | Result |
|---|---|
| `POST /v1/action-operations` `{operation_id, action, arguments}` | `201` allowed (`operation_status: authorized`), `202` approval pending, `403` denied (persisted, replay-stable), `200` exact replay, `409 operation_conflict`, `404 action_not_found`, `422 action_schema_invalid` / `operation_id_required`, `501 execution_unsupported` (MCP-sourced definition: catalogued, no executor on this adapter until #431; nothing bound or persisted) |
| `GET /v1/action-operations/{operation_id}` | safe projection (verdict, statuses, approval, latest attempt, reviewer projection — never raw arguments) |
| `POST /v1/action-operations/{operation_id}/attempts` | claim + arm + dispatch; `200` with `attempt.status` `succeeded` / `failed` / `unknown` and the observation facts `dispatch_armed`, `request_written`, `response_observed`, `http_status`; `409 approval_pending` (with `Retry-After`), `409 operation_already_succeeded`, `409 operation_outcome_unknown`, `409 attempt_already_in_progress`, `409 approval_binding_stale`, `409 approval_expired`, `403 policy_denied` / `approval_required` / `approval_rejected`, `409 payload_unavailable` |
| `GET /v1/approvals/{approval_id}` | approval + operation projection (owner agent key) |
| `POST /v1/approvals/{approval_id}/decisions` `{decision: approve\|reject, reason}` | `200` decided; `401 approval_not_authorized` (no/unknown approver credential, admin key, agent key, or a group not named by the matched rule — refusals are evidenced); `404 not_found` (no approval with that id **in the principal's tenant scope** — a valid id of another tenant is indistinguishable from a nonexistent one and touches nothing); `409 approval_already_decided`; `409 approval_expired` |

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
- **Tenant-scoped approval, opaque ids.** A `support-leads` credential of tenant A presenting a tenant-B approval id gets the same `404 not_found` as for a nonexistent id; tenant B's operation version, lifecycle sequence, evidence count and approval status are unchanged and dispatch count stays 0 (owner resolution is scoped by the principal's trusted tenant before any operation is loaded; `Decide` re-checks the tenant as defense in depth).
- **Revalidation at claim and at decision.** Current definition digest and approval-relevant policy digest must match; a current DENY blocks even an approved operation; first-attempt claim checks approval expiry; the sealed payload must open.
- **At most one effect.** Concurrent claims yield exactly one attempt; a succeeded operation is permanently closed; the dispatcher never replays at the transport level.
- **Crash recovery.** Interrupted after claim but before arm → retryable `failed/not_dispatched`; after arm (before the call, after the write, or after the response) → `unknown`, payload purged, no retry.
- **Evidence.** Every transition is a signed `action_lifecycle` record (spec 1.12) whose generic `status` is explicit (`queued`, `running`, `completed`, `failed`, `denied`, `cancelled`, `unknown`) — an ambiguous outcome is `unknown` at both the lifecycle and the generic level, never the empty-means-completed default; `talon audit verify --operation <id>` verifies signatures and lifecycle consistency (arm before completion, observed write + response for success, no attempt after close, reviewer tenant = operation tenant); tampered fields and impossible orders fail.
- **Referential integrity.** The evidence database connection enforces SQLite foreign keys; an approval, attempt or sealed payload cannot exist without its operation.

## Verify locally

```bash
scripts/action-smoke.sh            # built binary, mock downstream, no keys
scripts/action-catalog-smoke.sh    # trusted sources: CLI inspection, catalog in the generation, refresh/last-known-good
go test ./internal/action/...      # domain, repository, concurrency, verifier, MCP source discovery (official go-sdk upstream)
```

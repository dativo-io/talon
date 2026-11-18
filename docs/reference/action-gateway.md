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
  forbidden_tools: [delete_customer]        # DENY source for actions and gateway tools; glob vocabulary ("*", "delete_*", case-insensitive)

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

Rules: `DENY > REQUIRE_APPROVAL > ALLOW`, over the **effective** action policy — the company policy below composed with this file's rules. An action absent from the catalog is `action_not_found` (never executed). Plaintext `http` destinations are accepted for loopback only. Credentials never appear in a definition; the destination identity (`method + URL`) is bound into the digest.

**Schemas** are JSON Schema **2020-12** compiled **offline** (santhosh-tekuri/jsonschema v6). The dialect is pinned: an absent `$schema` compiles as 2020-12, the canonical `https://json-schema.org/draft/2020-12/schema` URI is accepted, and any other dialect (`draft-07`, `2019-09`, a custom URI) is refused at catalog compile. Any `$ref` outside the document (`http`, `https`, `file`, URNs) and any `$id` are rejected at catalog compile; nothing is ever fetched or read during compilation or validation. Supported subset covered by conformance tests: `type`, `properties`, `required`, `additionalProperties`, `enum`, `const`, `minimum`/`maximum`, `minLength`/`maxLength`, `pattern`, `items`/`maxItems`, nested objects, in-document `$ref`/`$defs`.

## Company action policy (`talon.config.yaml`, #425)

One operator-owned policy governs the catalogued actions of **every** AI use case. It lives in the gateway block of `talon.config.yaml` and reuses the organization constraints vocabulary:

```yaml
gateway:
  organization_policy:
    constraints:
      forbidden_tools: [delete_customer]          # company DENY for gateway tools AND catalogued actions; gateway glob vocabulary ("*", "delete_*")
      action_approvals:                            # company approval requirements
        rules:
          refund_authorization:
            actions: [create_refund_request]       # exact names or trailing-* prefixes
            approver_groups: [finance_leads]       # tenant-scoped approver principals' groups
```

**Composition** (`action.CompileEffectiveActionPolicy`, the one compiler every surface uses — serve on both serving modes, `talon validate`, `talon actions`): the company's `forbidden_tools` and `action_approvals.rules` are compiled first, then the use case's `capabilities.forbidden_tools` and `policies.approvals.rules`. The effective verdict is `DENY > REQUIRE_APPROVAL > ALLOW`. A use case **may add** a DENY or an approval requirement the company does not have; it **can never weaken** a company restriction: a company DENY stands whatever the agent file says, and a use-case rule that matches an action a company rule matches must name the **same** approver groups — different groups are an ambiguous authorization requirement and the configuration is refused at load (`talon validate`, `talon serve` startup), never resolved by rule-id order. The same refusal applies to two overlapping rules of one layer. A catalogued action no rule matches stays `ALLOW`; nothing is invented. The company policy declares no approval lifetime: the use case's `policies.approvals.expires_after` (default 1h, at most 30d) bounds every approval the effective policy requires, company rules included, and is part of the policy digest.

**Provenance.** Every compiled rule and every verdict names its layer: company rules carry the id `company:<rule>`, a DENY carries the typed id `company:forbidden_tools` or `use_case:forbidden_tools`, and operator-chosen rule ids follow `[a-z0-9][a-z0-9_-]{0,63}` in both layers so neither namespace can be claimed by a rule — the provenance derived from a persisted rule id is authoritative (`matched_rule_id` in projections and `matched_rule_id` / `matched_rule_source: company | use_case` in every lifecycle record); `talon actions list/show` print each rule's `source` and the `verdict_source`. The approval-relevant policy digest (`policy_digest`) covers the material rules of **both** layers; without a company policy it is byte-identical to the pre-#425 digest. The company part is bound as canonical, versioned JSON (explicit arrays for patterns, actions and groups), so two different lists can never serialize alike: `["a,b"]` and `["a","b"]` are different policies with different digests. `approver_groups` entries in both layers must follow the approver store's group grammar (`[a-z0-9][a-z0-9_-]{0,63}`, the grammar of `talon approver add --groups`), and a `forbidden_tools` pattern may not contain a comma or a control character such as a line break (no tool or action name does, and the use-case digest lines are comma- and newline-delimited); both are refused at load.

**Where it applies.** `talon serve --gateway` reads it from the gateway config it already loads. Native-only `talon serve` reads `TALON_GATEWAY_CONFIG` (default `talon.config.yaml`) when the file exists, so the company policy is authoritative for direct Action Gateway traffic on that path too; a present but invalid file is a startup error — a company policy that fails to load is never treated as absent. `--proxy-quickstart` serves no company policy (it accepts no gateway config). Without a `gateway:` block, or with neither `forbidden_tools` nor `action_approvals`, no company action policy is configured and per-use-case behaviour is unchanged. `talon validate` and `talon actions` resolve the same file and fail on a present but invalid one: they never report a result computed without the company policy.

**Activation is a restart boundary.** The company policy is loaded once at process start and frozen into every runtime generation the process builds; agent-file hot reloads keep that snapshot. A changed company policy activates at the next restart as a new effective generation (the generation id folds in the company digest): a pending approval established before it is invalidated at its next decision (`409 approval_binding_stale`, approval `invalidated`), an approved-but-unclaimed operation is refused at claim with the same code, historical evidence stays valid under the policy digest it was signed with, and the changed requirement needs a new operation.

## Argument rules (#205)

An **argument rule** is one declarative, typed condition on **one top-level argument** of matching actions, with a **restrictive** effect:

```
when <argument> <operator> <value> holds   →   require_approval (by approver_groups)  |  deny
```

A rule never grants anything. The action being catalogued and not forbidden is the prerequisite; a rule whose condition does not hold adds no restriction; the result is `DENY > REQUIRE_APPROVAL > the baseline`. It is one rule form, not an expression language: no nested paths, no conjunctions, no membership, no regular expressions, no functions, no external data (those are #570).

```yaml
# agent.talon.yaml (use-case layer)
policies:
  approvals:
    expires_after: 30m
    argument_rules:
      refund-needs-approval:
        actions: [create_refund_request]   # exact names or trailing-* prefixes
        argument: amount                   # a top-level argument of the action
        type: decimal                      # integer | decimal | string | boolean
        operator: gt                       # eq | ne | gt | gte | lt | lte
        value: "50.00"                     # the operand, in the rule's type
        effect: require_approval           # require_approval | deny
        approver_groups: [support-leads]   # required for require_approval, not allowed for deny
      refund-too-large:
        {actions: [create_refund_request], argument: amount, type: decimal, operator: gt, value: "500.00", effect: deny}
      mass-delete-denied:
        {actions: [delete_records], argument: count, type: integer, operator: gte, value: 1000, effect: deny}
      real-delete-needs-approval:
        {actions: [delete_records], argument: dry_run, type: boolean, operator: eq, value: false, effect: require_approval, approver_groups: [support-leads]}
      prod-deploy-needs-approval:
        {actions: [deploy_service], argument: environment, type: string, operator: eq, value: production, effect: require_approval, approver_groups: [release-managers]}

# talon.config.yaml (company layer; restart-required like the rest of the company action policy)
gateway:
  organization_policy:
    constraints:
      action_approvals:
        argument_rules:
          refund-too-large:
            {actions: [create_refund_request], argument: amount, type: decimal, operator: gt, value: "500.00", effect: deny}
```

These are example policies. Talon has no built-in notion of a refund, a currency or an environment.

### Types, operators and wire representation

| `type` | Argument on the wire | `value` in the rule | Operators |
|---|---|---|---|
| `integer` | a JSON number without fraction or exponent, at most 18 digits | a YAML integer | `eq ne gt gte lt lte` |
| `decimal` | an exact decimal with at most 18 integer and 6 fractional digits, as a JSON number (`75.00`) or a JSON string (`"75.00"`) | a **quoted** string (`"50.00"`) | `eq ne gt gte lt lte` |
| `string` | a JSON string, at most 1024 bytes | a string | `eq ne` (exact, case-sensitive) |
| `boolean` | a JSON boolean | `true` / `false` | `eq ne` |

- **Exact decimals:** a decimal is compared exactly, never as a float. An unquoted decimal operand in YAML would pass through a float and is refused at load. `"50"` and `"50.00"` are the same operand and the same digest.
- **No implicit coercion:** `"5"` is not an integer, `0` is not a boolean, `1e2` is not an integer.
- **Resolved against the trusted catalog:** at load (`talon validate`, `talon serve`, `talon actions`), for every catalogued action a rule applies to, the argument must be a declared top-level property that the action's input schema marks **required**, with a matching JSON type (`integer` → `integer`; `decimal` → `number` or `string`; `string` → `string`; `boolean` → `boolean`). A rule that could not be evaluated truthfully is a configuration error.

### Fail closed

When a rule applies to an action and its argument is missing, `null`, of another JSON type or outside the type's bounds, the condition cannot be established and the call is **denied** (reason code `argument_not_established`). An unestablished argument is never treated as "the rule does not match".

### Domain constraints belong to the catalog

What an amount may look like is the action's contract, not the policy's. Put it in the action's trusted input schema, which Talon enforces before any policy decision (`action_schema_invalid`, nothing bound):

```yaml
      input_schema:
        properties:
          amount: {type: string, pattern: "^(0|[1-9][0-9]{0,14})(\\.[0-9]{1,2})?$"}   # non-negative, cent precision
          currency: {type: string, enum: [EUR]}                                       # EUR only
```

An explicit guard rule is the alternative when the schema must stay open, for example `{argument: currency, type: string, operator: ne, value: EUR, effect: deny}`.

### Composition

Argument rules compile in the same one compiler as forbidden patterns and name-based approval rules:
- **Precedence:** a company `forbidden_tools` match denies whatever the arguments. A company rule's restriction stands whatever a use case declares; a use case can **add** rules (and so tighten) but has no way to lift one: there is no `allow` effect.
- **Unambiguous reviewers:** any two approval requirements that can apply to one action (name-based rules and `require_approval` argument rules, in either layer) must name the same approver groups; otherwise the configuration is refused at load.
- **Unique ids:** an argument rule may not reuse a rule id of its layer. Company rules carry `company:<id>`.

### Binding and re-check

- **At establish** the verdict is computed from the call's canonical arguments, and the approval (if one is required) binds the exact digest of those arguments. A different argument value under the same `operation_id` is `operation_conflict`.
- **Policy digest:** argument rules are part of the approval-relevant `policy_digest` (operands normalized), so changing an operand invalidates approvals granted under the old one (`approval_binding_stale`). A policy without argument rules keeps its digest byte for byte, and the company encoding stays version 1 unless it carries them.
- **Before a claim** the policy is re-evaluated against the operation's sealed arguments. An operation allowed under an earlier policy that a rule now denies is refused `policy_denied`; one that now requires approval is refused `approval_required`. Either way nothing is dispatched.

### Decisions, machine-readable

| Where | What it carries |
|---|---|
| `POST /v1/action-operations` (`operation`) | `verdict`, `matched_rule_id`, `matched_rule_source` (`company` \| `use_case`), `approval.approver_groups` |
| `talon actions show <action> [--json]` | `decision_basis`: `name` (the verdict holds for every call) or `arguments` (argument rules apply; a call can be stricter than `verdict`, never looser), and `argument_rules[]`: `id`, `source`, `argument`, `type`, `operator`, `value`, `condition`, `effect`, `approver_groups`. The text form prints `BY ARGUMENTS`. A consumer must not read `verdict: ALLOW` with `decision_basis: arguments` as unconditional |
| `talon actions validate --action <a> --input <file> [--json]` | for arguments that satisfy the action's definition: the verdict for those exact arguments, `matched_rule_id`, `reason`, and `reason_code` (`argument_rule_approval`, `argument_rule_deny` or `argument_not_established`). For arguments that do not (missing, malformed, wrong type, undeclared): `valid: false`, `verdict: REFUSED`, `reason_code: arguments_invalid` and a non-zero exit. Invalid arguments never show the action's name-only verdict, so they can never read as `ALLOW` |
| `talon agents show <name> --effective [--json]` and the console's use-case page | `action_boundary`: every action the agent file defines with `verdict`, `decision_basis` and the rules that apply, plus all `approval_rules` and `argument_rules` of both layers with their `source`. The console's Configuration page lists the company rules, and its evidence detail shows the verdict and matched rule of an action lifecycle record |
| signed lifecycle evidence | `matched_rule_id`, `matched_rule_source` and the reason |

**Inspection reason codes are not HTTP error codes.** `reason_code` and the `REFUSED` verdict exist only in the output of `talon actions validate`. They explain a pre-flight check to an operator or a script and are not part of the wire contract. The Action Gateway answers with the registered governance codes (`internal/govcode`, listed in the [MCP governance extension registry](mcp-governance-extension.md) and in the route table below), which are what clients key on:

| Inspection (`talon actions validate`) | What the Action Gateway answers for the same call |
|---|---|
| `verdict: REFUSED`, `reason_code: arguments_invalid` | `422 action_schema_invalid`; no operation is established |
| `verdict: DENY`, `reason_code: argument_rule_deny` or `argument_not_established` | `403` with `operation.verdict: DENY` and `matched_rule_id`; a claim is refused `policy_denied` |
| `verdict: REQUIRE_APPROVAL`, `reason_code: argument_rule_approval` | `202` with `operation.verdict: REQUIRE_APPROVAL`; a claim before the decision is refused `approval_pending` |
| `verdict: ALLOW` | `201`/`200` with `operation.verdict: ALLOW` |

**No argument values in reasons.** A reason names the rule and its argument (`use_case argument rule refund-needs-approval: its condition on argument "amount" holds; approval is required`). It never repeats a value of the call or the rule's operand: evidence outlives the sealed payload.

### Not supported (see #570)

Nested argument paths, several arguments in one rule, `and`/`or`, set membership, pattern matching, time- or history-dependent conditions, cumulative limits, and any `allow` effect. Corporate approval flows (chat, ticketing) are outside the OSS scope; the local reviewer path below is the supported one.

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

**Captured source facts (never authority).** The snapshot also records, bounded and credential-free, what the source advertised about itself so a later canonical route (#431) can answer from the captured generation without rediscovering: the `server/discover` capabilities (`tools`/`resources`/`prompts` with their flags, `completions`, `logging`, experimental entries by name, advertised extensions with their canonical settings objects — size- and count-bounded — and `instructions`), and per tool the `title`, the `annotations` hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, annotation title) and a canonical `outputSchema`. Icons and unknown members are dropped. These are observed facts: an advertised Tasks extension is recorded, never adopted (Talon advertises only what it implements); `destructiveHint: false` never makes a consequential action safe; `outputSchema` authorizes nothing and results are not validated against it in this slice. They enter the source generation and the catalog generation, never the definition identity.

**Freshness** is conservative at every level: a paginated list is as fresh as its least fresh page (shortest `ttlMs`, kept as that page's exact number; `private` if any page is private), and the whole snapshot — `server/discover` plus the complete `tools/list` — is one logical capture whose `ttlMs` is the shorter of the two and whose scope is the more restrictive. Every result is still validated individually; nothing malformed is normalized. A hint is converted to a refresh deadline with exact decimal semantics and clamped before conversion (≤ 0 → immediately stale, ≥ 24h → 24h), so no hint can overflow or defer polling beyond the operational cap. Captured capabilities are validated strictly against the 2026-07-28 shapes (`tools`/`prompts`/`resources` objects with boolean flags, `logging`/`completions` objects, `experimental` and `extensions` objects of objects, extension ids in the prefixed `{vendor-prefix}/{extension-name}` grammar): a malformed member fails the source. Excluded tools enter the source generation by name and stable code (`schema_missing`, `header_annotation_invalid`, `schema_unbounded`, `output_schema_invalid`, `definition_oversized`), never a definition identity.

**Credential header integrity.** `auth.header` (default `Authorization`) and `auth.scheme` (default `Bearer`) go through the one upstream-auth contract shared with the MCP proxy's `proxy.upstream.auth`: the header must be a legal HTTP field name and may not collide, case-insensitively, with a header the shared MCP client owns (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, any `Mcp-Param-*`, `Content-Type`, `Accept`, framing headers); the scheme must be a single token. Custom credential headers such as `X-Api-Key` are fine. A violation is refused at load, before any request exists.

**Overlay compile** (`action.CompileCatalog`, no I/O): a discovered schema must be a 2020-12 object (other dialects, `$id`, external `$ref` are refused); an absent `additionalProperties` is closed by normalization, any permissive value is unsupported. The reviewer projection must classify every top-level field exactly as for a declared action. Rejected: duplicate canonical names, duplicate source ids, an upstream tool mapped twice, a missing or excluded mapped tool, an unknown source, `input_schema`/`destination` together with `source`, `upstream_name` without `source`, an incomplete classification, `review.masked`. A static defect is never reported as "source not discovered".

**Shape:** declared and discovered definitions are the same `action.Definition`: `source` (`declared` or `mcp:<id>` with its config digest and discovered generation), `upstream_name`, canonical schema and digest, reviewer classification and projection digest, mirrored parameters (protocol metadata), binding profile, execution profile, destination (`http` method+URL or `mcp` source endpoint) and the definition digest.

## Binding and identity

The operation digest binds tenant, agent, canonical action name, the **complete canonical argument payload** (sorted keys, source-literal numbers so `50` ≠ `50.0`, explicit `null` ≠ absent, no exclusions), the **definition digest** and the approval-relevant policy digest.

The **definition digest** covers: canonical name, source type and trusted source id, the source **config digest** (type, id, endpoint, credential *reference* — header, scheme, secret name; never secret bytes, so a rotation under the same connector identity changes nothing), upstream name, schema digest, projection digest, destination id (`http:<METHOD> <URL>` or `mcp:<source id> <URL>`), success contract, execution profile and binding profile. Deliberately **not** bound: description, `x-mcp-header` mirrors, `serverInfo`, cache hints, the discovered generation as such, request/JSON-RPC/session ids, `clientInfo`, progress tokens. Drift classification: a schema, upstream-name, source/destination or review change is a **new definition identity** (pending approvals invalidate, approved ones are refused at claim); a description or `x-mcp-header` change updates the definition's **metadata digest** and therefore the catalog generation, but authorizes nothing and invalidates nothing; a `serverInfo` display-name change changes nothing — it is never a trusted identity. Every claim and every decision revalidates the current definition digest: a changed schema, projection, destination or success contract invalidates a pending approval (`invalidated`) and refuses an approved one (`approval_binding_stale`), always before dispatch.

**Payload at rest.** The operation row keeps only the digest, the reviewer projection (the shown material fields, in plaintext, because that is what the reviewer must see) and lifecycle metadata. The canonical arguments live in `action_payloads`, sealed with AES-256-GCM under a key derived (HKDF, explicit `key_version`) from the vault key, with the operation ref and digest as authenticated data. A missing or rotated key, or a tampered record, fails closed before any attempt is claimed (`payload_unavailable`). The payload is purged when the operation reaches a terminal state; digest, projection and signed lifecycle stay verifiable.

**Agent identity at ingress.** The agent-facing routes authenticate the AI use case either with its agent key (`Authorization: Bearer <agent key>`, `identity_source: caller_provided`) or, for a sandbox reaching Talon through an external runtime's egress hop, with a Talon-minted **workload hop assertion** (`X-Talon-Workload-Assertion`, `identity_source: workload_asserted`; see [`docs/integration/openshell.md`](../integration/openshell.md#action-gateway-through-the-hop-457482--the-sandbox-holds-no-talon-secret)). An assertion is verified against the exact method, path and body digest of the request, re-bound to the agent on the current runtime generation, and refused (`401 workload_identity_invalid`, `403 workload_identity_unbound`, `401 workload_identity_conflict` when an agent key names another use case) before any domain call. Lifecycle records of a hop-established operation carry `workload_identity` and `enforcement.runtime` (the sandbox and runtime request references) and the sandbox's `X-Talon-Session-ID` as `session_id`. Reviewer decisions never accept either identity.

- `operation_id` is caller-provided (`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`), unique per tenant + agent. Volatile request/trace/tool-call ids are not operation identity.
- Same id + same digest → the existing operation and state (`created: false`), never a new effect.
- Same id + different digest → `409 operation_conflict`, nothing mutated, conflict evidenced on the existing operation.

## Catalog in the runtime generation

The catalog is compiled into each `RuntimeAgent` of the atomic runtime generation (`agentcatalog`): discover every configured source → compile the complete candidate catalog → compile the approval policy → build the rest of the generation → one atomic publish. Catalog and approval policy therefore hot-reload with the generation; Service instances are immutable per generation. **One request, one generation (#267):** the agent key authenticates against a generation and the Action Gateway resolves the Service for that same generation — if a reload activated in between, the request is refused with `409 generation_changed` (`Retry-After: 1`) before any domain call: no operation, approval, attempt, lifecycle evidence or dispatch; the caller re-authenticates and retries. A Service resolved against a matching generation completes its request even if a reload lands afterwards. Reviewer decisions are tenant-scoped, not generation-bound; the domain revalidates the current definition/policy binding before any decision or claim regardless. The catalog is a property of the trusted configuration, not of the process: explicit definitions compile in every runtime build (serve, `talon run`, `talon plan`) with or without a source discoverer; an agent that configures MCP sources fails closed when the process has no discoverer, and its explicit subset never activates on its own. A request resolves its Action Gateway service from the generation it captured, so the catalog never changes under an in-flight operation. Cold start fails closed on any discovery or compile error. The reloader rebuilds a candidate when agent-file bytes change **or** when the earliest upstream `ttlMs` of the active generation expires (floored to one tick, capped at 24h); a candidate whose generation equals the active one activates nothing. A failed refresh keeps last-known-good serving, records one signed `config_reload` rejection per distinct cause set, exposes `action_sources_rejected`/`next_action_source_refresh` in `GET /v1/agents/fleet`, and retries after 30s. Generations are deterministic: the same files and the same discovered facts reproduce the same generation id.

## Operator inspection (`talon actions`)

```bash
talon actions list     --agent support-bot            # sources + actions: source, upstream identity, digests, verdict, rules
talon actions show     --agent support-bot create_refund_request
talon actions validate --agent support-bot --action create_refund_request --input args.json
```

All three read the one shared projection (`action.CatalogView`) the runtime generation is built from, with `--json` for machines. Shown: canonical action, source type/id and config digest, upstream identity, schema and schema digest, definition and metadata digests, binding and execution profiles, review fields and non-material fields, mirrored parameters, title/annotation hints/output schema as metadata, the safe destination reference, source generation, captured source capabilities and extensions with their digest, informational `serverInfo`, matching approval rules and groups. Never shown: secret values or references, sealed payloads, protected data. `validate` canonicalizes the document, validates it against the trusted schema and prints the canonical arguments digest, the exact reviewer projection and the verdict; it creates no operation and exits non-zero on an invalid document. The CLI compiles a **candidate** in its own process and labels it so: the generation a running server applies is reported by `GET /v1/agents/fleet`.

An MCP-sourced definition presented to this HTTP adapter is refused with `501 execution_unsupported` before anything is bound or persisted (its execution is #431).

## Reviewing approvals (`talon approvals`, #433)

A reviewer is a local approver principal (`talon approver add --name lead-1 --tenant acme --groups support-leads`). The command prints a `talon_appr_…` credential once. The reviewer exports it as `TALON_APPROVER_KEY`, which is never passed as a flag, and works against the running server (`--url`, default `http://localhost:8080`):

```bash
export TALON_APPROVER_KEY=...              # the credential from 'talon approver add'
talon approvals list                      # pending approvals of my tenant that one of my groups may decide
talon approvals show apr_...              # exactly what I would authorize
talon approvals approve apr_... --reason "customer verified"
talon approvals reject  apr_... --reason "duplicate refund"
```

`show` prints:
- the action, the operation and the AI use case that asked for it;
- the **target**: the trusted catalog destination Talon itself will call;
- the verdict with its rule id and layer;
- **why**: the matched rule as the current policy states it, for example the argument rule's condition;
- the **exact** material argument values from the reviewer projection, with the digest that binds them;
- the approval's groups and expiry.

It warns when the policy or the action definition changed since the operation was established, because an approval could then not be used.

A decision dispatches nothing. The AI use case's runtime claims the approved operation afterwards, and Talon re-checks the binding, the policy and its argument rules before any claim. `--reason` is required and recorded in the signed approval evidence. The command refuses to send the credential over plain `http` to a non-loopback host unless `--allow-plaintext` is given (for a protected network path). `--json` prints the server's answer.

| Route | Credential | Answer |
|---|---|---|
| `GET /v1/reviews` | approver only | `{tenant, reviews: [ReviewerView], more}`: pending approvals of the credential's tenant that share at least one approver group, oldest first, at most 200. The group filter is applied before the bound, so other groups' approvals never hide an eligible one. `more: false` means the listing is complete; `more: true` means older ones are shown and further eligible approvals exist (decide, then list again) |
| `GET /v1/reviews/{approval_id}` | approver only | `ReviewerView`: `operation` (the projection), `use_case`, `tenant`, `target`, `rule`, `policy_current`, `definition_current`; `404 not_found` for another tenant's approval or one none of the reviewer's groups may decide |
| `POST /v1/approvals/{approval_id}/decisions` | approver only | the decision (unchanged) |

Admin keys, agent keys, revoked and rotated-away credentials get `401 approval_not_authorized` on every reviewer route. Reads never change an operation, an approval or the evidence. The view shows the declared `review.fields` exactly and nothing else of the payload: a field declared `non_material` never appears in it. *(Backed by `TestReviewerReads_ScopedToTenantAndGroup`, `TestReview_ShowsDeclaredFieldsOnly`, `TestPendingApprovals_FilterBeforeBoundAndReportMore`, `TestE2E_ActionGateway_AmountBands`.)*

## Endpoints

Runtime routes take the AI use case's **agent key** (`Authorization: Bearer <agent key>`); admin keys are refused. Every agent-key route answers `409 generation_changed` when the runtime generation changed between authentication and resolution (see above). The decision route takes a **tenant-scoped approver credential** only (`talon approver add --name <subject> --tenant <tenant> --groups <g1,g2>`): a 256-bit credential of the form `talon_appr_<credential_id>.<secret>` whose raw value is stored nowhere. A decision is authorized when the principal's tenant scope equals the operation's tenant, one of its groups is an approver group of the matched rule, and the principal and credential are active — rechecked inside the decision transaction. Admin keys, agent keys, workload identities and legacy role approvers (`--role`, no tenant scope) are refused. Evidence records the principal id, tenant, subject, matched group, credential id and version — never a token or hash.

| Route | Result |
|---|---|
| `POST /v1/action-operations` `{operation_id, action, arguments}` | body: at most 512 KiB as a whole, exactly one JSON value, no unknown fields, no trailing material (`400 invalid_request`; `413 invalid_request` when over the bound) — refused before any domain call; `201` allowed (`operation_status: authorized`), `202` approval pending, `403` denied (persisted, replay-stable), `200` exact replay, `409 operation_conflict`, `404 action_not_found`, `422 action_schema_invalid` / `operation_id_required`, `501 execution_unsupported` (MCP-sourced definition: catalogued, no executor on this adapter until #431; nothing bound or persisted) |
| `GET /v1/action-operations/{operation_id}` | safe projection (verdict, statuses, approval, latest attempt, reviewer projection — never raw arguments) |
| `POST /v1/action-operations/{operation_id}/attempts` | claim + arm + dispatch; `200` with `attempt.status` `succeeded` / `failed` / `unknown` and the observation facts `dispatch_armed`, `request_written`, `response_observed`, `http_status`; `409 approval_pending` (with `Retry-After`), `409 operation_already_succeeded`, `409 operation_outcome_unknown`, `409 attempt_already_in_progress`, `409 approval_binding_stale`, `409 approval_expired`, `403 policy_denied` / `approval_required` / `approval_rejected`, `409 payload_unavailable` |
| `GET /v1/approvals/{approval_id}` | approval + operation projection (owner agent key) |
| `POST /v1/approvals/{approval_id}/decisions` `{decision: approve\|reject, reason}` | `200` decided; `401 approval_not_authorized` (no/unknown approver credential, admin key, agent key, or a group not named by the matched rule — refusals are evidenced); `404 not_found` (no approval with that id **in the principal's tenant scope** — a valid id of another tenant is indistinguishable from a nonexistent one and touches nothing); `409 approval_already_decided`; `409 approval_expired` |

Error envelope: `{"error": {"code", "message", "operation"?}}`. The code is the contract; HTTP status alone is insufficient. Codes are entries of the shared governance registry (`internal/govcode`, [MCP governance extension](mcp-governance-extension.md)), so the MCP adapter reports the same domain outcome under the same code.

**Evidence reference (#372).** Every operation projection returned by a call that committed lifecycle evidence (establish, decision, attempt, and the evidenced `operation_conflict` refusal) carries `evidence: {"id", "committed": true, "sequence"}`: the id of the last lifecycle record that call committed in the same SQLite transaction as the state change. Reads (`GET`) commit nothing and carry no `evidence`. The reference is a locator for `talon audit verify <id>` / `talon audit verify --operation <operation_id>`, never proof by itself, and `committed: true` is not a completeness or immutability claim.

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
- **Revalidation at claim and at decision.** Current definition digest and approval-relevant policy digest must match at **both** points: a reviewer decision on a pending approval whose policy (company or use case: groups, forbidden actions, lifetime) changed since establishment is refused and the approval is invalidated with signed evidence, never reinterpreted under the new rule; a current DENY blocks even an approved operation; first-attempt claim checks approval expiry; the sealed payload must open.
- **Company policy reaches every use case and cannot be weakened.** The shared ACME scenario (`internal/testutil/acme`, test ids `A1-*`/`A2-*`/`A3-*`) proves it at every level: the pure compiler, the service, runtime generation (company digest in the generation id, frozen across reloads, malformed policy never activates), the real router, and the built binary across a restart with a changed company rule (`make test-action-smoke`, smoke section 41 of `make test-smoke`, and a named PR CI step).
- **At most one effect.** Concurrent claims yield exactly one attempt; a succeeded operation is permanently closed; the dispatcher never replays at the transport level.
- **Crash recovery.** Interrupted after claim but before arm → retryable `failed/not_dispatched`; after arm (before the call, after the write, or after the response) → `unknown`, payload purged, no retry.
- **Evidence.** Every transition is a signed `action_lifecycle` record (spec 1.12) whose generic `status` is explicit (`queued`, `running`, `completed`, `failed`, `denied`, `cancelled`, `unknown`) — an ambiguous outcome is `unknown` at both the lifecycle and the generic level, never the empty-means-completed default; `talon audit verify --operation <id>` verifies signatures and lifecycle consistency (arm before completion, observed write + response for success, no attempt after close, reviewer tenant = operation tenant); tampered fields and impossible orders fail.
- **Referential integrity.** The evidence database connection enforces SQLite foreign keys; an approval, attempt or sealed payload cannot exist without its operation.

## Verify locally

```bash
make test-action-smoke             # built binary, mock downstream, no keys (= scripts/action-smoke.sh; smoke section 41; PR CI step)
scripts/action-catalog-smoke.sh    # trusted sources: CLI inspection, catalog in the generation, refresh/last-known-good
go test ./internal/action/...      # domain, repository, concurrency, verifier, MCP source discovery (official go-sdk upstream)
```

# NVIDIA OpenShell — composing Talon with external agent containment

**Status:** reference integration (#482/#457): model request side, response side (opt-in `response_governance`) and the sandbox → Action Gateway channel through the hop assertion are implemented and fixture-tested in every CI run; the live cases G–N and the settlement assertions are validated by the `OpenShell Live` workflow, not by this text; the fixture lane runs in every CI run and the live lane drives the **released OpenShell v0.1.3** gateway and sandbox in the `OpenShell Live` workflow, whose latest run is the source of truth for the full composition (a red run means the composition is broken, not that the lane was skipped). Two automated lanes: the fixture contract smoke (`scripts/openshell-smoke.sh`, routine CI) and the real-runtime live smoke (`scripts/openshell-live.sh` / `make test-openshell-live`, the `OpenShell Live` workflow) that drives a real v0.1.3 gateway and sandbox. Not yet implemented on this path: response-phase (`HTTP_RESPONSE/PRE_RETURN`) governance, WebSocket governance, and exact consequential-action authorization on this path (#431; the shipped #458 spine lives on the Action Gateway, not on the OpenShell model channel). Architecture context: this is the DELEGATE example of [ADR-004](../contributor/adr/ADR-004-modular-control-plane-and-runtime-boundaries.md) and [Control-plane boundaries](../reference/control-plane-boundaries.md).

| Claim | How it is verified |
|---|---|
| Talon speaks the v0.1.3 supervisor-middleware contract and negotiates the extension protocol | fixture smoke + live smoke (`Describe` with gateway peer metadata; the real gateway starts) |
| Talon decides before OpenShell injects the provider credential and never sees it | live smoke: provider receives the OpenShell-injected key, Talon state/logs/evidence contain neither it nor any credential header |
| PII transformation reaches the provider as Talon's exact body | fixture smoke (byte-exact) + live smoke (semantic JSON through OpenShell's framing) |
| Talon DENY → zero provider dispatch | fixture smoke + live smoke (mock provider count) |
| Unbound / forged / foreign identity → zero dispatch | live smoke (unbound real sandbox) + unit/fixture matrix (forged, expired, wrong `typ`/`iss`/`aud`, cross-sandbox) |
| Talon unavailable → OpenShell fails closed | live smoke (`middleware_failed`, provider count unchanged) |
| Talon restart needs no gateway restart | live smoke |
| Evidence provenance is literal (`delegated_expected`, `external_asserted`) | both lanes, offline `talon audit verify` |

OpenShell contains the agent runtime: filesystem, process, syscall and network sandboxing, and endpoint-bound provider credentials. Talon applies company policy to the model traffic OpenShell admits, decides what may reach a provider and in what form, and writes signed, verifiable evidence. Neither replaces the other, and neither is required by the other — Talon keeps governing ordinary apps, MCP clients, external workflows and coding agents that never run in a sandbox.

## Topology

Talon is registered with OpenShell as a **supervisor middleware** (OpenShell's supported extension point for inspecting and transforming admitted HTTP traffic). Pinned upstream contract: **OpenShell v0.1.3**, proto package `openshell.middleware.v1` (`internal/openshell/proto/v0.1.3`, with upstream paths and sha256 in `PROVENANCE.md`). The proto files are byte-identical to v0.1.2; what v0.1.3 required of Talon is the extension-protocol negotiation described below.

```text
agent process in sandbox
  → OpenShell network policy          (OpenShell: default deny, binary + host + port + L7 rules)
  → Talon  EvaluateHttpRequest        (Talon: identity, policy, PII, budget, tool governance → ALLOW/transform/DENY)
  → OpenShell credential injection    (OpenShell: placeholder → real provider key, endpoint-bound)
  → provider
```

Per the enforcement doctrine in #424 this is **DELEGATE**: Talon makes the decision, OpenShell's pre-execution hook enforces it. OpenShell's documented contract for that hook (v0.1.3): a middleware DENY always blocks regardless of `on_error`; an unavailable or failing middleware blocks by default (`on_error: fail_closed`); the request-phase middleware runs **before** credential injection and never sees the credential.

Talon does **not** dispatch, retry or fall back on this path.

## Who owns what

| Concern | Owner | How |
|---|---|---|
| Company/use-case policy for model traffic (models, providers, PII, budgets, tools, egress tiers) | **Talon** | the same pre-dispatch decision `/v1/proxy` uses (`internal/gateway/decision.go`) |
| Network admission, binary pinning, filesystem/process/syscall containment | **OpenShell** | its own policy; Talon does not mirror or compile any of it |
| Provider credential | **OpenShell** | placeholder resolution after Talon answers; Talon evidence records `upstream_auth_mode: external_runtime` and no `secrets_accessed` |
| Sandbox identity | **OpenShell issues, Talon verifies** | gateway-signed extension JWT (`typ: openshell-ext+jwt`, EdDSA) verified against configured issuer/audience/JWKS; subject bound to one agent in `agent.talon.yaml` |
| Provider attempt lifecycle (timeout, retry, fallback, cancellation) | **OpenShell + the agent's SDK** | each SDK retry is a fresh Talon decision; Talon's `retry`/`fallback` settings are inert on this path |
| Signed evidence | **Talon** | one record per decision with `workload_identity` and `enforcement` (evidence spec 1.11) |
| Containment facts OpenShell enforced alone | **OpenShell enforces, Talon imports** | `talon audit import-external` over OpenShell's OCSF export, labelled `external_asserted`, receipt unverified (an operator-imported assertion, never a Talon observation) |

There are no two authorities for one decision: a Talon rule never appears in OpenShell policy and an OpenShell rule never appears in Talon YAML. The one candidate for **COMPILE** — Talon's provider allowlist into OpenShell's endpoint allowlist — was evaluated and rejected for v1: OpenShell admission is additionally keyed by calling binary, L7 rules and `enforcement: enforce|audit`, so the semantics are not equivalent and a mechanical mapping could silently widen or narrow. No static capability-delta work applies because no mapping exists.

## Protocol negotiation and manifest (extension protocol 1.0)

At startup the gateway calls `Describe` with its own `PeerMetadata` (protocol 1.0, `openshell/gateway`, capability `openshell.supervisor-middleware.contract` both supported and required). Talon validates it reciprocally and fails closed: missing metadata or protocol version, another protocol major, a gateway requirement Talon does not implement, or a gateway that lacks the contract capability is answered with gRPC `FailedPrecondition` (`peer_metadata_missing`, `peer_protocol_version_incompatible`, `peer_capability_missing`, `peer_metadata_invalid`), and the gateway refuses to start. A newer compatible minor and additive unknown gateway capabilities are accepted.

Talon's manifest advertises only what it implements: `HTTP_REQUEST / PRE_CREDENTIALS` always and `HTTP_RESPONSE / PRE_RETURN` when `response_governance` is enabled, with `max_payload_bytes` (the response binding uses `max_capture_bytes`) and `request_timeout` from `gateway.openshell`, `expected_audience` equal to the configured verification audience (OpenShell refuses to start if it differs from the registration's `audience`), and `Extension{protocol 1.0, talon, <version>, supported=[contract], required=[contract]}`. `WEBSOCKET_MESSAGE` exists in the contract and is **not** advertised: Talon does not implement it, and a binding is a capability promise, not metadata; `HTTP_RESPONSE / PRE_RETURN` is advertised only when `response_governance` is on, for the same reason. The manifest `name` and the registration name are diagnostics and operator identity respectively; neither is ever a Talon tenant or agent identity (`ValidateConfig` rejects any policy-local config).

## Identity and binding (#457)

OpenShell's supervisor authenticates to registered middleware with a short-lived gateway-signed JWT (unchanged in v0.1.3): `typ: openshell-ext+jwt`, `alg: EdDSA`, `iss: openshell-gateway:<gateway_id>`, `aud` = the registration audience, `sub: spiffe://openshell/sandbox/<sandbox_id>`, `caller_kind: supervisor`, `sandbox_id`, `jti` (reused until rotation, so it is not a replay discriminator), `iat/exp` (900 s by default, ≤ 1 h). Keys are published at the gateway's `/.well-known/jwks.json` and `/.well-known/openid-configuration` (issuer = the gateway identity, not the URL). Tokens are bearer credentials; v0.1.3 offers no mTLS client authentication for middleware, and Talon implements none. A plaintext (`allow_insecure_transport`) registration carries **no** token, so every request is denied for missing identity.

Talon verifies: EdDSA signature under a known `kid`, exact `typ`, exact `iss` and `aud`, `exp`/`nbf`/`iat`, bounded lifetime, `caller_kind == supervisor`, `sub` consistent with `sandbox_id`, and `sandbox_id` consistent with the request context. The verified subject then resolves to **one** agent through trusted Talon configuration:

```yaml
# agent.talon.yaml
agent:
  name: sandboxed-support
  key: { secret_name: sandboxed-support-talon-key }   # still required for gateway-loaded agents
  workload_identity:
    bindings:
      - runtime: openshell
        subject: "spiffe://openshell/sandbox/<sandbox_id>"
```

Rules, all tested:

- an unverified, expired, forged, wrong-audience or wrong-issuer token → `workload_identity_required`, nothing evaluated, zero dispatch;
- a verified subject bound to no agent → `workload_identity_unbound`, zero dispatch;
- a subject binds to exactly one agent per installation (registry build fails otherwise);
- OpenShell's `sandbox` display name, the policy-local middleware `config` and request headers can never select an agent (`ValidateConfig` rejects any policy-local config);
- the raw token is verified in memory and never persisted; evidence stores issuer, subject, audience, method, binding source and outcome only.

Sandbox ids are per sandbox, so a new sandbox needs a new binding line. Bindings live in the agent file and ride the normal agent reload (#269); no Talon restart is needed.

## Action Gateway through the hop (#457/#482 — the sandbox holds no Talon secret)

A sandboxed agent that must request a **consequential action** (`POST /v1/action-operations`, see [`action-gateway.md`](../reference/action-gateway.md)) reaches Talon's own HTTP API through the same OpenShell egress and the same `talon` middleware. The sandbox never holds an agent key or any Talon credential, and OpenShell does not let middleware write the `Authorization` header of a forwarded request. Talon therefore authenticates the sandbox at the **hop**:

1. The operator lists the host (optionally `host:port`) under which sandboxes reach Talon in `gateway.openshell.self_destination.hosts` and attaches the `talon` middleware to that host in the sandbox policy (network policy admits Talon's port; nothing else is needed).
2. On a sandbox request to that host, Talon's middleware verifies the gateway-signed token exactly as for model traffic, binds the subject to its use case (`workload_identity_unbound` / `agent_disabled` fail closed), and allows only the agent-facing routes: `POST /v1/action-operations`, `GET /v1/action-operations/{id}`, `POST /v1/action-operations/{id}/attempts`, `GET /v1/approvals/{id}`. Everything else — above all the reviewer route `/v1/approvals/{id}/decisions` and the model proxy — is denied with `self_destination_path_not_governed` before any binding is resolved.
3. Talon returns ALLOW with one header mutation: `X-Talon-Workload-Assertion` written with **overwrite** semantics, so a value the sandbox put there itself is replaced, never appended to. The assertion is a Talon-signed (HMAC-SHA256 under a key HKDF-derived from the deployment root `TALON_SECRETS_KEY`, info `talon-workload-hop-assertion-v1`), short-lived (`assertion_ttl`, default 60 s, max 5 m) statement of what the hop verified — runtime, issuer, subject, principal, sandbox id, OpenShell request id, bound agent and tenant, the client-asserted session header — **bound to the exact method, path and SHA-256 of the body** the hop saw. It never contains the gateway token.
4. Talon's ingress verifies the assertion against the request it actually receives (signature, lifetime, audience, method/path/body digest), re-resolves the binding on the **current** runtime generation (a binding removed or an agent disabled in between fails closed), and sets the same agent identity an agent key would. An agent key presented together with an assertion must name the same use case (`workload_identity_conflict` otherwise). The operation is established with `identity_source: workload_asserted`.
5. From there the Action Gateway contract is unchanged: ALLOW → the sandbox claims and Talon dispatches once; DENY → zero dispatch; REQUIRE_APPROVAL → zero dispatch until a **human reviewer** decides from outside the sandbox; the approved claim dispatches at most once; exact replay returns the existing operation; a changed payload conflicts.

Why this is not identity issuance: the assertion is consumed only by the deployment that minted it, names nothing a third party could redeem, and cannot be redirected (route-bound) or re-used for another payload (body-bound). Replay of the identical request within the TTL is absorbed by the operation's idempotency contract — it can never produce a second effect. A direct request to Talon carrying a sandbox-forged, tampered or expired assertion is `401 workload_identity_invalid` with no state created; the gateway-signed token is still required at the hop, so an unbound or forged sandbox never reaches Talon's HTTP API at all.

Every action lifecycle record of such an operation carries `workload_identity` (`status: verified`, `runtime: openshell`, `auth_method: workload_hop_assertion`, the real issuer and subject, `binding: agent_config`), `enforcement.provenance: talon_enforced` with `enforcement.runtime` = `{type: openshell, id: <issuer>, reference: <sandbox id>, request_id: <OpenShell request id>}` (Talon dispatches the action itself; the runtime reference is attribution and correlation, never authority), and the sandbox's `X-Talon-Session-ID` as `session_id`, so `talon audit export` joins the model decisions and the action lifecycle of one sandbox session. `talon audit verify --operation <operation_id>` verifies the whole lifecycle.

Tests: `TestHop_*` (middleware hop over real gRPC), `TestWorkloadHop_*` (ingress), `TestHopSigner_*` (assertion), `TestE2E_OpenShell_ComposedActionChannel` (fixture supervisor against the built binary, allow/deny/approval/replay/forged/tampered/unbound/cross-route, session join, offline verification, restart), live lane cases G–M (real OpenShell).

## Evidence and provenance (#146)

Every delegated decision writes one signed record (invocation type `gateway`) carrying:

```json
"upstream_auth_mode": "external_runtime",
"gateway_annotations": ["delegated_dispatch"],
"workload_identity": {"status":"verified","runtime":"openshell","auth_method":"jwt_eddsa","issuer":"openshell-gateway:gw-1","subject":"spiffe://openshell/sandbox/sb-42","principal_id":"…","audience":"…","binding":"agent_config","verified_at":"…"},
"enforcement": {"mechanism":"delegate","boundary":"external_runtime","decision_authority":"talon","provenance":"delegated_expected","decision_returned_via":"openshell_middleware",
                "runtime":{"type":"openshell","id":"openshell-gateway:gw-1","policy_ref":"<openshell network_middlewares entry>","reference":"<sandbox_id>","request_id":"<openshell request id>"}}
```

Read it precisely:

- `decision_authority: talon` — Talon decided allow/deny/transform under its own compiled policy (digests in `policy_decision.policy_digests`).
- `boundary: external_runtime`, `mechanism: delegate` — the prevention point was OpenShell's hook, not Talon's proxy.
- `provenance: delegated_expected`, `decision_returned_via: openshell_middleware` — Talon proves exactly two things: it decided, and it returned that verdict through the configured middleware. Enforcement is **expected** under OpenShell's documented hook contract and was **not observed**; Talon's HMAC proves Talon recorded this decision, nothing about what OpenShell did with it. The vocabulary is literal: `talon_enforced` (Talon owned and observed the boundary), `delegated_expected`, `external_asserted` (unsigned/unverified external statement), `external_verified` (cryptographically or authoritatively verified receipt), `client_asserted`.
- A record with no `enforcement` object is the ordinary Talon-intercepted gateway path (`talon audit show` prints the default explicitly).

An OpenShell-only containment denial (network or HTTP class, `action: Denied`) imported with `talon audit import-external --runtime openshell --file <ocsf.jsonl>` becomes an `external_runtime_event` record (never request-class): `mechanism: verify`, `decision_authority: external_runtime`, `provenance: external_asserted`, `receipt: {kind: openshell_ocsf, digest, verified: false}`, `workload_identity.status: asserted`. It is an **assertion**: Talon never claims it saw the file, process or connection, and never claims the export is authentic; it claims an operator imported OpenShell's unsigned statement. `external_verified` is reserved for receipts Talon can verify, which OpenShell v0.1.3 does not provide (its OCSF export is unsigned). Attribution uses the same sandbox binding as the live path; events for unbound sandboxes are skipped and reported.

**Cost and usage** depend on `gateway.openshell.response_governance`. Without it, Talon never sees the provider response: `execution.cost` is the pre-request estimate, token counts are zero, and budgets work on estimates. With it (recommended), Talon implements OpenShell's `HTTP_RESPONSE / PRE_RETURN` binding (`HttpResponsePreReturn.Evaluate`): the decision record books **no cost** (`pricing_basis: awaiting_settlement`, annotation `response_settlement_pending`), and when the provider's response passes the hook Talon commits a second record — `invocation_type: gateway_response`, same `correlation_id` and `session_id` — carrying the **observed** usage priced from the pricing table (`pricing_basis: table`, `pricing_known: true`), the estimate kept beside it, and `response_observed`. A response without usage fields settles with the estimate and `pricing_basis: estimate_no_usage`; a response that never arrives within `settlement_timeout` is settled by Talon's sweeper as `status: unknown`, `failure_reason: response_unobserved`, `pricing_basis: estimate_unsettled` (the estimate stands; the model call's outcome is unknown, never a claimed success); a response that arrives **after** the sweeper booked the estimate is reconciled: a further `gateway_response` record under the same correlation id (`pricing_basis: late_reconciliation`, annotation `response_observed_late`) whose cost is only the amount by which the actual exceeded the booked estimate, so the records of one request always sum to max(estimate, actual); a response Talon has no request half for at all (decided before the ledger existed) is observed once as `decision_unmatched` under the use case's current response policy. The request half is a row in a **durable settlement ledger** inside the evidence database, keyed by the runtime's own request id (runtime, sandbox, request id), written in the **same SQLite transaction** as the decision record. Every later transition — `pending → settled` (response), `pending → unobserved` (sweeper), `unobserved → reconciled` (late response) — is likewise one transaction carrying the conditional status update with its outcome and the signed `gateway_response` record, and the database takes the write lock at `BEGIN`, so two settlers of one exchange (a callback and the sweeper, two callbacks, two Talon processes on one database) never interleave: the second sees the first's committed row and replays or reconciles against it. A crash before `COMMIT` leaves the row as it was and no record for the attempt — nothing is ever settled without its record or recorded without its transition. A repeated response callback for the same exchange replays the committed verdict (`settlement_replayed`; a blocked response stays blocked, a redacted body is reproduced, and a replay that cannot re-inspect fails closed) and writes nothing; a callback whose verified principal is not the one the request was decided for is refused (`workload_identity_conflict`); a Talon restart keeps every pending obligation and the response policy that was in force at decision time. The ledger is bounded by `max_pending` — admission and insert are one statement under the write lock, so concurrent requests cannot exceed the bound — and when it is full **new** delegated requests are refused (`settlement_capacity_exhausted`, HTTP 503) rather than any obligation being dropped; a runtime request id that is still pending is refused (`settlement_unavailable`, HTTP 409) rather than overwritten. Settled rows are pruned after `ledger_retention` (default 30 days; pending rows and rows with owed session work never are). Exactly one record per request carries its cost, so budget sums never add an estimate to an actual; pending estimates still count against the daily/monthly caps while in flight. The session budget lives in a separate database and cannot join the transaction: each committed settlement records what it owes the session, applies it right after commit and marks it; a failed session update is retried by the sweeper. That is at-least-once (a crash between the session update and the mark can charge a session twice); the signed records are the spend of record and are exactly once. OpenShell selects middleware by host, so when Talon's own Action Gateway shares a host with a provider the hook also sees Talon's own responses (and any response from a host Talon has no provider for): those are skipped (`self_destination_response` / `destination_not_governed`), never settled. The request hop asks the provider for `Accept-Encoding: identity` so the response body is inspectable; a compressed body is `response_body_uninspectable` (usage unobserved) under an observational policy and **blocked** (`output_scan_unavailable`, fail closed) under a preventive one. **Content-type contract:** JSON (`application/json`, `+json`) and SSE bodies are inspected field by field; `text/*` bodies are scanned as raw text (`response_text_body_scanned`; PII blocks delivery under `block`/`redact` rather than rewriting text Talon does not understand, and is recorded under `warn`); any other media type (binary, unknown, missing) has no inspector — a preventive policy blocks it (`output_content_unsupported`), an observational one records it as uninspectable. **Capture bound:** a whole body larger than `max_capture_bytes` can only be scanned in part, and a preventive policy blocks it (`output_scan_incomplete`) even when the scanned prefix is clean — the forbidden value may sit past the bound; under `warn` it passes and the record says `capture_limit_exceeded`. A body handed over in a less restrictive mode than the plan asked for is blocked under a preventive policy (`response_mode_mismatch`). A scanner failure blocks under a preventive policy (`output_scanner_unavailable`). Provider **error** responses (4xx/5xx) are not exempt: their bodies echo inputs and validation detail, so under any response policy other than `allow` an inspectable JSON/text error body is held and scanned as a whole (`provider_error_body_scanned`) — PII in it blocks delivery under `block`/`redact` (`output_pii_blocked`; a vendor error envelope is not reconstructible, so it is not rewritten) and is recorded under `warn`; an uninspectable error body is blocked under a preventive policy. Nothing is billed for an error response.

**Response PII policy** uses the agent's effective `response_pii_action`. `block` and `redact` are **preventive** on this path: Talon asks OpenShell for `WHOLE_BODY_BYTES`, so the body — streamed or not — is held until Talon answers with pass, a transformed replacement or `block_delivery` (the sandbox then gets OpenShell's `403 middleware_denied` with Talon's reason code); evidence records `response_scan.enforcement: preventive`. `warn` on a streamed response uses `STREAM_BYTES`: units are passed as they arrive and the capture is scanned after delivery (`post_delivery_observation`); Talon never claims prevention for bytes already delivered. Blocking a response cannot undo the provider call, and OpenShell's own limitation applies: compressed, partial and `no-transform` bodies cannot be inspected.

## Configuration

```yaml
# talon.config.yaml
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"        # used by /v1/proxy only; never read on the delegated path
      base_url: "https://api.openai.com"   # the HOST is how a delegated request maps to this provider
  openshell:
    enabled: true
    listen: "0.0.0.0:50051"                # must be reachable from the OpenShell gateway AND every sandbox supervisor
    tls:
      cert_file: /etc/talon/openshell-middleware.pem
      key_file:  /etc/talon/openshell-middleware-key.pem
    identity:
      issuer:   "openshell-gateway:<gateway_id>"           # exact iss claim
      audience: "urn:openshell:extension:middleware:talon"  # exact registration audience
      jwks_url: "https://<openshell-gateway>/.well-known/jwks.json"   # or jwks_file: for a static copy
    middleware_name: talon        # must equal the gateway.toml registration name
    max_payload_bytes: 4194304    # ≤ OpenShell's 4 MiB ceiling
    request_timeout: 10s          # advertised in the manifest; OpenShell accepts 10ms–30s
    self_destination:             # optional: sandboxes reach Talon's OWN Action Gateway here
      hosts: ["talon.corp.example"]            # or "host:port" when a provider shares the hostname
      assertion_ttl: 60s                       # workload assertion lifetime, 5s–5m
    response_governance:          # recommended: HTTP_RESPONSE / PRE_RETURN (actual usage, cost settlement, response PII)
      enabled: true
      settlement_timeout: 5m                   # unobserved responses settle with the estimate after this (30s–1h)
      max_capture_bytes: 1048576               # response body bound Talon holds/observes (≤ max_payload_bytes)
      max_pending: 10000                       # settlement ledger bound; new requests are refused beyond it (100–1000000)
      ledger_retention: 720h                   # settled ledger rows are pruned after this (24h–8760h); pending ones never
```

`response_governance` is opt-in because advertising the binding changes what OpenShell asks Talon for, and a Talon outage then blocks responses (OpenShell fails closed) in addition to requests. Enable it, restart the gateway (the manifest is read at startup), and the same `network_middlewares` entry covers both hooks.

A destination host with no matching enabled provider `base_url` and no `self_destination` entry is denied with `destination_not_governed` (fail closed): if an OpenShell policy binds Talon to a host Talon does not govern, nothing passes as "allowed". A `self_destination` entry on a provider's hostname must carry Talon's own port (a destination is either Talon or a provider; the config is refused otherwise). `self_destination` needs a `TALON_SECRETS_KEY` of at least 32 bytes (the assertion key is derived from it); without one Talon refuses to start.

`allow_insecure_transport: true` serves plaintext h2c for local fixtures only. OpenShell sends **no** caller token over an insecure registration, so every real request is then denied for missing identity.

## Live lane (real OpenShell — v0.1.3 validated baseline, v0.1.4 pinned)

```bash
make test-openshell-live                          # == scripts/openshell-live.sh (OpenShell v0.1.3)
OPENSHELL_VERSION=v0.1.4 make test-openshell-live # the pinned v0.1.4 release
```

**Supported versions.** v0.1.3 (released 2026-10-09) is the validated baseline: its middleware proto is pinned under `internal/openshell/proto/v0.1.3/` and the live lane runs it as the required workflow entry. v0.1.4 (released 2026-10-13) is pinned in the lane with its release checksums; its `supervisor_middleware.proto` differs from v0.1.3 by one comment and `extension.proto` is identical, so the generated contract is unchanged. The `OpenShell Live` workflow runs v0.1.4 as an **experimental** matrix entry (reported, not blocking) until it has passed once and is promoted; until then "v0.1.4 works" is a pinned expectation, not a validated claim. Versions without pinned checksums are refused by the harness. Newer releases are never assumed compatible: add the pin, run the lane, then document.

What it does, on one Linux host with Docker Engine ≥ 28 (GitHub-hosted `ubuntu-latest` in the `OpenShell Live` workflow, or any developer Linux box): downloads the **released** v0.1.3 `openshell` CLI and `openshell-gateway` binaries and verifies their sha256 against the release manifests on every run (the cached tarballs are re-verified, never trusted); builds `talon` and a deterministic mock OpenAI-compatible provider from the checkout; generates the gateway's Ed25519 signing bundle and Talon's middleware TLS identity in OpenShell's trust topology (an operator CA that signs Talon's server certificate; SANs: the host address and `host.openshell.internal`, EKU serverAuth; the CA, not the leaf, is `tls_ca_cert_path`); proves that `Describe` over TLS fails with an unrelated CA and succeeds with the registered one; starts Talon with the `gateway.openshell` block below; starts the real gateway (docker driver, `--disable-tls` listener, `gateway_jwt`, Talon registered over `https://<host>:<port>` with `tls_ca_cert_path`); imports a provider profile that binds `OPENAI_API_KEY` to `host.openshell.internal:<mock port>`; creates a provider with the mock key; creates a sandbox with `--from` the digest-pinned workload fixture (below), the policy below and `--provider`; proves inside that real sandbox that `curl`, `sh` and `sleep` exist at the paths the profile and policy name and that Docker resolved the pinned digest; binds the **real** sandbox id in `agent.talon.yaml` (picked up by the agent reload, no restart); then issues requests with `openshell sandbox exec … curl` and asserts on the mock provider's counters and recorded bytes, OpenShell's error envelopes, and Talon's signed evidence. It refuses to start, with a clear message, when Docker, the kernel or a tool is missing; nothing is installed system-wide and no provider spend occurs.

Cases and assertions:

| Case | Sandbox request | Expected |
|---|---|---|
| A allowed | `gpt-4o-mini`, plain content | provider count 1; provider saw `Authorization: Bearer <OpenShell-injected key>`; Talon record `workload_identity.status: verified`, `upstream_auth_mode: external_runtime`, `enforcement.provenance: delegated_expected` |
| provenance split | — | no model-path record (`gateway`, `gateway_response`) of an OpenShell identity is `talon_enforced`; action lifecycle records of the same sandbox are `talon_enforced` with `enforcement.runtime` naming it (Talon dispatches the action) |
| B PII | content with `jane.doe@example.com` | provider count 2; forwarded body differs from the original, never contains the e-mail, keeps the rest |
| C blocked model | `gpt-4o` | sandbox gets `403 {"error":"middleware_denied", "reason_code":"model_not_allowed"}`; count unchanged |
| D unbound identity | second sandbox with no Talon binding | `403 middleware_denied`, `reason_code: workload_identity_unbound`; count unchanged |
| E Talon down | Talon stopped | `middleware_failed` from OpenShell (`on_error: fail_closed`); count unchanged — OpenShell enforced this, not Talon |
| F Talon restart | same registration | request governed again, count 3, no gateway restart |
| G allowed read action | `POST /v1/action-operations` (`lookup_ticket`) then the claim, via the hop | 201 under the verified sandbox identity (no agent key in the sandbox); claim `succeeded`; protected service `tickets` = 1 |
| H forbidden action | `delete_customer` (in `forbidden_tools`) | 403 `DENY`; claim `403 policy_denied`; protected `customers` = 0 |
| I approval-required action | `create_refund_request` | 202 `awaiting_approval`; claim `409 approval_pending`; the sandbox can read its approval; a human reviewer approves from the host → `authorized`, `refunds` still 0; sandbox claim → `succeeded`, `refunds` = 1; exact replay → `created: false`; second claim `409 operation_already_succeeded`; `refunds` still 1; the protected service saw Talon's `Idempotency-Key` |
| J unbound sandbox, action path | second sandbox | `403 middleware_denied`, `reason_code: workload_identity_unbound`; Talon record count unchanged; protected count unchanged |
| K assertion header | sandbox writes `X-Talon-Workload-Assertion` itself; a forged assertion sent directly to Talon from the host | the hop overwrites the sandbox's value (the request still resolves to the verified sandbox's own operation); the direct forgery is `401 workload_identity_invalid` |
| L direct egress | sandbox `curl` to the protected service's port | blocked by OpenShell network policy (the port is not admitted); protected count unchanged — OpenShell enforced this, not Talon |
| M reviewer route | sandbox `POST /v1/approvals/{id}/decisions` with a reviewer credential | `403 middleware_denied`, `reason_code: self_destination_path_not_governed` |
| O | model response whose body carries an e-mail address (`X-Mock-Scenario: response-pii`, org policy `redact`) | 200; the sandbox receives Talon's replacement body (envelope and `usage` kept), never the value; the settlement is `output_pii_detected` with a `preventive` response scan and the mock's usage |
| P | model response of ~5 KiB with the e-mail address past the 4 KiB `max_capture_bytes` (`oversized`) | not 200; zero body bytes reach the sandbox; the settlement is a block with `response_scan.status: incomplete`, `incomplete_reason: capture_limit_exceeded` |
| Q | provider `400` whose error envelope echoes the e-mail address (`error-pii`) | not 200 and not the provider's 400; the sandbox never sees the value; the settlement is `status: failed`, blocked, `output_pii_detected`, cost 0 |
| R | provider holds its answer 15 s; Talon is killed after the decision and restarted before the response | 200 with the held completion; the new process settles against the ledger row the old process committed with the decision (no `decision_unmatched`) |
| response settlement | every allowed model response (A, B, F, O, R; P and Q settle without priced usage) | each allowed decision record has `pricing_basis: awaiting_settlement` and `cost: 0`; exactly one `gateway_response` record per decision under the same `correlation_id`; the priced ones carry the mock's actual usage (`tokens 12/3`), `cost > 0` from the table and `response_observed`; no `decision_unmatched`; the e-mail address appears nowhere in the export or the serve log |
| evidence | — | ≥3 `delegated_expected` records with `decision_authority: talon`, `decision_returned_via: openshell_middleware`; one allowed record verifies offline; ≥8 `action_lifecycle` records with `workload_identity` verified for the real issuer and sandbox subject, `auth_method: workload_hop_assertion`, `enforcement.provenance: talon_enforced`, `enforcement.runtime.reference` = the sandbox id, `identity_source: workload_asserted`; the session header joins ≥3 model and ≥8 action records; `audit verify --operation` VALID for the refund and the denial; the provider key, the reviewer credential and assertion material appear nowhere in Talon's data dir, serve log or export; Talon's own vault value never reaches the provider |

**Workload fixture.** The automated docker-driver proof creates its sandboxes from `docker.io/curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777` (multi-arch index digest) solely as a deterministic, curl-capable workload: it contains `/usr/bin/curl` (the binary the provider profile and network policy name), busybox `/bin/sh` and `/bin/sleep`, and nothing is installed at run time; because Alpine keeps busybox under a real `/bin` (outside OpenShell's `/usr`-based baseline), the lane's sandbox policy adds `filesystem_policy: { include_workdir: true, read_only: [/bin] }`, a fixture need and not a governance rule. OpenShell's default workload image (`nvcr.io/nvidia/base/ubuntu:24.04`) is never used because it has no HTTP client. Production deployments run their own agent images; Talon has no dependency on this image or on curl, and the reference architecture is independent of the fixture.

The run prints the OpenShell versions and checksums, the Talon commit, the Docker/kernel versions, the workload image with its resolved digest and in-sandbox binary paths, and the OpenShell images used. The gateway's OCSF JSONL (`[openshell.gateway.ocsf_log]`) is kept with the logs.

Minimal configuration actually used by the lane (operator values in angle brackets):

```toml
# gateway.toml (OpenShell)
[openshell]
version = 2
[openshell.gateway.gateway_jwt]           # the gateway mints extension tokens with this key
signing_key_path = "<dir>/signing.pem"
public_key_path  = "<dir>/public.pem"
kid_path         = "<dir>/kid"
gateway_id       = "<gateway_id>"          # Talon's identity.issuer is "openshell-gateway:<gateway_id>"
[[openshell.supervisor.middleware]]
name = "talon"                             # policies attach by this name; restart the gateway after changing it
grpc_endpoint = "https://<host>:50051"      # reachable from the gateway AND every sandbox supervisor
tls_ca_cert_path = "<dir>/ca.pem"                # the CA that signed Talon's tls.cert_file; a self-signed leaf is NOT accepted as a trust anchor
audience = "urn:openshell:extension:middleware:talon"
max_payload_bytes = 1048576                # ≤ Talon's gateway.openshell.max_payload_bytes
timeout = "10s"                            # ≥ Talon's request_timeout; 10ms–30s
```

```yaml
# sandbox policy (OpenShell)
version: 1
network_middlewares:
  talon-governance:
    middleware: talon
    order: 10
    on_error: fail_closed
    endpoints: { include: ["<provider host>"] }
network_policies:
  provider:
    endpoints:
      - { host: "<provider host>", port: 443, protocol: rest, access: read-write, enforcement: enforce }
    binaries: [{ path: /usr/bin/curl }]
  talon-action-gateway:                  # Talon's own API, selected by the same middleware entry (by host)
    endpoints:
      - { host: "<talon host>", port: <talon http port>, protocol: rest, access: read-write, enforcement: enforce }
    binaries: [{ path: /usr/bin/curl }]
```

In the lane, `<provider host>` and `<talon host>` are both `host.openshell.internal` on different ports, so Talon's `self_destination.hosts` entry is `host.openshell.internal:<talon http port>`. The protected action target's port is deliberately absent from the policy (case L).

The provider credential stays an OpenShell provider (profile endpoint bound to `<provider host>`), attached with `--provider`; Talon never holds it. Registration is static: changing the `[[openshell.supervisor.middleware]]` entry requires a gateway restart; restarting Talon itself does not (case F).

## Operator runbook

**Supported versions.** OpenShell v0.1.3 (validated baseline, live lane required entry) and v0.1.4 (pinned, experimental matrix entry until green). Talon pins the middleware proto under `internal/openshell/proto/v0.1.3/`; v0.1.4's proto is identical but for a comment. A release that changes the proto needs a new pin, regenerated types (`make openshell-proto`), a live run and a documentation update — never an assumption.

**Reproduce the reference environment first.** On a Linux host with Docker ≥ 28, `TALON_OPENSHELL_KEEP=1 make test-openshell-live` builds Talon, downloads the pinned OpenShell release (checksums verified), generates a local-only operator CA, Talon's TLS identity, the gateway's JWKS, a complete `talon.config.yaml` with `gateway.openshell` (identity, `self_destination`, `response_governance`), a use case with bindings, catalog and approval rule, a reviewer credential, and the sandbox policy that admits the provider and Talon's host with the `talon` middleware attached fail-closed — then runs cases A–R against the real runtime and keeps the work dir (`work dir retained: …`). Every file there is a worked example of the steps below; none of its keys or certificates is for production. The steps below are the same decisions made for your own hosts and trust anchors.

**Deploy, in order.**

1. **Talon TLS identity.** Issue a server certificate for Talon's middleware listener from an operator CA (serverAuth EKU, SANs for every address the gateway and supervisors dial). Configure `gateway.openshell.tls`; give OpenShell the **CA** as `tls_ca_cert_path`. A self-signed leaf is refused by OpenShell's rustls trust anchor rules.
2. **Trust anchors.** Set `identity.issuer` to `openshell-gateway:<gateway_id>` (the `gateway_jwt.gateway_id` of your gateway) and `identity.audience` to the registration audience; point `identity.jwks_url` at the gateway's `/.well-known/jwks.json` over TLS (or ship a static `jwks_file`). Rotation of the gateway signing key is picked up by `jwks_url` on the next unknown `kid`; a static file must be replaced.
3. **Use cases.** For each sandbox, bind its id in the agent file (`agent.workload_identity.bindings`). Declare the trusted action catalog (`actions.definitions`), the approval rules (`policies.approvals`) and `capabilities.forbidden_tools`. Bindings and catalog changes ride the agent reload; no Talon restart.
4. **Action Gateway hop.** Set `self_destination.hosts` to the host (`host:port` when a provider shares the hostname) under which sandboxes dial Talon's HTTP API; `TALON_SECRETS_KEY` must be 32 bytes and identical on every Talon instance that verifies assertions.
5. **Response governance.** Set `response_governance.enabled: true` (recommended). It changes the manifest, so restart the OpenShell gateway after enabling it.
6. **Reviewers.** `talon approver add --name <who> --tenant <t> --groups <group>`; keep the credential outside the sandbox. Decisions are `POST /v1/approvals/{id}/decisions` from the operator network.
7. **Provider.** Register the provider in OpenShell with its credential (Talon never holds it); the provider's hostname is how Talon maps a delegated request to its configured provider (`providers.<name>.base_url`), so the two must agree.
8. **Register.** Add the `[[openshell.supervisor.middleware]]` entry (name, `https://` endpoint, `tls_ca_cert_path`, audience, `max_payload_bytes ≤` Talon's, `timeout ≥` Talon's `request_timeout`) and restart the gateway; it refuses to start when `Describe` fails (unreachable, wrong CA, protocol mismatch, audience mismatch).
9. **Sandbox policy.** Admit the provider host and Talon's host:port in `network_policies`; attach the `talon` middleware to both in `network_middlewares` with `on_error: fail_closed`. Do **not** admit the protected action targets: the sandbox reaches them only through Talon (live case L proves OpenShell blocks the direct path).
10. **Verify.** `talon doctor --gateway-config talon.config.yaml` (category `openshell`: transport, identity keys, bindings, self destination, response governance), then run `examples/openshell/sandbox-agent.sh` inside a sandbox and `talon audit list --session <id>` / `--runtime-ref <sandbox id> --report` / `talon audit verify --operation <id>` on the host. `--runtime-ref` is a filtered scan of the most recent records (50×`--limit`, at least 500 and at most 20,000, per tenant/agent), not an indexed lookup: for older history narrow with `--tenant`/`--agent` or use `--session`/`--operation`, which are indexed.

**Rotation and recovery.**

- *Gateway signing key:* with `jwks_url`, nothing to do (an unknown `kid` triggers a refetch; OpenShell tokens are ≤ 1 h). With `jwks_file`, replace the file and restart Talon.
- *Talon TLS certificate:* replace the files and restart Talon; the registration (CA) is unchanged unless the CA changed, in which case update `tls_ca_cert_path` and restart the gateway.
- *`TALON_SECRETS_KEY`:* rotating it invalidates in-flight assertions (TTL ≤ 5 m) and the sealed action payloads of in-flight operations (`payload_unavailable` at claim); rotate between operations, on every instance at once.
- *Sandbox replaced:* a new sandbox id needs a new binding line; the old binding should be removed (an orphaned binding is harmless but misleading).
- *Talon restart:* no gateway restart (live case F). In-flight response settlements survive in the ledger (evidence database): their responses settle normally under the decision-time policy, and ones that never arrive are swept as `response_unobserved`; in-flight hop assertions remain valid until their TTL.
- *Talon outage:* OpenShell fails closed for requests and, with response governance, for responses (`middleware_failed`). Nothing is dispatched or delivered ungoverned; nothing is recorded by Talon for that window.

**Upgrade and rollback.** Talon upgrades are independent of the gateway while the pinned proto is unchanged; downgrading Talon below this release drops the response binding from the manifest and the gateway must be restarted to stop asking for it. Moving OpenShell to a newer release: run `OPENSHELL_VERSION=<tag> make test-openshell-live` (the harness refuses unpinned versions), then promote in the workflow matrix and here.

**Troubleshooting.**

| Symptom | Cause | Check |
|---|---|---|
| gateway refuses to start, log mentions TLS/certificate | wrong CA, missing SAN, self-signed leaf | `talon doctor` `openshell_transport`; `tls_ca_cert_path` is the CA |
| gateway refuses to start, protocol/capability | proto or capability mismatch | Talon version vs pinned contract; `Describe` with `tests/openshell-live/describe` |
| every request `workload_identity_required` | tokens not verifiable (issuer/audience/JWKS) or insecure registration | `openshell_identity_keys`; `identity.issuer == openshell-gateway:<gateway_id>` |
| every request `workload_identity_unbound` | sandbox id not bound | `openshell_bindings`; `openshell sandbox list --ids` |
| action requests `destination_not_governed` | Talon's host missing from `self_destination.hosts` or port mismatch | config; the sandbox dials exactly the listed host:port |
| action requests `self_destination_path_not_governed` | route is not an agent-facing Action Gateway route | only `/v1/action-operations*` and `GET /v1/approvals/{id}` pass the hop |
| `401 workload_identity_invalid` at Talon | assertion tampered, expired, or replayed against another route/body; different `TALON_SECRETS_KEY` across instances | the hop and ingress must share the root key |
| responses `middleware_failed` | Talon down or response hook erroring | Talon logs; OpenShell `on_error: fail_closed` is doing its job |
| responses blocked `output_scan_unavailable` | compressed/partial body under a preventive policy | the request hop sets `Accept-Encoding: identity`; a proxy in between may re-compress |
| settlement `estimate_unsettled` / `unknown` | no response within `settlement_timeout` | provider latency or sandbox abort; the estimate stands (a later response reconciles as `late_reconciliation`) |
| `settlement_capacity_exhausted` (503) | the ledger holds `max_pending` unsettled requests | responses are not reaching Talon (response hook not attached, or the sweeper's `settlement_timeout` is long relative to load); check `talon audit list --runtime-ref <sandbox id>` for missing `gateway_response` records, raise `max_pending` or shorten `settlement_timeout` |
| `settlement_unavailable` (503/409) | the ledger cannot be read/written, or the runtime reused a pending request id | evidence database health; a 409 names a duplicate runtime request id |
| `output_scan_incomplete` | a response larger than `max_capture_bytes` under `block`/`redact` | raise `max_capture_bytes` (≤ OpenShell's `max_payload_bytes`) or accept that large bodies are blocked under a preventive policy |
| `output_content_unsupported` | a non-JSON/SSE/text response under `block`/`redact` | the provider returned a media type Talon cannot inspect; a preventive policy has no safe way to deliver it |
| `workload_identity_conflict` (response) | the response callback's sandbox is not the one the request was decided for | a runtime misbinding; the obligation stays with the original exchange |

## Reference agents

Two agents ship under `examples/openshell/`, both running **inside** the sandbox with no Talon, reviewer or provider credential:

- `sandbox-agent.sh` — the deterministic protocol fixture (POSIX `sh` + `curl` + `sed`): every step is scripted, so the live lane (case N) runs it against the released runtime and asserts each boundary.
- `agent/` (`support-agent`) — the **tool-using** reference built on the official OpenAI Go SDK: the model chooses tools through chat-completions tool calling and the agent executes every tool as a Talon action (`lookup_ticket` allowed, `delete_customer` forbidden, `create_refund_request` approval-required). Talon removes the forbidden tool from what the model sees (`tool_governance.tools_filtered`) and, when the model asks for it anyway, denies the exact action before dispatch; the refund waits for a reviewer outside the sandbox and is dispatched at most once on the agent's claim (a replay never duplicates the effect). `TestE2E_OpenShell_SDKAgent` runs this binary against the built Talon through a fixture gateway (two plain-HTTP listeners replaying OpenShell's supervisor for whatever the agent sends, including the response hook) with a scripted model, so CI proves the journey without spend; it is not part of the live lane (the pinned sandbox image carries only curl). See `examples/openshell/agent/README.md` for the SDK choice, environment and the operator steps.

**Walkthrough.** `talon audit list --runtime-ref <sandbox id> --report` renders one sandbox's history as the operator reads it: the verified identity; every model exchange (decision verdict, request PII, tools removed, pricing basis) with its settlement (tokens, cost, basis, response scan and delivery); every operation with its lifecycle (verdict, the human reviewer's decision, the claimed attempt, dispatch and result, provenance); imported runtime events in their own section, labelled as external assertions Talon recorded but did not verify; and the count of records whose Talon signature verifies. Ordering is deterministic (oldest first within each section), the query is complete over the store (paged by `--limit`/`--offset`), and no credential or payload value is printed.

## Bypass model — stated honestly

- **Agent → provider directly, skipping Talon.** Prevented by **OpenShell**, not Talon: the provider host is admitted only with the Talon middleware bound to it, `tls: skip` endpoints cannot overlap a fail-closed middleware selector (OpenShell policy validation), and every other destination is default-denied. Talon can only import the resulting OCSF denial. If the OpenShell policy admits the provider host without binding Talon, traffic flows ungoverned and Talon has no record — that is an OpenShell policy error Talon cannot detect.
- **Agent → Talon's gRPC endpoint directly.** Needs a gateway-signed supervisor token; a workload never holds one and cannot mint one. A stolen token binds one sandbox and is checked against the request context.
- **Agent → Talon's Action Gateway directly, skipping the hop.** Needs a valid workload assertion; only Talon mints them, only at the hop, only for a verified and bound sandbox, bound to one request. A sandbox-forged, tampered, re-routed or re-bodied assertion is `401 workload_identity_invalid`; an assertion replayed verbatim within its TTL reaches the idempotency contract and cannot cause a second effect. Inside a real sandbox this path does not exist at all: every egress passes the supervisor.
- **Agent → reviewer route.** Unreachable through the hop (`self_destination_path_not_governed`) whatever credential the sandbox holds; from outside, reviewer credentials are tenant-scoped local principals and are never accepted from an agent-identified request.
- **Host compromise mints assertions.** The assertion key derives from Talon's root secret: an attacker with that secret can forge assertions, as they could forge any Talon state. This is the same trust boundary as the vault, not a new one.
- **Middleware unavailable.** OpenShell blocks (fail closed by default). Talon does not retry, so there is no retry amplification between the layers.
- **Host or gateway compromise.** Out of scope for both products' claims here. Talon does not claim kernel isolation, filesystem containment, or resistance to a compromised OpenShell gateway (which could mint tokens for any sandbox).
- **Response side.** With `response_governance` Talon implements `HTTP_RESPONSE / PRE_RETURN`: preventive response PII policies hold the body until Talon answers; observational ones watch after delivery and say so. Without it, response PII controls and real token accounting apply only to `/v1/proxy`. A block cannot undo the provider call; compressed/partial/`no-transform` bodies cannot be inspected (preventive policies fail closed on them). WebSocket middleware exists upstream and is not implemented.

## Verify locally

```bash
scripts/openshell-smoke.sh        # fixture contract smoke (no Docker, no OpenShell install)
make test-openshell-live          # real OpenShell v0.1.3 (Linux + Docker >= 28)
```

The fixture smoke runs `TestE2E_OpenShell_ComposedModelChannel`, `TestE2E_OpenShell_ComposedActionChannel` and `TestE2E_OpenShell_ResponseGovernance` (the PRE_RETURN exchange replayed: whole body held, actual usage settled under the decision's correlation id with the decision booking no cost, a response carrying an e-mail transformed before delivery, a usage-less response keeping its estimate, session cost equal to the settled actuals, offline verification). The second drives the sandbox → Action Gateway channel through the hop: allowed read executed once, forbidden action with zero dispatch, approval-required refund with a host-side reviewer and exactly one effect, exact replay, unbound/forged/tampered/re-routed identity refused with no state, the reviewer route closed through the hop, the session join of model and action records, offline lifecycle verification, and a Talon restart. The first runs `TestE2E_OpenShell_ComposedModelChannel`: a **fixture supervisor** replays the pinned v0.1.3 contract over real gRPC against the built `talon` binary, including the protocol negotiation (a legacy `Describe` without peer metadata is refused), redaction reaching a counting mock provider exactly once with the replaced bytes and the runtime's credential, model restriction and forged/foreign/missing identity → zero dispatch, an imported OCSF denial with external provenance, no secret in evidence or logs, offline verification across a restart. Everything asserted about Talon is real; OpenShell's side is the documented contract replayed. The live smoke replaces the replay with the released runtime.

Unit/contract coverage: `go test ./internal/workload ./internal/openshell ./internal/gateway ./internal/server -run 'TestJWT|TestHop|TestEvaluate|TestDescribe|TestValidateConfig|TestParseOCSF|TestContainmentRecord|TestProviderForHost|TestSelfDestination|TestWorkloadHop'`.

## Non-goals of this integration

No Landlock/seccomp/eBPF/BlueField work in Talon, no OpenShell lifecycle management, no mirroring of OpenShell policy into Talon YAML, no Talon PKI, no #149 exact-request attestation, and no claim about local actions that bypass both enforcement boundaries.

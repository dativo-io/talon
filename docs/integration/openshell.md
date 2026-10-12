# NVIDIA OpenShell — composing Talon with external agent containment

**Status:** reference integration (#482), request side complete; the fixture lane runs in every CI run and the live lane drives the **released OpenShell v0.1.3** gateway and sandbox in the `OpenShell Live` workflow, whose latest run is the source of truth for the full composition (a red run means the composition is broken, not that the lane was skipped). Two automated lanes: the fixture contract smoke (`scripts/openshell-smoke.sh`, routine CI) and the real-runtime live smoke (`scripts/openshell-live.sh` / `make test-openshell-live`, the `OpenShell Live` workflow) that drives a real v0.1.3 gateway and sandbox. Not yet implemented on this path: response-phase (`HTTP_RESPONSE/PRE_RETURN`) governance, WebSocket governance, and exact consequential-action authorization (#431/#458).

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

Talon's manifest advertises only what it implements: one binding, `HTTP_REQUEST / PRE_CREDENTIALS`, with `max_payload_bytes` and `request_timeout` from `gateway.openshell`, `expected_audience` equal to the configured verification audience (OpenShell refuses to start if it differs from the registration's `audience`), and `Extension{protocol 1.0, talon, <version>, supported=[contract], required=[contract]}`. `HTTP_RESPONSE / PRE_RETURN` and `WEBSOCKET_MESSAGE` exist in the v0.1.3 contract and are **not** advertised: Talon does not implement them yet, and a binding is a capability promise, not metadata. The manifest `name` and the registration name are diagnostics and operator identity respectively; neither is ever a Talon tenant or agent identity (`ValidateConfig` rejects any policy-local config).

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

Cost on this path is **estimate-only**: Talon does not see the provider response, so `execution.cost` is the pre-request estimate and token counts are zero. Budget enforcement works on those estimates. OpenShell v0.1.3 provides the response-phase hook (`HttpResponsePreReturn`); implementing it in Talon is the next #482 slice.

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
```

A destination host with no matching enabled provider `base_url` is denied with `destination_not_governed` (fail closed): if an OpenShell policy binds Talon to a host Talon does not govern, nothing passes as "allowed".

`allow_insecure_transport: true` serves plaintext h2c for local fixtures only. OpenShell sends **no** caller token over an insecure registration, so every real request is then denied for missing identity.

## Live lane (real OpenShell v0.1.3)

```bash
make test-openshell-live          # == scripts/openshell-live.sh
```

What it does, on one Linux host with Docker Engine ≥ 28 (GitHub-hosted `ubuntu-latest` in the `OpenShell Live` workflow, or any developer Linux box): downloads the **released** v0.1.3 `openshell` CLI and `openshell-gateway` binaries and verifies their sha256 against the release manifests on every run (the cached tarballs are re-verified, never trusted); builds `talon` and a deterministic mock OpenAI-compatible provider from the checkout; generates the gateway's Ed25519 signing bundle and Talon's middleware TLS identity in OpenShell's trust topology (an operator CA that signs Talon's server certificate; SANs: the host address and `host.openshell.internal`, EKU serverAuth; the CA, not the leaf, is `tls_ca_cert_path`); proves that `Describe` over TLS fails with an unrelated CA and succeeds with the registered one; starts Talon with the `gateway.openshell` block below; starts the real gateway (docker driver, `--disable-tls` listener, `gateway_jwt`, Talon registered over `https://<host>:<port>` with `tls_ca_cert_path`); imports a provider profile that binds `OPENAI_API_KEY` to `host.openshell.internal:<mock port>`; creates a provider with the mock key; creates a sandbox from the released image with the policy below and `--provider`; binds the **real** sandbox id in `agent.talon.yaml` (picked up by the agent reload, no restart); then issues requests with `openshell sandbox exec … curl` and asserts on the mock provider's counters and recorded bytes, OpenShell's error envelopes, and Talon's signed evidence. It refuses to start, with a clear message, when Docker, the kernel or a tool is missing; nothing is installed system-wide and no provider spend occurs.

Cases and assertions:

| Case | Sandbox request | Expected |
|---|---|---|
| A allowed | `gpt-4o-mini`, plain content | provider count 1; provider saw `Authorization: Bearer <OpenShell-injected key>`; Talon record `workload_identity.status: verified`, `upstream_auth_mode: external_runtime`, `enforcement.provenance: delegated_expected` |
| B PII | content with `jane.doe@example.com` | provider count 2; forwarded body differs from the original, never contains the e-mail, keeps the rest |
| C blocked model | `gpt-4o` | sandbox gets `403 {"error":"middleware_denied", "reason_code":"model_not_allowed"}`; count unchanged |
| D unbound identity | second sandbox with no Talon binding | `403 middleware_denied`, `reason_code: workload_identity_unbound`; count unchanged |
| E Talon down | Talon stopped | `middleware_failed` from OpenShell (`on_error: fail_closed`); count unchanged — OpenShell enforced this, not Talon |
| F Talon restart | same registration | request governed again, count 3, no gateway restart |
| evidence | — | ≥3 `delegated_expected` records with `decision_authority: talon`, `decision_returned_via: openshell_middleware`; one allowed record verifies offline; the provider key appears nowhere in Talon's data dir, serve log or export; Talon's own vault value never reaches the provider |

The run prints the OpenShell versions and checksums, the Talon commit, the Docker/kernel versions and the images used. The gateway's OCSF JSONL (`[openshell.gateway.ocsf_log]`) is kept with the logs.

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
```

The provider credential stays an OpenShell provider (profile endpoint bound to `<provider host>`), attached with `--provider`; Talon never holds it. Registration is static: changing the `[[openshell.supervisor.middleware]]` entry requires a gateway restart; restarting Talon itself does not (case F).

## Bypass model — stated honestly

- **Agent → provider directly, skipping Talon.** Prevented by **OpenShell**, not Talon: the provider host is admitted only with the Talon middleware bound to it, `tls: skip` endpoints cannot overlap a fail-closed middleware selector (OpenShell policy validation), and every other destination is default-denied. Talon can only import the resulting OCSF denial. If the OpenShell policy admits the provider host without binding Talon, traffic flows ungoverned and Talon has no record — that is an OpenShell policy error Talon cannot detect.
- **Agent → Talon's gRPC endpoint directly.** Needs a gateway-signed supervisor token; a workload never holds one and cannot mint one. A stolen token binds one sandbox and is checked against the request context.
- **Middleware unavailable.** OpenShell blocks (fail closed by default). Talon does not retry, so there is no retry amplification between the layers.
- **Host or gateway compromise.** Out of scope for both products' claims here. Talon does not claim kernel isolation, filesystem containment, or resistance to a compromised OpenShell gateway (which could mint tokens for any sandbox).
- **Response side.** OpenShell v0.1.3 provides the `HTTP_RESPONSE / PRE_RETURN` middleware (`HttpResponsePreReturn.Evaluate`), but Talon does not implement that binding yet and does not advertise it: response PII controls and real token accounting apply only to `/v1/proxy`. WebSocket middleware exists upstream too and is likewise not implemented.

## Verify locally

```bash
scripts/openshell-smoke.sh        # fixture contract smoke (no Docker, no OpenShell install)
make test-openshell-live          # real OpenShell v0.1.3 (Linux + Docker >= 28)
```

The fixture smoke runs `TestE2E_OpenShell_ComposedModelChannel`: a **fixture supervisor** replays the pinned v0.1.3 contract over real gRPC against the built `talon` binary, including the protocol negotiation (a legacy `Describe` without peer metadata is refused), redaction reaching a counting mock provider exactly once with the replaced bytes and the runtime's credential, model restriction and forged/foreign/missing identity → zero dispatch, an imported OCSF denial with external provenance, no secret in evidence or logs, offline verification across a restart. Everything asserted about Talon is real; OpenShell's side is the documented contract replayed. The live smoke replaces the replay with the released runtime.

Unit/contract coverage: `go test ./internal/workload ./internal/openshell ./internal/gateway -run 'TestJWT|TestEvaluate|TestDescribe|TestValidateConfig|TestParseOCSF|TestContainmentRecord|TestProviderForHost'`.

## Non-goals of this integration

No Landlock/seccomp/eBPF/BlueField work in Talon, no OpenShell lifecycle management, no mirroring of OpenShell policy into Talon YAML, no Talon PKI, no #149 exact-request attestation, and no claim about local actions that bypass both enforcement boundaries.

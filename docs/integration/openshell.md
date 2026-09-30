# NVIDIA OpenShell — composing Talon with external agent containment

**Status:** reference integration, first slice (#482). Shipped: the delegated model channel, verified sandbox identity, external-enforcement provenance, containment-fact import, and a deterministic fixture smoke. Not shipped: a live smoke against a running OpenShell gateway (see [Live lane](#live-lane-real-openshell-gateway)), the response-phase hook, and exact consequential-action authorization on this path.

OpenShell contains the agent runtime: filesystem, process, syscall and network sandboxing, and endpoint-bound provider credentials. Talon applies company policy to the model traffic OpenShell admits, decides what may reach a provider and in what form, and writes signed, verifiable evidence. Neither replaces the other, and neither is required by the other — Talon keeps governing ordinary apps, MCP clients, external workflows and coding agents that never run in a sandbox.

## Topology

Talon is registered with OpenShell as a **supervisor middleware** (OpenShell's supported extension point for inspecting and transforming admitted HTTP traffic). Pinned upstream contract: **OpenShell v0.1.2**, proto package `openshell.middleware.v1` (`internal/openshell/proto/v0.1.2`).

```text
agent process in sandbox
  → OpenShell network policy          (OpenShell: default deny, binary + host + port + L7 rules)
  → Talon  EvaluateHttpRequest        (Talon: identity, policy, PII, budget, tool governance → ALLOW/transform/DENY)
  → OpenShell credential injection    (OpenShell: placeholder → real provider key, endpoint-bound)
  → provider
```

Per the enforcement doctrine in #424 this is **DELEGATE**: Talon makes the decision, OpenShell's pre-execution hook enforces it. OpenShell's documented contract for that hook (v0.1.2): a middleware DENY always blocks regardless of `on_error`; an unavailable or failing middleware blocks by default (`on_error: fail_closed`); the request-phase middleware runs **before** credential injection and never sees the credential.

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
| Containment facts OpenShell enforced alone | **OpenShell enforces, Talon imports** | `talon audit import-external` over OpenShell's OCSF export, labelled `external_runtime_enforced`, `observed: false`, receipt unverified |

There are no two authorities for one decision: a Talon rule never appears in OpenShell policy and an OpenShell rule never appears in Talon YAML. The one candidate for **COMPILE** — Talon's provider allowlist into OpenShell's endpoint allowlist — was evaluated and rejected for v1: OpenShell admission is additionally keyed by calling binary, L7 rules and `enforcement: enforce|audit`, so the semantics are not equivalent and a mechanical mapping could silently widen or narrow. No static capability-delta work applies because no mapping exists.

## Identity and binding (#457)

OpenShell's supervisor authenticates to registered middleware with a short-lived gateway-signed JWT: `iss: openshell-gateway:<gateway_id>`, `aud` = the registration audience, `sub: spiffe://openshell/sandbox/<sandbox_id>`, `caller_kind: supervisor`, `sandbox_id`, `jti`, `iat/exp` (≤ 1 h). Keys are published at the gateway's `/.well-known/jwks.json`.

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
"enforcement": {"mechanism":"delegate","boundary":"external_runtime","decision_authority":"talon","provenance":"external_runtime_enforced","observed":false,
                "runtime":{"type":"openshell","id":"openshell-gateway:gw-1","policy_ref":"<openshell network_middlewares entry>","reference":"<sandbox_id>","request_id":"<openshell request id>"}}
```

Read it precisely:

- `decision_authority: talon` — Talon decided allow/deny/transform under its own compiled policy (digests in `policy_decision.policy_digests`).
- `boundary: external_runtime`, `mechanism: delegate` — the prevention point was OpenShell's hook, not Talon's proxy.
- `observed: false` — Talon returned a verdict and did **not** see OpenShell block or forward. `external_runtime_enforced` on such a record means "enforced by the runtime under its documented hook contract"; Talon's HMAC proves Talon recorded this decision, not that OpenShell honored it.
- A record with no `enforcement` object is the ordinary Talon-intercepted gateway path (`talon audit show` prints the default explicitly).

An OpenShell-only containment denial (network or HTTP class, `action: Denied`) imported with `talon audit import-external --runtime openshell --file <ocsf.jsonl>` becomes an `external_runtime_event` record (never request-class): `mechanism: verify`, `decision_authority: external_runtime`, `provenance: external_runtime_enforced`, `observed: false`, `receipt: {kind: openshell_ocsf, digest, verified: false}`, `workload_identity.status: asserted`. Talon never claims it saw the file, process or connection; it claims an operator imported OpenShell's unsigned statement that it did. Attribution uses the same sandbox binding as the live path; events for unbound sandboxes are skipped and reported.

Cost on this path is **estimate-only**: Talon does not see the provider response, so `execution.cost` is the pre-request estimate and token counts are zero. Budget enforcement works on those estimates. The response-phase hook (OpenShell `HttpResponsePreReturn`) is the next slice.

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

## Live lane (real OpenShell gateway)

> **Unverified on this repository's CI.** The steps below follow the OpenShell v0.1.2 documentation (`docs/extensibility/supervisor-middleware/*.mdx`, `docs/how-it-works/gateways/configuration.mdx`, `docs/how-it-works/policies/schema.mdx` at tag v0.1.2) and have not been executed against a live gateway here: OpenShell needs an OS package install and a Docker/Podman/Kubernetes compute driver. Treat this as a runbook to validate, not as a tested artifact.

1. Serve Talon with the `gateway.openshell` block above (TLS, JWKS URL of your OpenShell gateway). Talon must be running before the OpenShell gateway starts (it calls `Describe` at startup).
2. Register Talon statically in the OpenShell gateway config and restart the gateway:

   ```toml
   [[openshell.supervisor.middleware]]
   name = "talon"
   grpc_endpoint = "https://talon.internal:50051"
   tls_ca_cert_path = "/etc/openshell/certs/talon-ca.pem"
   audience = "urn:openshell:extension:middleware:talon"
   max_payload_bytes = 4194304
   timeout = "10s"
   ```

   `[openshell.gateway.gateway_jwt]` must be configured so the gateway mints extension tokens.
3. Attach Talon to the provider host in the sandbox policy and keep the provider credential endpoint-bound in OpenShell:

   ```yaml
   version: 1
   network_policies:
     openai:
       endpoints:
         - host: api.openai.com
           port: 443
           protocol: rest
           enforcement: enforce
       binaries:
         - path: /usr/local/bin/python3
   network_middlewares:
     talon-governance:
       middleware: talon
       order: 10
       on_error: fail_closed
       endpoints:
         include: ["api.openai.com"]
   ```
4. Create the sandbox, read its sandbox id, add the binding line to the agent file, and let the agent reload pick it up.
5. From inside the sandbox send one request with PII and one with a blocked model; then `talon audit list` / `talon audit show <id>` / `talon audit verify <id>`.
6. Ship the sandbox's OCSF export (`/var/log/openshell-ocsf-*.log` with `ocsf_json_enabled`, or `openshell logs <sandbox> --source sandbox`) to the Talon host and run `talon audit import-external`.

## Bypass model — stated honestly

- **Agent → provider directly, skipping Talon.** Prevented by **OpenShell**, not Talon: the provider host is admitted only with the Talon middleware bound to it, `tls: skip` endpoints cannot overlap a fail-closed middleware selector (OpenShell policy validation), and every other destination is default-denied. Talon can only import the resulting OCSF denial. If the OpenShell policy admits the provider host without binding Talon, traffic flows ungoverned and Talon has no record — that is an OpenShell policy error Talon cannot detect.
- **Agent → Talon's gRPC endpoint directly.** Needs a gateway-signed supervisor token; a workload never holds one and cannot mint one. A stolen token binds one sandbox and is checked against the request context.
- **Middleware unavailable.** OpenShell blocks (fail closed by default). Talon does not retry, so there is no retry amplification between the layers.
- **Host or gateway compromise.** Out of scope for both products' claims here. Talon does not claim kernel isolation, filesystem containment, or resistance to a compromised OpenShell gateway (which could mint tokens for any sandbox).
- **Response side.** Not governed on this path in this slice (no response-phase hook): response PII controls and real token accounting apply only to `/v1/proxy`.

## Verify locally

```bash
scripts/openshell-smoke.sh
```

runs `TestE2E_OpenShell_ComposedModelChannel`: a **fixture supervisor** replays the pinned v0.1.2 contract over real gRPC against the built `talon` binary (redaction reaches a counting mock provider exactly once with the replaced body and the runtime's credential; model restriction, forged/foreign/missing identity → zero dispatch; an OCSF denial is imported with external provenance; secrets never appear in evidence or logs; records verify offline and across a restart). Everything asserted about Talon is real; OpenShell's side is the documented contract replayed, not OpenShell itself.

Unit/contract coverage: `go test ./internal/workload ./internal/openshell ./internal/gateway -run 'TestJWT|TestEvaluate|TestDescribe|TestValidateConfig|TestParseOCSF|TestContainmentRecord|TestProviderForHost'`.

## Non-goals of this integration

No Landlock/seccomp/eBPF/BlueField work in Talon, no OpenShell lifecycle management, no mirroring of OpenShell policy into Talon YAML, no Talon PKI, no #149 exact-request attestation, and no claim about local actions that bypass both enforcement boundaries.

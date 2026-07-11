# Air-gapped deployment

Deploy Talon with **provable in-region operation**: no surprise outbound traffic except endpoints you explicitly declare (local Ollama or chosen EU LLM providers).

Air-gapped and EU-sovereign operation is a **trust-layer differentiator** on Talon's control plane: the same budgets, shared policy, routing, and signed evidence, deployed so that confidential data stays in-region or fully offline. Because Talon is a single self-hosted Go binary, in-region operation is provable rather than promised — teams that need evidence that AI traffic stays inside Europe get it from the same signed records. Background: issues [#111](https://github.com/dativo-io/talon/issues/111) and [#132](https://github.com/dativo-io/talon/issues/132).

## `sovereignty.mode` is the single source of truth

`sovereignty.mode` (`eu_strict` | `eu_preferred` | `global`) is the one knob that
defines your data-sovereignty posture. When set, it:

1. **Supersedes** `llm.routing.data_sovereignty_mode` — you set the mode once at the
   top level; the routing engine inherits it. A conflicting routing value is
   overridden with a warning.
2. **Excludes non-compliant providers** — under `eu_strict`, declared providers
   whose jurisdiction is not `EU`/`LOCAL` (and that do not expose an EU region,
   e.g. Bedrock `eu-central-1`) are **excluded from routing** with an ERROR log
   at startup. The process keeps running so compliant providers remain available.
   Direct gateway requests to an excluded provider receive HTTP 403 with signed
   audit evidence. This covers:
   - an enabled gateway provider in a non-EU/LOCAL region,
   - an operator-keyed provider (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`),
   - a non-sovereign entry in the `llm.providers` block.
   Non-sovereign providers that were *not* explicitly configured are filtered
   silently from the available set (Debug log) so routing cannot select them.

`eu_preferred` and `global` impose no hard provider gate (routing still applies EU
preference under `eu_preferred`).

## What air_gap mode adds

`sovereignty.deployment_mode: air_gap` is a **stricter sub-mode**. It implies
`sovereignty.mode: eu_strict` (setting a looser `mode` is rejected) and adds:

1. **Gateway egress** — applies deny-by-default egress rules allowing only `EU` and `LOCAL` regions when no custom `gateway.organization_policy.egress` block is present.
2. **Transport guard** — wraps the gateway upstream HTTP client with an allowlist derived from:
   - `ollama_base_url`
   - enabled gateway provider `base_url` values
   - optional `sovereignty.allowed_egress_hosts`
   - loopback (`localhost`, `127.0.0.1`, `::1`)
3. **Crypto hardening** — rejects startup when `TALON_SECRETS_KEY` / `TALON_SIGNING_KEY` are generated defaults (air-gap deployments must use explicit keys).

Defense in depth: excluded providers are dropped from routing and denied at the gateway (403); policy egress blocks disallowed destinations **before** forward; the transport guard catches misconfiguration or code paths that would otherwise surprise-egress.

## Quick start

1. Copy the example config:

   ```bash
   cp examples/airgap/talon.config.airgap.yaml ~/.talon/talon.config.yaml
   ```

2. Set explicit crypto keys (required for air_gap):

   ```bash
   export TALON_SECRETS_KEY="$(openssl rand -hex 32)"   # AES-256: 64 hex chars (32 bytes)
   export TALON_SIGNING_KEY="$(openssl rand -hex 32)"   # HMAC: 64 hex chars (32 bytes)
   ```

3. Store local provider credentials in the vault (even for Ollama, use a placeholder if your endpoint has no auth):

   ```bash
   talon secrets set ollama-api-key 'local-only'
   ```

4. Validate before serving:

   ```bash
   talon doctor --gateway-config ~/.talon/talon.config.yaml --skip-upstream
   ```

5. Start the gateway:

   ```bash
   talon serve --gateway --gateway-config ~/.talon/talon.config.yaml
   ```

Point your OpenAI-compatible client at `http://127.0.0.1:8080/v1/proxy/ollama/v1/...` with the agent key `talon-airgap` (from the example config).

## Configuration reference

```yaml
sovereignty:
  mode: eu_strict                   # eu_strict | eu_preferred | global (source of truth)
  deployment_mode: air_gap          # standard | air_gap (air_gap implies eu_strict)
  allowed_egress_hosts:             # optional extension to auto allowlist
    - "llm.internal.example"
```

You no longer need to mirror `llm.routing.data_sovereignty_mode` — it is derived
from `sovereignty.mode` for both the gateway and `talon run` paths. See
[configuration reference](../reference/configuration.md).

## Secrets vault rotation (air-gap hardening)

Rotate secrets on a schedule without plaintext exposure:

```bash
# Re-encrypt a single secret with a fresh nonce (audited as reason=rotate)
talon secrets rotate <secret-name>

# Verify vault access audit trail
talon secrets audit
```

Every rotation is logged in the vault audit table. Combine with explicit `TALON_SECRETS_KEY` rotation only during a planned maintenance window (re-encrypting the vault requires the current key).

## Verification

CI runs `tests/integration/airgap_test.go` which:

- wires a full gateway in `air_gap` mode;
- proves allowed LOCAL upstream traffic succeeds;
- proves a non-allowlisted host is blocked by the egress guard with **zero** upstream calls.

Run locally:

```bash
go test -race -tags=integration ./tests/integration/ -run AirGap
```

## Compliance language

Air-gap controls provide **supporting evidence for data-residency and egress discipline**. They do not, by themselves, make a deployment GDPR-, NIS2-, or EU AI Act–compliant. Use `talon compliance ropa` and the sovereignty posture report ([#133](https://github.com/dativo-io/talon/issues/133)) for auditor-facing artifacts.

## Related

- [EU routing and egress policy cookbook](policy-cookbook.md)
- [Configuration reference](../reference/configuration.md)
- Example: `examples/airgap/`

# Air-gapped deployment

Deploy Talon with **provable in-region operation**: no surprise outbound traffic except endpoints you explicitly declare (local Ollama or chosen EU LLM providers).

This guide implements [feature bet 5.3](https://github.com/dativo-io/talon/issues/111) / issue [#132](https://github.com/dativo-io/talon/issues/132). It supports EU regulated buyers who need evidence that AI traffic stays inside Europe — Talon's structural advantage as a single self-hosted Go binary.

## What air_gap mode does

When `sovereignty.deployment_mode: air_gap` is set in `talon.config.yaml`:

1. **Routing** — forces `llm.routing.data_sovereignty_mode: eu_strict` (or requires it if you set it explicitly).
2. **Gateway egress** — applies deny-by-default egress rules allowing only `EU` and `LOCAL` regions when no custom `gateway.default_policy.egress` block is present.
3. **Transport guard** — wraps the gateway upstream HTTP client with an allowlist derived from:
   - `ollama_base_url`
   - enabled gateway provider `base_url` values
   - optional `sovereignty.allowed_egress_hosts`
   - loopback (`localhost`, `127.0.0.1`, `::1`)
4. **Crypto hardening** — rejects startup when `TALON_SECRETS_KEY` / `TALON_SIGNING_KEY` are generated defaults (air-gap deployments must use explicit keys).
5. **Provider regions** — rejects gateway providers whose `region` is not `EU` or `LOCAL`.

Defense in depth: policy egress blocks disallowed destinations **before** forward; the transport guard catches misconfiguration or code paths that would otherwise surprise-egress.

## Quick start

1. Copy the example config:

   ```bash
   cp examples/airgap/talon.config.airgap.yaml ~/.talon/talon.config.yaml
   ```

2. Set explicit crypto keys (required for air_gap):

   ```bash
   export TALON_SECRETS_KEY="$(openssl rand -hex 16)"
   export TALON_SIGNING_KEY="$(openssl rand -hex 32)"
   ```

3. Store local provider credentials in the vault (even for Ollama, use a placeholder if your endpoint has no auth):

   ```bash
   talon secrets set ollama-api-key 'local-only' --tenant default --agent '*'
   ```

4. Validate before serving:

   ```bash
   talon doctor --gateway-config ~/.talon/talon.config.yaml --skip-upstream
   ```

5. Start the gateway:

   ```bash
   talon serve --gateway --gateway-config ~/.talon/talon.config.yaml
   ```

Point your OpenAI-compatible client at `http://127.0.0.1:8080/v1/proxy/ollama/v1/...` with caller bearer `talon-airgap` (from the example config).

## Configuration reference

```yaml
sovereignty:
  deployment_mode: air_gap          # standard | air_gap
  allowed_egress_hosts:             # optional extension to auto allowlist
    - "llm.internal.example"
```

Mirror `llm.routing.data_sovereignty_mode: eu_strict` in agent policies when using `talon run` — gateway and agent paths are configured separately today. See [configuration reference](../reference/configuration.md).

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

# Air-gapped deployment example (#132)

Minimal `talon.config.yaml` for a fully in-region deployment using local Ollama only.
Copy to your Talon data directory and set explicit crypto keys before `talon serve --gateway`.

```bash
export TALON_SECRETS_KEY="$(openssl rand -hex 32)"   # AES-256: 64 hex chars (32 bytes)
export TALON_SIGNING_KEY="$(openssl rand -hex 32)"   # HMAC: 64 hex chars (32 bytes)
cp talon.config.airgap.yaml ~/.talon/talon.config.yaml
talon secrets set ollama-api-key 'local-only'   # placeholder; Ollama needs no auth
talon doctor --gateway-config ~/.talon/talon.config.yaml --skip-upstream
talon serve --gateway --gateway-config ~/.talon/talon.config.yaml
```

`talon doctor` should report `0 failures` for a healthy air-gap deployment (a couple of advisory warnings are
expected: no agent policy is needed for a gateway-only deployment, an empty
`forbidden_tools` list, or excluded non-EU providers when a compliant LOCAL/EU provider also exists).

See [Air-gapped deployment guide](../../docs/guides/air-gapped-deployment.md) for the full runbook.

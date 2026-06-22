# Air-gapped deployment example (#132)

Minimal `talon.config.yaml` for a fully in-region deployment using local Ollama only.
Copy to your Talon data directory and set explicit crypto keys before `talon serve --gateway`.

```bash
export TALON_SECRETS_KEY="$(openssl rand -hex 16)"   # 32-byte hex
export TALON_SIGNING_KEY="$(openssl rand -hex 32)"   # 64-byte hex
cp talon.config.airgap.yaml ~/.talon/talon.config.yaml
talon doctor --gateway-config ~/.talon/talon.config.yaml --skip-upstream
talon serve --gateway --gateway-config ~/.talon/talon.config.yaml
```

See [Air-gapped deployment guide](../../docs/guides/air-gapped-deployment.md) for the full runbook.

# Vendor Proxy Example

Brownfield setup: route third-party support AI (e.g. Zendesk, Freshdesk) through Talon so every request is policy-checked and audited.

## Using the OpenAI-compatible endpoint

Point your vendor integration at Talon’s `/v1/chat/completions` instead of the vendor’s API:

```bash
talon serve --port 8080
# In another terminal:
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Talon-Tenant: acme" \
  -H "X-Talon-Agent: zendesk-vendor-proxy" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Help me reset my password"}]}'
```

To use this policy with `talon serve`, run from the repo root and set the default policy in `talon.config.yaml`, or run from a directory that contains a `talon.config.yaml` with `default_policy: examples/vendor-proxy/agent.talon.yaml`.

## Direct run (no proxy)

```bash
talon run --tenant acme --agent zendesk-vendor-proxy --policy examples/vendor-proxy/agent.talon.yaml \
  "Customer asked: how do I request a refund?"
```

## Validate and audit

```bash
talon validate -f examples/vendor-proxy/agent.talon.yaml
talon audit list --tenant acme --agent zendesk-vendor-proxy
```

## Notes

- Replace agent name and policy path with your proxy config when deploying.
- See `docs/VENDOR_INTEGRATION_GUIDE.md` and `docs/ARCHITECTURE_MCP_PROXY.md` for full proxy architecture.

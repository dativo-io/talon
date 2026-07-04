# Talon + Presidio scanner sidecar

Runs Talon's gateway with a stock [Microsoft Presidio](https://microsoft.github.io/presidio/)
analyzer container as the active PII scanner engine — no glue code, the
`scanner:` block points straight at the analyzer's REST API.

```bash
cd examples/scanners/presidio
docker compose up
```

Send a request containing PII through the gateway (the upstream is a mock
OpenAI provider, no API key needed):

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer talon-demo-key" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My email is jan@example.com"}]}'
```

The email is detected by Presidio, redacted to `[EMAIL]` before the request
leaves Talon, and the evidence records which engine made the call:

```bash
docker compose exec talon /usr/local/bin/talon audit list
# classification.scanner: {"engine":"presidio-demo","type":"presidio","version":"latest",...}
```

## Fail-closed behavior

External scanner failures block rather than degrade:

```bash
docker compose stop presidio-analyzer
curl ...   # → HTTP 502 {"error":{"type":"scanner_unavailable",...}}

docker compose restart talon   # → refuses to start (eager health check)
```

## Notes

- The adapter protocol has no authentication — keep the analyzer on an
  isolated network (here: the compose-internal network; no published port).
- Offsets: stock Presidio reports codepoint offsets; `type: presidio` handles
  the conversion to Talon's canonical byte offsets automatically.
- Full reference: [docs/reference/external-scanners.md](../../../docs/reference/external-scanners.md).

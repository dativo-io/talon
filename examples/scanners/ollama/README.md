# Talon + Ollama: local Llama as the PII scanner

Runs Talon's gateway with a local Llama model (via [Ollama](https://ollama.com))
as the active PII scanner engine. Detection happens entirely on your
hardware — nothing is sent to a cloud scanner.

```bash
cd examples/scanners/ollama
docker compose up          # first start pulls llama3.2:1b (~1.3 GB)
```

Send a request with PII through the gateway (mock upstream, no API key):

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer talon-demo-key" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My email is jan@example.com"}]}'
```

The model reports the email verbatim, Talon relocates it to exact byte
offsets, redacts it to `[EMAIL]`, verifies the redacted text with a second
scan, and only then forwards. Check the evidence:

```bash
docker compose exec talon /usr/local/bin/talon audit list
# classification.scanner: {"engine":"llm:llama3.2:1b","type":"llm","version":"llm-ner/v1",...}
```

## Fail-closed behavior

```bash
docker compose stop ollama
curl ...                       # → HTTP 502 scanner_unavailable
docker compose restart talon   # → refuses to start (health probe checks the model is pulled)
```

## Choosing a model

`llama3.2:1b` keeps this demo small; its recall is mediocre. For real use
prefer `llama3.1:8b` or `qwen2.5:7b` (change the model in **both**
`docker-compose.yml`'s model-pull service and `talon.config.yaml`), and read
the [local scanner engines guide](../../../docs/guides/local-scanner-engines.md)
for latency budgets, hallucination handling, and air-gapped setups.

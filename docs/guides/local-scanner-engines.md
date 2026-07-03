# Local scanner engines (Ollama / Llama cookbook)

Talon can use a local LLM as its PII scanner engine: `scanner.type: llm`
prompts any OpenAI-compatible endpoint (Ollama, llama.cpp server, vLLM) for
NER. This guide covers running it well. For the wire-level reference and
fail-closed semantics shared by all external engines, see
[external scanners](../reference/external-scanners.md); for a runnable stack,
see [`examples/scanners/ollama/`](../../examples/scanners/ollama/).

## Quick start (host Ollama)

```bash
ollama pull llama3.1:8b
```

```yaml
# talon.config.yaml
scanner:
  type: llm
  timeout: "30s"          # see latency budget below
  llm:
    model: "llama3.1:8b"
```

`scanner.endpoint` defaults to `ollama_base_url` + `/v1`
(`http://localhost:11434/v1`), so a host Ollama needs no endpoint at all.
At startup Talon queries `GET /models` and refuses to start if the model
isn't pulled.

## How detection works (and why offsets are safe)

LLMs are unreliable at reporting character positions, so Talon never asks for
them:

1. A fixed, versioned prompt (`llm-ner/v1`, recorded in evidence as the
   engine version) lists the entity types derived from your effective policy
   (`enabled_entities`/`disabled_entities`/custom recognizers) and demands
   `{"entities":[{"type","value"}]}` with **verbatim** values.
2. Talon finds every occurrence of each value in the original text itself —
   byte-exact, deterministic, Unicode-safe.
3. Values that don't appear verbatim are **dropped as hallucinations**
   (counted in `talon.scanner.llm.hallucinations.total`). Placeholder-shaped
   values (`[EMAIL]`, `<PII .../>`) are ignored so re-scanning redacted text
   doesn't false-block.
4. A non-JSON reply, timeout, or transport error is an engine failure —
   fail-closed on every enforcement path, never "no PII found".

The prompt is intentionally not operator-customizable: evidence semantics
stay attributable to a known prompt version. If you need custom detection
semantics, put your own engine behind the generic Presidio-compatible
adapter (`scanner.type: http`) instead.

## Latency budget

Every gated data movement costs at least one model call; redact paths cost
**two** (scan + verify re-scan of the redacted text). With response scanning
enabled, one gateway round trip can mean up to four model calls. Rough
guidance:

| Setup | Typical scan | Suggested `scanner.timeout` |
|-------|--------------|------------------------------|
| 7–8B model, Apple Silicon / modern GPU | 0.5–3 s | `30s` |
| 7–8B model, CPU-only server | 3–20 s | `60s` |
| 1B model (demo), CPU | 1–5 s | `60s` (cold starts) |

Raise the gateway `request_timeout` accordingly — it must cover request scan
+ upstream call + response scan + verify. There are no retries by design; a
scan that misses its deadline blocks (enforce) or logs (shadow/warn).

## Model choice

- **Recall beats size-efficiency here**: a missed entity is a PII leak.
  `llama3.1:8b` and `qwen2.5:7b` are solid defaults; `llama3.2:1b` is
  demo-grade only.
- Models that support JSON mode (`response_format: json_object` — Ollama
  does) are markedly more reliable; Talon requests it and also tolerates
  code fences.
- Watch two metrics while evaluating: `talon.scanner.llm.hallucinations.total`
  (model inventing values) and residual-PII blocks after redaction (model
  missing entities on the verify pass — these fail closed, so they surface
  as blocked egress, not leaks).

## Verifying your setup

The smoke suite has a dedicated section for the llm engine
(`tests/smoke_sections/36_external_scanner.sh`): by default it runs against a
hermetic llama stand-in (same Ollama wire protocol), covering fail-closed
startup, end-to-end redaction, evidence attribution, and mid-flight engine
loss. Point it at your real Ollama to validate an actual llama model:

```bash
TALON_SMOKE_OLLAMA_URL=http://localhost:11434 \
TALON_SMOKE_OLLAMA_MODEL=llama3.1:8b \
make test-smoke
```

(The real-model scenario asserts pipeline health and evidence attribution,
not recall — recall is model-dependent, which is exactly why the hermetic
scenario exists.)

## Shadow-mode rollout

Test recall without blocking traffic: set the gateway to `mode: shadow` and
watch evidence for `scanner_unavailable` shadow violations and detection
quality, then switch to enforce.

## Air-gapped deployments

`scanner.type: llm` composes with `sovereignty.deployment_mode: air_gap`:
the endpoint must be provably local (loopback, private IP, or a unix socket
in front of the runtime), and the adapter transport is wrapped with the same
egress allowlist as the gateway upstream. A fully local Talon + Ollama stack
keeps detection, redaction, and evidence on your hardware end to end.

## Hybrid pattern: regex floor + LLM engine

Talon runs exactly one engine (no merge semantics). If you want the built-in
validated recognizers (IBAN checksums, Luhn, BSN…) *and* model-based
detection of names/addresses, run Presidio with custom recognizers or your
own engine behind `scanner.type: http` and do the merging inside your
engine, where you own the semantics.

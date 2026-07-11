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

## End-user test drive (host binary, real provider)

Full manual walkthrough on a single host: Talon binary + host Ollama as the
scanner + a real OpenAI upstream. Everything is observable with curl and
`talon audit`.

```bash
# --- 1. Environment (adjust paths; generate real keys once) ---
export PATH="$HOME/talon/bin:$PATH"
export TALON_SECRETS_KEY=$(openssl rand -hex 32)
export TALON_SIGNING_KEY=$(openssl rand -hex 32)
export TALON_ADMIN_KEY=$(openssl rand -hex 32)
# ABSOLUTE path, exported in EVERY shell that runs talon (serve, curl checks,
# audit export). A relative $PWD here silently splits your evidence across
# directories; a shell without it reads an empty store and jq shows nulls.
export TALON_DATA_DIR="$HOME/talon-scanner-drive/.talon"

# --- 2. The scanner engine: host Ollama with a llama model ---
# SIZE THE MODEL TO THE HOST: an 8B model needs ~8 GB free RAM. On small
# hosts (e.g. 4 GB VPS) use llama3.2:1b — a pulled-but-unloadable model
# fails the startup warm-up probe with an actionable error.
ollama pull llama3.1:8b                     # >= 8 GB RAM hosts
# ollama pull llama3.2:1b                   # small hosts / quick spin

# --- 3. Project scaffold + provider credential in the vault ---
mkdir -p "$HOME/talon-scanner-drive" && cd "$HOME/talon-scanner-drive"
talon init --scaffold --name scanner-drive
talon secrets set openai-api-key "sk-proj-..."   # real key; vault-encrypted

# --- 4. Configure the llm scanner + gateway (talon.config.yaml) ---
cat >> talon.config.yaml <<'CFG'

scanner:
  type: llm
  timeout: "60s"          # endpoint defaults to ollama_base_url + /v1
  llm:
    model: "llama3.1:8b"

gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "enforce"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    default_pii_action: "redact"
CFG

# Agent identity (#266): the scaffolded agent.talon.yaml binds me-talon-key
talon secrets set me-talon-key "talon-drive-key"

# --- 5. Serve (startup health-probes Ollama and the model; fail-closed) ---
talon serve --port 8080 --gateway --gateway-config talon.config.yaml
# log line to look for:
#   external PII scanner engine active ... engine=llm:llama3.1:8b
```

In a second terminal, send PII through and inspect what actually happened:

```bash
curl -s -X POST http://127.0.0.1:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer talon-drive-key" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Email jan.kowalski@example.com about IBAN DE89370400440532013000"}]}'

# The upstream model answers about [EMAIL] / [IBAN] — it never saw the raw
# values. Evidence attributes the engine and the versioned prompt
# (same TALON_DATA_DIR must be exported in this shell; sanity-check with
#  jq '.export_metadata.total_records' — 0 means you are reading the wrong store):
talon audit export --format json --from 2020-01-01 --to 2099-12-31 \
  | jq '.records[-1] | {allowed, scanner_engine, scanner_type, scanner_version, pii_detected, input_tier}'
# -> "scanner_engine": "llm:llama3.1:8b", "scanner_version": "llm-ner/v1", ...
# (the export is an envelope: metadata + .records[])
```

Fail-closed, observed as an end user:

```bash
# Kill the engine mid-flight: requests block, they don't degrade.
pkill ollama
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer talon-drive-key" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# -> 502 (scanner_unavailable); the denial is in `talon audit export` with
#    scanner_failure set to the typed kind (e.g. "transport").

# Restarting talon while the engine is down refuses to start:
talon serve --port 8080 --gateway --gateway-config talon.config.yaml
# -> "external scanner ... unreachable ...; Talon refuses to start (fail-closed)"
```

To drive a **Presidio** engine instead, swap step 2 and the scanner block:

```bash
docker run -d --name presidio -p 127.0.0.1:5002:3000 mcr.microsoft.com/presidio-analyzer:latest
```

```yaml
scanner:
  type: presidio
  endpoint: "http://127.0.0.1:5002"
  name: "presidio-drive"
  engine_version: "latest"
```

Same curl, same audit checks — `scanner_engine` becomes `presidio-drive`,
and `docker stop presidio` gives you the same 502/startup-refusal behavior.

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

Two levers for constrained hosts (small VPS class):

- **Narrow the prompt**: `scanner.entities: ["EMAIL_ADDRESS", "IBAN_CODE", …]`
  replaces the full policy-derived entity list in the NER prompt. Prompt
  evaluation dominates CPU scan latency, so hunting 4 types instead of ~30
  cuts every call substantially. (Only the listed types are detected —
  scope it to what your policy actually governs.)
- **Budget honestly**: on a 2-vCPU host expect 15–30 s per call; with
  request scan + redact + verify + response scan that is 4+ sequential
  calls per PII request. Set `scanner.timeout: "180s"` rather than letting
  a borderline call fail closed, or set
  `gateway.organization_policy.response_pii_action: "allow"` to skip
  response-side scanning where the demo/use-case doesn't need it.

## Model choice

- **Recall beats size-efficiency here**: a missed entity is a PII leak.
  `llama3.1:8b` and `qwen2.5:7b` are solid defaults. Field-tested floor for
  small (4 GB) hosts: `llama3.2:3b` with `scanner.entities` narrowed to
  pattern-like types (email/IBAN/phone) — it detects bare, keyword-less
  values that `llama3.2:1b` misses. `llama3.2:1b` is demo-grade only: it
  misses unlabeled values and emits erratic reply shapes.
- **Scope out fuzzy classes on small models**: PERSON/LOCATION are noisy in
  both directions below ~7B — over-redacting inputs (a country name as
  [PERSON]) and residual-blocking outputs (template tokens like
  "[Recipient's Name]" flagged as persons). Prefer pattern-like entity types
  in `scanner.entities` unless the model has the headroom.
- **Size the model to the host's RAM** (~1 GB per billion parameters at
  Q4 quantization, plus headroom): an 8B model on a 4 GB machine is
  *listed* by Ollama but cannot load. Talon's startup probe warms the
  model up with a real completion, so this misconfiguration fails at
  `talon serve` with an actionable error rather than fail-closed-blocking
  every request at runtime. The warm-up also absorbs the cold-load
  latency before the first real scan.
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

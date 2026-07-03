# External scanner engines

Talon's PII scanning runs on a pluggable engine seam. The built-in regex
scanner is the zero-config default; operators can replace it with an
out-of-process engine — a [Microsoft Presidio](https://microsoft.github.io/presidio/)
analyzer sidecar, a custom detector speaking the same wire format, or a local
LLM prompted for NER — without changing gateway, MCP, agent, evidence, or
redaction paths.

Design invariants, regardless of engine:

- **Core stays deterministic.** Talon owns policy, evidence, enrichment,
  redaction, and the final egress decision. The engine only reports entities.
- **Adapter output is untrusted input.** Every response is validated and
  bounded; a single invalid entity (bad offsets, score, or substring
  mismatch) rejects the entire scan.
- **Byte offsets are canonical.** Engines may report rune/codepoint offsets;
  Talon converts at the boundary and verifies against the original text.
- **Fail closed.** When the scan gates egress (block/redact actions, egress
  verification), an engine timeout or error blocks the data movement. It is
  never treated as "no PII found".
- **One engine per instance.** The configured engine replaces the built-in
  scanner everywhere; results are never merged across engines.

## Configuration

The engine is selected in the operator config (`talon.config.yaml`), not in
agent policy — see the [configuration reference](configuration.md#scanner-block-external-pii-engines)
for every field:

```yaml
scanner:
  type: presidio                    # regex | presidio | http | llm
  endpoint: "http://localhost:5002" # or unix:///var/run/presidio/analyzer.sock
  timeout: "10s"
  min_score: 0.5
  name: "presidio-prod"             # detector identity in evidence
  engine_version: "2.2.354"         # recorded in evidence
```

At startup Talon probes the engine (`GET /health`, falling back to a minimal
`/analyze` call) and **refuses to start** if it is unreachable. Disable with
`health_check: false` (the first scan then fails closed instead).

## Wire protocol (presidio / http types)

The adapter speaks the Presidio analyzer REST protocol, so a stock
`mcr.microsoft.com/presidio-analyzer` container works with zero glue.

Request — `POST {endpoint}/analyze`:

```json
{"text": "…content…", "language": "en", "score_threshold": 0.5}
```

(`entities` is included when `scanner.entities` is configured.)

Response — `200` with a JSON array of recognizer results:

```json
[
  {
    "entity_type": "EMAIL_ADDRESS",
    "start": 24,
    "end": 40,
    "score": 1.0,
    "analysis_explanation": null,
    "recognition_metadata": {"recognizer_name": "EmailRecognizer"}
  }
]
```

### Offsets

Stock Presidio reports **codepoint (rune) offsets** (Python string indices)
and no encoding marker; Talon's canonical offsets are **bytes**. The adapter
resolves this per engine type:

- `type: presidio` — results default to `rune` encoding and are converted.
- `type: http` — results default to `byte` encoding (for byte-native custom
  engines).
- Either default can be overridden globally with `scanner.offset_encoding`,
  or per result with an `offset_encoding` field (`"byte"` or `"rune"`) in the
  response — useful for custom engines that mix sources.

Conversion validates span bounds and Unicode combining-sequence boundaries;
an offset that does not map cleanly rejects the whole response.

### Entity types

Well-known Presidio entity labels map to Talon's canonical types
(`EMAIL_ADDRESS` → `email`, `CREDIT_CARD` → `credit_card`, `NL_BSN` →
`national_id`, …). Unknown labels **pass through** as `lower_snake` (e.g.
`INTERNAL_PROJECT_CODE` → `internal_project_code`) so policies can match
custom detectors without code changes.

Sensitivity (and therefore tiering) is resolved in this order:

1. An explicit `expected_sensitivity` (1–3) on the wire result always wins.
2. Otherwise, **known built-in labels get their registry sensitivity
   automatically** — a stock Presidio `IBAN_CODE`, `PASSPORT`, or
   `CREDIT_CARD` detection tiers as 2 with no Talon-specific fields.
3. Unknown custom entity types default to sensitivity 1 (tier 1); supply
   `expected_sensitivity` per result if a custom detector's findings should
   tier higher.

## Failure semantics

Every failure is classified (`timeout`, `transport`, `status`, `decode`,
`validation`) and recorded in evidence and metrics — never the raw response,
which is untrusted. There are **no retries**; tune `scanner.timeout` instead.

| Path | On engine failure |
|------|-------------------|
| Gateway request scan (enforce) | HTTP 502, `scanner_unavailable` error body, request never reaches the provider |
| Gateway request scan (shadow) | Forwarded; a `scanner_unavailable` shadow violation is recorded |
| Gateway response scan, action `block`/`redact` | HTTP 502 with a `scanner_unavailable` error body — never the upstream 200 |
| Gateway response scan, action `warn` | Forwarded with a logged warning (warn never gates) |
| Request/response redaction | Blocked — content known to contain PII is never forwarded unredacted |
| Egress verification (post-redaction re-scan) | Blocked — an egress that cannot be verified does not proceed |
| MCP tool arguments / results | JSON-RPC error, call blocked |
| Agent run input/output scan | Run terminated (`scanner_unavailable` evidence) |
| Attachment scan | Attachment treated as PII-bearing; policy block/strip applies |
| Semantic cache | Unverifiable cache hits are bypassed; unscannable responses are not cached |
| Memory / CoPaw memory writes | Write denied |
| Evidence text sanitization | Text withheld (`[content withheld: PII scanner unavailable]`) |

## Evidence and observability

Every blocked outcome is a real denial end to end: gateway HTTP paths return
a non-200 error body (451 for PII policy blocks, 502 for scanner failures —
never the upstream 200), while MCP paths return a JSON-RPC error object (over
HTTP 200, per JSON-RPC convention). In both cases evidence records
`policy_decision.allowed=false` with a machine reason (`output_pii_blocked`,
`output_residual_pii_after_redaction`, `output_scanner_unavailable`, …), and
metrics count the request as blocked. Shadow mode inverts this consistently:
nothing is blocked or mutated, and the would-be enforcement is recorded as a
shadow violation.

Each evidence record carries `classification.scanner` — engine identity,
type, declared version, scan duration, and on scanner-driven blocks the
**typed failure kind** (`timeout`, `transport`, `status`, `decode`,
`validation`; `scanner_unavailable` only for engines outside the adapter
error model) — see [spec v1.4](evidence-integrity-spec.md). `output_tier`
reflects the scanned response content itself, so a clean prompt whose
response leaked an IBAN records `input_tier: 0, output_tier: 2`. Raw PII
text and raw engine errors are never stored.

OTel: spans `scanner.adapter.analyze` / `scanner.adapter.health`; metrics
`talon.scanner.requests.total{engine,outcome}`, `talon.scanner.latency{engine}`,
`talon.scanner.failures.total{engine,kind}`.

`talon audit export` surfaces the same attribution as flat fields on every
record: `scanner_engine`, `scanner_type`, `scanner_version`, and
`scanner_failure`.

## Test coverage

- **Unit/integration (mocks, every CI run)**: adapter offset/failure-kind
  suites, gateway/MCP/agent fail-closed integration tests, and response
  fuzzing — wired into `make proof-gates`.
- **Smoke (black-box, real binary)**: `tests/smoke_sections/36_external_scanner.sh`
  runs `talon serve` with `scanner.type: llm` against a hermetic **llama
  stand-in** speaking the exact Ollama wire protocol (`/v1/models` +
  `/v1/chat/completions`): startup refusal against a dead engine, PII
  detection + redaction before the upstream provider sees the prompt,
  evidence attribution (`llm:<model>`, `llm-ner/v1`), and a mid-flight
  engine kill blocking 502 with denial evidence. Set `TALON_SMOKE_OLLAMA_URL`
  (and optionally `TALON_SMOKE_OLLAMA_MODEL`, default `llama3.2:1b`) to also
  run the scenario against a **real Ollama llama model**.
- **Nightly**: the `scanner-ollama-smoke` GitHub workflow exercises the llm
  adapter against real Ollama with `llama3.2:1b`.

## Deployment patterns

### Presidio sidecar (docker compose)

See [`examples/scanners/presidio/`](../../examples/scanners/presidio/) for a
runnable compose file. Minimal shape:

```yaml
services:
  presidio-analyzer:
    image: mcr.microsoft.com/presidio-analyzer:latest
    ports: ["127.0.0.1:5002:3000"]
  talon:
    image: dativo/talon:latest
    volumes: ["./talon.config.yaml:/app/talon.config.yaml:ro"]
```

### Unix domain socket (air-gapped / same-host)

For engines managed alongside Talon (systemd, docker with a shared volume),
skip TCP entirely:

```yaml
scanner:
  type: http
  endpoint: "unix:///var/run/scanner/analyzer.sock"
```

The engine listens on the socket and speaks the same JSON protocol. This is
the recommended shape under `deployment_mode: air_gap`.

### Sovereignty / air-gap rules

Under `sovereignty.deployment_mode: air_gap`, `scanner.endpoint` must be
provably local: a unix socket, loopback, or a private (RFC1918/ULA/link-local)
IP literal. DNS hostnames other than `localhost` are rejected — they cannot
be proven local at startup. The adapter's HTTP transport is additionally
wrapped with the same egress-guard allowlist as the gateway upstream.

### Security note

The adapter protocol carries **no authentication** in this iteration. Run the
engine on localhost, a unix socket, or an isolated network segment. Every
scanned text — prompts, responses, tool arguments, attachments — is sent to
the engine, so its deployment must meet the same data-handling bar as Talon
itself.

## Limitations

- Semantic enrichment (`semantic_enrichment` policy) is a built-in-engine
  feature; with an external engine it is skipped and legacy `[TYPE]`
  placeholders are used.
- Redact-and-verify paths make two engine calls per egress (scan + re-scan of
  the redacted text). Budget latency accordingly for slow engines.

## The llm engine (local models)

`scanner.type: llm` prompts any OpenAI-compatible endpoint (Ollama,
llama.cpp server, vLLM) for NER with a fixed, versioned prompt
(`llm-ner/v1`, recorded in evidence). The model returns entity type +
verbatim value only; Talon relocates every occurrence to byte offsets
itself, drops values not found verbatim (hallucination guard), and ignores
placeholder-shaped values so verify re-scans of redacted text don't
false-block. The entity set is derived from the effective policy. See the
[local scanner engines guide](../guides/local-scanner-engines.md) and
[`examples/scanners/ollama/`](../../examples/scanners/ollama/).

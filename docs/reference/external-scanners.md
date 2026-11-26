# External scanner engines

Talon's PII scanning runs on a pluggable engine seam. The built-in regex
scanner is the zero-config default; operators can replace it with an
out-of-process engine — a [Microsoft Presidio](https://microsoft.github.io/presidio/)
analyzer sidecar, a custom detector speaking the same wire format, or a local
LLM prompted for NER — without changing gateway, MCP, agent, evidence, or
redaction paths.

Design invariants, regardless of engine:

- **Core stays deterministic.** Talon owns policy, evidence, redaction
  and the final egress decision. The external engine only reports entities;
  built-in semantic enrichment is not available with external engines.
- **Adapter output is untrusted input.** The HTTP adapter bounds the
  response size, decodes it, filters results by confidence and validates
  the retained results before canonicalization. See the validation
  limitations below.
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
  language: en                     # forwarded in each /analyze request
  min_score: 0.5
  name: "presidio-prod"             # detector identity in evidence
  engine_version: "2.2.354"         # operator-declared, recorded in evidence
```

At startup Talon probes the engine (`GET /health`, falling back to a minimal
`/analyze` call only on HTTP 404 or 405) and **refuses to start** if the
probe fails. Disable with `health_check: false` (a subsequent failed scan
then blocks when it gates egress).

## Wire protocol (presidio / http types)

### Implementing a compatible scanner

A third-party detector can integrate through configuration alone if it
implements the subset of the [Presidio Analyzer REST API](https://microsoft.github.io/presidio/analyzer/)
used by Talon. Full Presidio behavioral parity, anonymization endpoints,
Talon-specific SDKs, and a scanner-specific Talon adapter are not required.
The detector returns spans over the original text; Talon performs redaction
and policy enforcement. See also the [compatibility matrix](presidio-compatibility-matrix.md).

**Required: `POST {endpoint}/analyze`**, with a JSON request and an HTTP 200
JSON array response on successful inference.

Example request:

```json
{
  "text": "My name is John Smith",
  "language": "en",
  "score_threshold": 0.5
}
```

| Request field | Meaning |
|---|---|
| `text` | Original text to scan, without normalization or masking that changes offsets. |
| `language` | Instance-configured language (default `en`); Talon does not automatically select a language per request. |
| `score_threshold` | Configured minimum score (default 0.5); Talon also filters returned results below this threshold. |
| `entities` | Optional array of requested entity labels, sent when `scanner.entities` is configured. |

Honor the requested language, threshold and entity filter where supported.
Document automatic language detection, supported labels and any limitations.
Return a non-200 response when a request cannot be scanned (including
unsupported required options), not a successful empty result.

Example response (the score is illustrative):

```json
[
  {
    "entity_type": "PERSON",
    "start": 11,
    "end": 21,
    "score": 0.95
  }
]
```

| Response field | Required | Meaning |
|---|---|---|
| `entity_type` | Yes | Presidio-style label; see entity mapping below. |
| `start` | Yes | Zero-based, inclusive start in the declared offset encoding. |
| `end` | Yes | Exclusive end in the same encoding; must identify a nonempty span of the original text. |
| `score` | Yes | Numeric score in [0, 1]; document its semantics, including any fixed-score detector behavior. |
| `offset_encoding` | No | `rune` or `byte`; overrides the configured default for this result. |
| `recognition_metadata`, `analysis_explanation` | No | Optional metadata objects; omit unless needed and avoid including sensitive text. |
| `expected_substring` | No | If provided, Talon checks the extracted original substring against this value. Prefer omitting it in production to avoid duplicating sensitive text. |

Return `[]` only when scanning succeeded and no matching entities were
found. Do not return `null`, an object envelope, or an empty success response
on failure. Return a non-200 status on inference errors, and do not log
raw request content or echo it in errors. A correct API shape does not
guarantee detection quality or complete policy coverage.

**Optional: `GET {endpoint}/health`**. Return HTTP 200 only when the model
is ready to scan; the response body is not inspected. If the endpoint is
absent, return 404 or 405 and Talon will probe `/analyze` instead. Other
status codes and transport errors fail the startup probe.

For a custom engine returning Unicode codepoint offsets, configure
`scanner.type: presidio` or set `scanner.offset_encoding: rune` explicitly
with `scanner.type: http`. Both use the same HTTP wire contract.

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

For retained results, normalization checks span bounds and, for rune
offsets, rejects boundaries splitting Unicode combining sequences. If
`expected_substring` is supplied, it also checks the extracted substring.
Use nonempty spans aligned to UTF-8 character boundaries in either mode;
do not assume the current adapter checks every such condition.

### Entity types

Well-known Presidio entity labels map to Talon's canonical types
(`EMAIL_ADDRESS` → `email`, `CREDIT_CARD` → `credit_card`, `NL_BSN` →
`national_id`, …). Unknown labels **pass through** as `lower_snake` (e.g.
`INTERNAL_PROJECT_CODE` → `internal_project_code`) so policies can match
custom detectors without code changes. Use the standard labels (for example,
`PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `LOCATION`) where their meaning
matches. Custom labels such as `ADDRESS` normalize to `address`, not
`location`; verify the effective policy and tiering before use.

Sensitivity (and therefore tiering) is resolved in this order:

1. An explicit `expected_sensitivity` (1–3) on the wire result always wins.
2. Otherwise, **known built-in labels get their registry sensitivity
   automatically** — a stock Presidio `IBAN_CODE`, `PASSPORT`, or
   `CREDIT_CARD` detection tiers as 2 with no Talon-specific fields.
3. Unknown custom entity types default to sensitivity 1 (tier 1); supply
   `expected_sensitivity` per result if a custom detector's findings should
   tier higher.

### Compatibility checklist

Before publishing support for a new engine, test against a pinned Talon
release and pinned scanner/model version using synthetic or approved data:

- [ ] Health readiness, successful detection, and a genuinely empty result.
- [ ] Requested entity filters, confidence thresholds and language behavior.
- [ ] Correct spans over original text, including accents, combining marks,
  CJK, emoji and multiple occurrences; verify redaction and residual scans.
- [ ] Detection precision/recall by entity type and language, including all
  identifiers required by the effective policy. An external engine replaces
  the built-in scanner; compare coverage rather than assuming equivalence.
- [ ] Timeout, unavailable scanner, non-200 response and malformed result;
  verify that gating requests do not reach the upstream provider and that
  denial evidence is independently verifiable.
- [ ] Local deployment and data-handling review; record latency, resource
  use, version, supported entity types and known detection gaps.

Use [the existing Presidio sidecar example](../../examples/scanners/presidio/)
as a deployment reference and [adapter tests](../../internal/classifier/adapter/adapter_test.go)
as protocol test references. Do not claim compatibility until the actual
engine has passed the relevant end-to-end tests.

## Failure semantics

Every failure is classified (`timeout`, `transport`, `status`, `decode`,
`validation`) and recorded in evidence and metrics — never the raw response,
which is untrusted. There are **no retries**; tune `scanner.timeout` instead.

| Path | On engine failure |
|------|-------------------|
| Gateway request scan | HTTP 502, `scanner_unavailable` error body, request never reaches the provider |
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
metrics count the request as blocked. There is no observe-and-forward
posture (#442): a scanner outcome that gates under the declared rule action
gates every time.

Each evidence record carries `classification.scanner` — engine identity,
type, operator-declared version (not independently attested), scan duration,
and on scanner-driven blocks the
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

- The current HTTP adapter filters results below `scanner.min_score` before
  validating retained entities. It does not validate every discarded result.
- The current JSON decoder can accept a top-level `null` as an empty slice;
  absent numeric fields can decode to zero values. These are implementation
  limitations, not valid successful scanner responses. The contract requires
  a JSON array and all four required fields per result. A detected scanner
  failure is fail-closed on gating paths; a missed or silently discarded
  detection is not necessarily distinguishable from a clean scan.
- A single scanner and configured language apply instance-wide. Detection
  coverage, including structured identifiers, is the external engine's
  responsibility; there is no built-in regex merge or fallback.
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

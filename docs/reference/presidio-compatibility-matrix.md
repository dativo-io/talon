# Presidio Compatibility Matrix

This reference defines Talon's scanner compatibility boundary for Epic #112.

Talon is Presidio-compatible at the **external result shape** boundary. Internal runtime processing remains canonical (`CanonicalEntity` / `PIIEntity`) and byte-offset based.

## Scope boundary

- **In scope (#112):** Presidio-shaped result contract, normalization, fixtures, and scanner seam.
- **Out of scope (#112):** production external runtime adapter selection, HTTP/gRPC adapter clients, Llama/ONNX runtime wiring, sidecar lifecycle (tracked in #181).
- **No parity claim:** Talon does not claim full behavioral parity with Presidio recognizer internals.

## Required external fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `entity_type` | string | yes | Presidio-style entity identifier |
| `start` | int | yes | Start offset in declared encoding |
| `end` | int | yes | End offset in declared encoding |
| `score` | float | yes | Confidence in `[0,1]` |

## Optional external fields

| Field | Purpose |
|---|---|
| `offset_encoding` | Declares `byte` or `rune` at boundary |
| `explanation` | Human/debug explanation text |
| `recognition_metadata` | Detector metadata map |
| `analysis_explanation` | Additional analysis metadata |
| `detector_metadata` | Detector identity/context |
| `provider_metadata` | Upstream/provider context |
| `expected_substring` | Guard rail for fixture/normalization checks |

## Mapping to canonical Talon model

| External (Presidio shape) | Canonical Talon field | Rule |
|---|---|---|
| `entity_type` | `Type` | mapped via entity type table (`entityToType`) |
| `start` / `end` | `Start` / `End` | canonicalized to byte offsets |
| `score` | `Confidence` | preserved as confidence score |
| metadata fields | `Attributes` | normalized to deterministic key/value attributes |
| optional field attribution | `FieldPath` | preserved for targeted JSON/tool path attribution |

## Offset normalization rules

Byte offsets are canonical for enforcement and redaction.

- Rune offsets are accepted only at this boundary and converted before canonicalization.
- Enforcement never uses rune offsets.
- Normalization fails fast for invalid spans:
  - `start < 0`
  - `end > len(text)`
  - `start > end`
  - Rune spans splitting combining sequences
  - Offset range mismatch with expected substring (when provided)

## Verification pointers

- Implementation: `internal/classifier/presidio/types.go`, `internal/classifier/presidio/normalize.go`
- Tests: `internal/classifier/presidio/normalize_test.go`, `internal/classifier/offset_test.go`
- Scanner seam: `internal/classifier/facade.go`

## Proof gates and regression bar

Epic #112 closure is enforced by reproducible proof gates:

- `make proof-gates`
  - recognizer matrix coverage
  - normalization parity checks
  - egress residual fail-closed tests (gateway/MCP/agent)
  - fuzz sanity runs
  - benchmark regression check

`BenchmarkPIIScan` regression is bounded to **<=10%** over the checked-in
baseline artifact:

- Baseline artifact: `testdata/benchmarks/pii_scan_baseline.json`
- Gate script: `scripts/check-pii-benchmark-regression.sh`


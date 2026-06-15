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
platform baseline artifact:

- Baseline artifacts: `testdata/benchmarks/pii_scan_baseline.<goos>.<goarch>.json`
  (for example `pii_scan_baseline.linux.amd64.json`, `pii_scan_baseline.darwin.arm64.json`)
- Gate script: `scripts/check-pii-benchmark-regression.sh`
- Regenerate for your host: `make benchmark-baseline-update`
- Skip benchmark gate only when no baseline exists for your platform:
  `SKIP_BENCHMARK_REGRESSION=1 make proof-gates`

## CI enforcement

Baseline artifacts under `testdata/benchmarks/` are enforced in GitHub Actions
([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)):

| Trigger | Job / step | Command |
|---------|------------|---------|
| Every PR and push | `test` → validate baselines | `jq` schema check on `pii_scan_baseline.*.json` |
| Every PR and push | `test` → benchmark regression | `make benchmark-regression` (uses `linux.amd64` on `ubuntu-latest`) |
| Push to `main`, nightly (03:00 UTC) | `proof-gates` | `make proof-gates` (matrix, egress, fuzz, benchmark) |

The `darwin.arm64` baseline is for **local macOS development only**; CI does not
run a macOS runner.

### CI maintenance

If `make benchmark-regression` fails on `ubuntu-latest` after an intentional PII
scanner change, regenerate the Linux baseline on a Linux host (or in CI) and commit:

```bash
make benchmark-baseline-update
git add testdata/benchmarks/pii_scan_baseline.linux.amd64.json
```

Update the baseline only when the median shift is expected (>10% slower than the
checked-in value). Do not loosen the threshold to silence failures.

For informational multi-benchmark tables (gateway + evidence + PII), see
[Reproducible benchmarks](./benchmarks.md) (`make benchmarks`). That output is
not a CI gate; regression enforcement uses `BenchmarkPIIScan` only.


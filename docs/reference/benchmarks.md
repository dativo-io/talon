# Reproducible Benchmarks

**Status:** stable · **Scope:** gateway pipeline overhead, PII scan latency, evidence write throughput.

The README states that pipeline overhead is typically **under 15 ms excluding upstream
latency**. This document defines how to reproduce the micro-benchmarks behind that claim,
what each number measures, and what is intentionally out of scope.

The authoritative numbers for a given machine are whatever `make benchmarks` prints
when you run it locally. Results vary with CPU, Go version, SQLite build, and load;
do not treat a single snapshot as a SLA.

## Quick start

```bash
make benchmarks
```

Or with a saved snapshot file:

```bash
scripts/run-benchmarks.sh -o /tmp/talon-benchmarks.md
```

Requirements: Go 1.22+ (project pins 1.25.x in CI), CGO enabled (SQLite), repo root checkout.

## What we measure

| Metric | Go benchmark | Package | What it includes |
|--------|--------------|---------|------------------|
| **Gateway pipeline overhead** | `BenchmarkGatewayPipelineOverhead` | `internal/gateway` | One non-streaming `ServeHTTP` round trip: route, caller auth, request extract, PII scan, OPA policy evaluation, forward to a **local** `httptest` mock upstream, response PII scan, signed evidence write, metrics. Representative payload includes EU email + IBAN patterns. |
| **Gateway overhead — large Anthropic prompt** (informational) | `BenchmarkGatewayPipelineOverheadLargePrompt` | `internal/gateway` | Same non-streaming `ServeHTTP` round trip through the Anthropic wire format (`/v1/messages`), with a deterministic ~50KB system prompt built from a repeated fixed sentence containing a corpus email — exercises the PII scanner at large-prompt scale. |
| **PII scan latency** | `BenchmarkPIIScan` | `internal/classifier` | One `Scanner.Scan` on fixed text (email, IBAN, card). Isolates classifier cost without HTTP or SQLite. |
| **Evidence write throughput** | `BenchmarkEvidenceStore` | `internal/evidence` | One `Generator.Generate` (HMAC-signed SQLite insert) per iteration. Isolates evidence path without gateway HTTP. |

> **Note:** `BenchmarkGatewayPipelineOverheadLargePrompt` is **informational**. It tracks
> large-prompt scaling on the Anthropic path (its numbers are expected to sit well above
> the 15 ms small-payload budget because the PII scan cost scales with input size) and
> does **not** join the benchmark regression gate yet.

### What is excluded

- **WAN upstream RTT** — the gateway benchmark uses an in-process mock server; add your provider latency separately.
- **Retry / fallback routing** — not benchmarked until Epic #113 ([#138](https://github.com/dativo-io/talon/issues/138) / [#139](https://github.com/dativo-io/talon/issues/139)) lands.
- **Streaming responses** — benchmarks use non-streaming JSON completions only.
- **Attachment extraction / injection scan** — not in the default payload; add fixtures if you need that dimension.

## Method

1. **Toolchain:** `go test -bench=… -benchmem -benchtime=2s -count=5 -run=^$` over `./internal/gateway/...`, `./internal/classifier/...`, and `./internal/evidence/...`.
2. **Cache:** `-count=5` runs five iterations; the script reports the **last** `ns/op` line per benchmark (median-of-runs is a reasonable stability check; inspect raw output in stderr for spread).
3. **Hardware:** `scripts/run-benchmarks.sh` records `go version`, `uname`, and CPU model in the emitted table. Paste that block when publishing numbers externally.
4. **Comparison to the 15 ms budget:** See the step table in [What Talon does to your request](../explanation/what-talon-does-to-your-request.md). Gateway overhead should be **below 15 ms** on a modern laptop/desktop when upstream is local; production adds network, disk contention, and concurrent load.

## Interpreting results

- **Gateway ms/req** — wall-clock per governed request with mock upstream. If this is consistently above 15 ms on your hardware, profile before citing the README claim in customer-facing material.
- **PII ms/scan** — scales with input length and pattern density; the fixed benchmark string is a regression anchor, not a worst case.
- **Evidence writes/s** — inverse of `ns/op` for `BenchmarkEvidenceStore`; useful for capacity planning on evidence-heavy workloads.

## Source locations

- Gateway: [`internal/gateway/bench_test.go`](../../internal/gateway/bench_test.go)
- PII: [`internal/classifier/pii_test.go`](../../internal/classifier/pii_test.go) (`BenchmarkPIIScan`)
- Evidence: [`internal/evidence/store_test.go`](../../internal/evidence/store_test.go) (`BenchmarkEvidenceStore`)
- Runner: [`scripts/run-benchmarks.sh`](../../scripts/run-benchmarks.sh)

## Related proof-bar docs

- [Presidio compatibility matrix](./presidio-compatibility-matrix.md) — CI-enforced `BenchmarkPIIScan` regression gate (`make benchmark-regression`)
- [Conformance suite & count](conformance.md) — reproducible test count for evidence + policy paths
- [Evidence integrity specification](evidence-integrity-spec.md) — signed record format
- [Threat model](threat-model.md) — trust boundaries the benchmarks do not replace

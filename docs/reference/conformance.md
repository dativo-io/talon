# Conformance Suite & Published Count

**Status:** stable · **Scope:** the evidence and policy execution paths.

Talon publishes a single, reproducible number: the count of passing tests across
the two paths that carry its core guarantees — the **evidence** path (how records
are built, signed, exported, and verified) and the **policy** path (how requests
are classified, routed, and allowed or denied).

The number is meant to be *checkable*, not impressive. Anyone can reproduce it
from a clean checkout, and CI prints it on every run. The authoritative value is
whatever `make conformance` reports for the commit you are looking at.

## Reproduce it

```bash
make conformance
```

Example output:

```
Conformance: 317 passing tests across evidence + policy paths (./internal/policy/... ./internal/evidence/...)
```

The target runs `go test -count=1 -run . -v` over `./internal/policy/...` and
`./internal/evidence/...`, then counts the `--- PASS:` lines emitted by the Go test
runner. That count includes both top-level test functions and table-driven
subtests, so each named case is counted once. `-count=1` disables the test cache,
so the number is computed fresh every time. If any test fails, the target exits
non-zero and prints the failure tail instead of a count.

## What is in scope

The count aggregates the test files in the two packages below. The list is
descriptive — the suite is simply "every test in these two packages", so new tests
raise the number automatically without touching this document.

**Policy path — `internal/policy`**

| File | Covers |
|------|--------|
| `engine_test.go` | Policy engine evaluate/decision logic |
| `gateway_engine_test.go` | Gateway-mode policy evaluation |
| `golden_test.go` | Golden policy decisions against `testdata/` fixtures |
| `loader_test.go` | `.talon.yaml` policy loading and validation |
| `routing_policy_test.go` | Tier-based model routing decisions |
| `classifier_convert_test.go` | Classifier → policy-input conversion |
| `proxy_test.go` | Proxy-mode policy enforcement |
| `openclaw_gaps_test.go` | Regression cases for known governance gaps |
| `metrics_test.go` | Policy decision metrics |

**Evidence path — `internal/evidence`**

| File | Covers |
|------|--------|
| `store_test.go` | Evidence record build, persist, query, tenant scoping |
| `signed_export_test.go` | Signed JSON/NDJSON export and offline verification |
| `integrity_spec_test.go` | Round-trip of the [evidence integrity spec](evidence-integrity-spec.md) |
| `schema_compat_test.go` | Backward compatibility of the record schema |
| `export_test.go` | CSV/JSON export shape |
| `metrics_test.go` | Evidence write metrics |

### Adjacent suites (counted separately)

The embedded OPA/Rego policies have their own test suite that runs under the `opa`
toolchain rather than `go test`, so it is **not** included in the Go conformance
count. Run it with `make opa-test`. Integration and end-to-end tiers
(`make test-integration`, `make test-e2e`) exercise the same paths through the
running binary and are likewise tracked separately.

## What the number means — and what it does not

- It **does** mean: the evidence and policy code paths have this many passing,
  deterministic checks that anyone can re-run, and a regression that breaks one of
  them fails CI.
- It **does not** mean: that the suite is exhaustive, that it covers every
  configuration, or that a high count by itself demonstrates a compliance outcome.
  Talon produces supporting controls and evidence; coverage and limitations are
  documented in [`LIMITATIONS.md`](../../LIMITATIONS.md).

The count is a floor that grows as tests are added; it is not a marketing target.
Treat the live output of `make conformance` as the source of truth.

---
paths:
  - "internal/govcode/**"
  - "internal/gateway/errors*.go"
  - "internal/gateway/evidence.go"
  - "internal/gateway/decision.go"
  - "internal/config/**"
  - "internal/pricing/**"
  - "pricing/**"
  - "docs/reference/**"
  - "tests/smoke_sections/**"
  - "tests/smoke_test.sh"
  - "CHANGELOG.md"
  - "LIMITATIONS.md"
---

# Contract-surface registration checklists

Each surface below is registered in several places that tests pin against each other. Change all of them in the same commit, or the repository tests fail.

## Machine code (governance / error contract)

1. `internal/govcode/codes.go`: the constant and its spec (class, retryability, explanation code, producer).
2. The emitting site uses the `code: message` prefix so `normalizeGatewayError` (`internal/gateway/errors.go`) lifts it into both wire families; budget and pricing preconditions live in `internal/gateway/decision.go`, policy denials in `internal/policy/rego/gateway_access.rego`.
3. `docs/reference/error-contract.md`: table row (status, code, trigger, retriable) and a semantics bullet when the code changes what clients may rely on.
4. `docs/reference/mcp-governance-extension.md`: registry table row.
5. `internal/gateway/errors_test.go`: `TestErrorContract_DocumentedCodes` and `TestErrorContract_CodesRegisteredInGovcode` lists; `TestEvaluateDelegated_TalonDenyCodes` when the delegated path can emit it.
6. `CHANGELOG.md` upgrade impact: codes are additive and public; clients key on them.

## Evidence annotation

1. Add it to the allowed-annotation set in `internal/gateway/evidence.go`; an unlisted annotation is silently dropped (`dropping_unsupported_gateway_annotation`) even if docs mention it.
2. Document it where the code that sets it is documented (`docs/reference/error-contract.md` for budget preconditions) and assert it in the test that produces the record.

## Pricing table

- Two hand-maintained mirrors: `pricing/models.yaml` (repo, copied verbatim by demos) and `internal/pricing/default_models.yaml` (embedded; `talon init` writes it). Edit both identically.
- Semantics: `models: {}` declares an explicitly zero-cost provider; `inherit: <catalog provider>` prices an aliased endpoint; a provider or model that is absent is unknown and is denied `pricing_unavailable` under a binding cap (the organization baseline always binds one). Never list a commercial endpoint as free.
- `talon openshell prepare --provider-pricing` writes aliases for sandbox-facing providers; an operator-priced provider is never overwritten.
- Changing semantics touches `docs/reference/provider-registry.md` (cost estimation), `LIMITATIONS.md` §7 and `TestResolve_ZeroCostVersusUnknown`.

## Configuration field

Struct field, default, validation, `docs/reference/configuration.md` row, example configs and templates that show it, and a test for default plus invalid value. A field is public once released; prefer no field over a speculative one.

## Smoke section

1. `tests/smoke_sections/NN_name.sh` defining `test_section_NN_name`, using the request helpers in `tests/smoke_lib.sh`.
2. `tests/smoke_test.sh`: the sourced-file list, the `run_section "NN_name" test_section_NN_name` call, the section index comment in the header, and `SMOKE_OFFLINE_SECTIONS` when the section needs no provider key.
3. `Makefile` help text and `CONTRIBUTING.md` "No-key smoke gates" when the section is an offline gate; a CI step when it must gate PRs.
4. The section exercises the claimed feature end to end; startup or HTTP 200 is not proof.

## Docs guarded by tests

- `go test ./tests`: no legacy caller nouns (#266), no live-posture vocabulary (#442), no rejected architecture claims; ADRs and CHANGELOG are allowlisted history.
- `scripts/check-claim-discipline.sh`: never a compliance outcome, always "supporting controls / evidence for <article>".
- Markdown link check runs on `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LIMITATIONS.md`, `docs/`, `examples/`.
- `LIMITATIONS.md` "Backed by" lists name tests that exist.

## CHANGELOG entry

Under `## [Unreleased]`, in the matching `### Added | Changed | Fixed | Security` group: problem solved, who should care, how to verify (command or test), upgrade or migration impact, share artifact when applicable. Shipped behaviour only.

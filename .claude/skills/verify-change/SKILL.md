---
name: verify-change
description: Run the right local verification ladder for a Talon change, map every CI job to its local command, and reproduce a CI failure from a pasted log before changing anything.
---

Verify $ARGUMENTS (a change, a package set, or a pasted CI log).

## Ladder

Run narrow first, broad before handoff, one heavyweight suite at a time (the dev hosts have few cores; never run two race/integration/e2e suites concurrently).

1. Focused: `go test ./internal/<pkg> -run '<TestName>' -count=1`
2. Package(s) touched, with the race detector: `go test -race -count=1 ./internal/<pkg>/...`
3. Black-box tiers the change crosses:
   - integration: `go test -race -count=1 -tags=integration ./tests/integration/...`
   - e2e (builds the binary in TestMain): `go test -count=1 -tags=e2e -timeout 5m ./tests/e2e/...`
   - offline smoke sections: `SMOKE_ONLY="37_mcp_governance 38_openshell 39_budget" make test-smoke` (no provider key); the full `make test-smoke` needs `TALON_SECRETS_KEY` and `OPENAI_API_KEY`.
4. Static: `gofmt -l .`, `go vet ./...`, `golangci-lint run ./...`, `git ls-files -z '*.sh' | xargs -0 shellcheck`, `git diff --check`.
5. Repository guards whenever docs, examples or templates changed: `go test ./tests` (vocabulary and architecture-claim guards) and `bash scripts/check-claim-discipline.sh`.
6. Repository-level confidence: `make check` (lint, vet, SSOT gate, unit, integration, guards) and `make test-e2e`.

Use `-count=1` for anything you will report. Report exactly which commands ran and their result; name what you did not run and why.

## CI job to local command

| Workflow / job / step | Local equivalent | Needs |
|---|---|---|
| CI / test / Format check, Vet | `gofmt -l .`, `go vet ./...` | — |
| CI / test / Run unit tests | `go test -race -count=1 $(go list ./internal/... ./cmd/... \| grep -v internal/testutil \| grep -v internal/llm/testutil \| grep -v 'cmd/talon')` | CGO + SQLite |
| CI / test / PII benchmark regression | `make benchmark-regression` | linux/amd64 for the baseline |
| CI / test / Run integration tests | `go test -race -count=1 -tags=integration ./tests/integration/...` | — |
| CI / test / Run repository guard tests | `go test ./tests` | — |
| CI / test / Run e2e tests | `go test -count=1 -tags=e2e -timeout 5m ./tests/e2e/...` | — |
| CI / test / MCP governance smoke | `make test-mcp-governance-smoke` | — |
| CI / test / OpenShell composition smoke | `make test-openshell-smoke` | — (fixture supervisor, no Docker) |
| CI / test / OpenShell showcase runner contract | `make test-openshell-showcase-contract` | — |
| CI / test / Check coverage | unit coverage ≥ 65% (`coverage.out` from the unit run) | — |
| CI / test / Conformance count | `make conformance` | — |
| CI / test / OPA/Rego policy tests | `make opa-test` | `opa` binary |
| CI / proof-gates | `make proof-gates` (fuzz gates; slow) | — |
| CI / product-demo-smoke | `make smoke-product-demo` | `gum`; writes under `/tmp` (copy the script and redirect paths on a host where `/tmp` is read-only) |
| CI / lint, shellcheck | `golangci-lint run ./...`, shellcheck over `git ls-files '*.sh'` | — |
| CI / build, docker | `make build`, `docker build -t talon:ci .` | Docker for the image |
| Docs / Markdown link check, claim discipline | check every link you added by hand; `bash scripts/check-claim-discipline.sh` | — |
| Security / govulncheck, gitleaks, SBOM | `govulncheck ./...` when `go.mod` or the toolchain changes | network |
| Shortlist Demo | `make verify-shortlist-demo` | Docker compose |
| OpenShell Live / live (v0.1.3 required, v0.1.4 experimental) | `make test-openshell-live` (`OPENSHELL_VERSION=v0.1.x`) | Docker ≥ 28 on Linux, GHCR pull |
| OpenShell Live / showcase | `make openshell-showcase-validate` | Docker ≥ 28 on Linux |
| CodeQL | no local equivalent | — |

Anything in the Docker rows cannot be proven on a host without a Docker socket; say so and let the PR's own CI run be the proof for those rows.

## Reproducing a CI failure from a log

1. Read the `Run <command>` header line: it names the job step and therefore the row above.
2. Establish which commit CI ran before concluding anything: `gh pr view <n> --json headRefOid` (or the GitHub API) against `git log -1`. A failure is often already fixed by a local commit that has not been pushed; say that instead of re-fixing.
3. Run the step's exact command locally, with the same flags (`-race`, `-tags`, `-count=1`), on the whole package, not only the failing test.
4. If it passes in isolation but fails in the package run, look for order or environment dependence: shared global state, cwd-relative files, pricing fixtures (black-box fixtures use the real catalog, where `ollama` is zero-cost), time boundaries, a pre-existing recovered panic printed by another test. Do not call it flaky until you have a mechanism.
5. A fix needs a test that fails without it; re-run the step's full command afterwards and quote the result.

## Fixture rules that CI enforces

- Black-box fixtures (`internal/server`, `tests/integration`, `tests/e2e`) price with the production estimator over the embedded catalog. A provider or model outside `pricing/models.yaml` is denied `pricing_unavailable` in tests exactly as in production; fix the fixture's provider or model, never the estimator.
- Preventive claims are proven by counting the upstream or action target, not by a status code.
- No sleeps, retries, or fixture-specific branches to hide a failure (see `.claude/rules/testing.md`).

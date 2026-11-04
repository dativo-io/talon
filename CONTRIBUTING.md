# Contributing to Talon

Thanks for helping improve Talon.

## Start Here (30 seconds)

- New contributors: pick a [`good first issue`](https://github.com/dativo-io/talon/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
- Want broader tasks: check [`help wanted`](https://github.com/dativo-io/talon/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
- Need context first: read [docs/README.md](docs/README.md)
- Unsure where to begin: open an issue and ask for a starter task

## Maintainer Response SLA (best effort)

- New issues: within 72 hours
- Pull requests: first review within 72 hours
- Security reports: see [SECURITY.md](SECURITY.md)

## Development Setup

1. Install Go 1.26.10+ (`go.mod` pins the toolchain; `GOTOOLCHAIN=auto` fetches it on an older install)
2. Install dependencies: `go mod download`
3. Build: `make build`
4. Test: `make test`
5. Lint: `make lint`

## Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes following this guide
4. Run `make check` (lint, vet, unit + integration tests; must pass)
5. Optionally run `make test-e2e` or `make test-all` for full CI parity (e2e included)
6. Commit using conventional commits: `type(scope): description`
7. Push and create PR

## Commit Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `chore`: Maintenance
- `refactor`: Code refactoring
- `perf`: Performance improvement

## Code Style

- Keep behavior changes accompanied by tests.
- Prefer clear, verifiable claims in docs (commands, source links, or test references).

### Compliance-claim discipline (required)

EU buyers distrust overclaiming, so every compliance reference must be under-claimed:

- **Always** phrase as "supporting controls / evidence for `<regulation/article>`" and pair a feature with the article it supports (e.g. "output PII scan → supporting control for GDPR Art. 32").
- **Never** claim a compliance *outcome*: avoid "GDPR compliant", "makes you compliant", "ensures/guarantees compliance", or "X to compliant". The operator remains responsible for the legal determination.
- See [LIMITATIONS.md](LIMITATIONS.md) for the compliance boundary and [`internal/compliance/mapping.go`](internal/compliance/mapping.go) for the built-in article mappings.

## Testing

- **Unit tests:** `go test -race -coverprofile=coverage.out ./internal/... ./cmd/...` (or `make test`, which also runs integration)
- **Integration tests:** `make test-integration` — runs `./tests/integration/...` with `-tags=integration`
- **E2E tests:** `make test-e2e` — runs `./tests/e2e/...` with `-tags=e2e` (builds binary in TestMain, 5m timeout)
- **All tiers:** `make test-all` — unit + integration + e2e
- **No-key smoke gates:** `make test-mcp-smoke` (MCP 2026-07-28 wire, #447), `make test-mcp-governance-smoke` (governance extension + signed evidence contract against the built binary, #372; also smoke section 37 and a PR CI step) `make test-action-catalog-smoke` (trusted catalog, #427) and `make test-openshell-smoke` (OpenShell composition against the fixture supervisor incl. the SDK agent, #482; also smoke section 38 and a PR CI step). `make test-smoke` is the full black-box suite and needs a provider key.

Test layout:

- Unit tests live next to code in `internal/*` and `cmd/*` (no build tags).
- Integration tests are in `tests/integration/` and use `//go:build integration`.
- E2E tests are in `tests/e2e/` and use `//go:build e2e`; they run the real CLI against a mock LLM (set `OPENAI_BASE_URL` to a mock server).

CI runs all three tiers; coverage is computed from unit tests only. Coverage target: ≥65% (CI fails if below; goal 70%). The coverage run excludes `cmd/talon` (main) and `internal/testutil` (test helpers).

## Release Notes Quality Bar

When your PR changes user-facing behavior, include a release-note friendly summary in your PR description:

- Problem solved
- Who should care
- How to verify
- Upgrade or migration impact

## Release Artifact Verification (maintainers)

The release workflow (`.github/workflows/release.yml`, #507) is build → verify → publish:
GoReleaser creates the release as a **draft** (invisible to `releases/latest`, `install.sh`
and anonymous downloads), the showcase bundle and the darwin archives are added to the
draft, and `release-verify` downloads every asset from the draft, checks every digest,
confirms the manifest's `artifacts.talon.sha256` is the digest of the released binary, runs
the showcase **customer path** from the published artifacts (no checkout, real OpenShell
sandbox) and only then publishes the release and moves the Docker `latest` and
`<major>.<minor>` tags. A failed verification leaves a draft: fix forward and cut the next
version. A published release is never modified (`scripts/release-guard.sh` refuses to build
or upload against one; enable **immutable releases** in the repository settings so GitHub
enforces the same and attaches attestations). All release runs share one concurrency group,
so two versions, or an audit and a release, never race over `releases/latest` and the movable
Docker tags; GitHub keeps one pending run per group and cancels an older pending one, so a run
queued behind two others must simply be re-run. Before publication the verify job also pulls
and runs `ghcr.io/dativo-io/talon:<version>` — the image `latest` will point at.

**If the run fails after "Publish the release"** (alias promotion or the anonymous
re-download), the release is public and correct; nothing needs rewriting. Re-run the
verification in audit mode — it re-checks every published asset and re-applies the Docker
`latest` / `<major>.<minor>` tags when the tag is the repository's latest release:

```bash
gh workflow run release.yml -f tag=vX.Y.Z
```

**Rehearse pipeline changes with a pre-release.** Any change to `release.yml`,
`.goreleaser.yml` or the bundle script is exercised first by tagging `vX.Y.Z-rc.1`: the
same draft → verify → publish path runs for real, GoReleaser marks it a pre-release,
`releases/latest`, `install.sh` and the movable Docker tags ignore it, and a failure leaves
a draft. Only then tag `vX.Y.Z`.

After the workflow has published the release:

```bash
LATEST=$(gh release view --json tagName -q .tagName)
gh release view "$LATEST" --json isDraft,assets -q '"draft=\(.isDraft)", .assets[].name'
gh api "/repos/dativo-io/talon/actions/workflows/release.yml/runs?per_page=1" -q '.workflow_runs[0].conclusion'
# the manifest lists the released talon binary (the customer path depends on it)
V=${LATEST#v}; gh release download "$LATEST" -p "talon_${V}_linux_amd64.tar.gz" -p "talon-openshell-showcase_${V}_linux_amd64.manifest.json" -D /tmp/rel
tar -C /tmp/rel -xzf "/tmp/rel/talon_${V}_linux_amd64.tar.gz" talon && [ "$(jq -r .artifacts.talon.sha256 /tmp/rel/*.manifest.json)" = "$(sha256sum /tmp/rel/talon | cut -d' ' -f1)" ] && echo manifest-ok
docker pull ghcr.io/dativo-io/talon:latest
# re-run the verification against any published release (audit mode, changes nothing)
gh workflow run release.yml -f tag="$LATEST"
```

Check that release notes link at least one share artifact (screenshot, GIF, or migration snippet). To refresh Mission Control screenshots, see [docs/contributor/mission-control-screenshots.md](docs/contributor/mission-control-screenshots.md).

## Weekly Repo Quality Scorecard (maintainers)

- Broken markdown links: target `0`
- Missing contributor-path links: target `0`
- New trust/proof artifacts added this week
- `good first issue` count and freshness
- README install/proof commands still reproducible

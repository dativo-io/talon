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
- **No-key smoke gates:** `make test-mcp-smoke` (MCP 2026-07-28 wire, #447), `make test-mcp-governance-smoke` (governance extension + signed evidence contract against the built binary, #372; also smoke section 37 and a PR CI step) `make test-action-catalog-smoke` (trusted catalog, #427), `make test-action-smoke` (exact governed action and the company action policy against the built binary, #458/#425; also smoke section 41 and a PR CI step) and `make test-openshell-smoke` (OpenShell composition against the fixture supervisor incl. the SDK agent, #482; also smoke section 38 and a PR CI step). `make test-smoke` is the full black-box suite and needs a provider key.

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

The release workflow (`.github/workflows/release.yml`, #507, #359) is build → verify → publish:
GoReleaser creates the release as a **draft** (invisible to `releases/latest`, `install.sh`
and anonymous downloads), the showcase bundle and the darwin archives are added to the
draft, and `release-verify` downloads every asset from the draft and runs
`scripts/verify-release.sh` on it — the same verifier a customer runs: every digest, the
executable reports exactly `Talon <version>` and the commit the tag points at, the manifest's
`artifacts.talon.sha256` is the digest of the released executable, the bundle is consistent —
then runs the showcase **customer path** from the published artifacts (no checkout, real
OpenShell sandbox) and only then publishes the release and moves the Docker `latest` and
`<major>.<minor>` tags. After publication it runs the verifier again from the customer's
side: public downloads, no token, anonymous image pulls, `install.sh` under `sh` into a
scratch directory, the installed binary byte-identical to the verified one, the public
bytes identical to the draft's.

**Supported-platform guarantee (#359 MVP).** The gated installer path is **linux/amd64**: its
archive is required, verified before publication and installed by `install.sh`. The darwin
archives (arm64, amd64) are **best effort**: present when the macOS job built them, absent
otherwise, and the release never claims otherwise — `scripts/release-platform-report.sh`
classifies the darwin outcome from the run's jobs and its "Platform assets" table is appended
to the release notes and the job summary before publication. The classification matters: a
macOS runner that was never acquired (v1.15.4-rc.2: queued 15 minutes, `cancelled`, three
times) is a **warning** and does not block a Linux release; a **failed macOS build** is
reported as exactly that (`::error` annotation, "build FAILED at step …" on the release page),
is never described as an unavailable runner, and is fixed forward in the next version; a
darwin job that succeeded without leaving an archive **stops** the publication. This neither
promises darwin archives nor removes them: the README has listed linux/amd64 as the prebuilt
platform since the first releases, and each release page now states which archives it ships.
Changing the guarantee (for example making darwin required, or shipping linux/arm64) is a
documented decision in README, this section and `release.yml`, not a side effect of a job. Talon releases form one ascending line (fix forward, no maintenance
branches): publishing marks the release GitHub's latest, so `releases/latest`, `install.sh`
and both movable tags always follow the newest published version. Tagging a version lower
than the current latest is not a supported path — it would become latest everywhere. A
failed verification leaves a draft: fix forward and cut the next version. A published release is never modified (`scripts/release-guard.sh` refuses to build
or upload against one; enable **immutable releases** in the repository settings so GitHub
enforces the same and attaches attestations). All release runs share one concurrency group,
so two versions, or an audit and a release, never race over `releases/latest` and the movable
Docker tags; GitHub keeps one pending run per group and cancels an older pending one, so a run
queued behind two others must simply be re-run. Before publication the verify job also proves
both GHCR packages (`talon`, `talon-openshell-agent`) are pullable **without credentials**
(`scripts/check-image-public.sh`; a workflow-created package is private until its visibility is
set to Public once in the package settings — customers and OpenShell have no GHCR login), then
pulls and runs `ghcr.io/dativo-io/talon:<version>` — the image `latest` will point at.

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
a draft. Only then tag `vX.Y.Z` on the same commit: GoReleaser is told the tag it builds and
the tag the release notes start after (the latest published release) explicitly, so the rc and
the final release both carry the full notes instead of the empty `rc.1..vX.Y.Z` range.

After the workflow has published the release:

```bash
LATEST=$(gh release view --json tagName -q .tagName)
gh release view "$LATEST" --json isDraft,assets -q '"draft=\(.isDraft)", .assets[].name'
gh api "/repos/dativo-io/talon/actions/workflows/release.yml/runs?per_page=1" -q '.workflow_runs[0].conclusion'
# the customer's verification, from the public artifacts only (no token, no Go):
# checksums, executable version + commit against the tag, manifest artifacts.talon.sha256,
# bundle, anonymous image pulls, install.sh into a scratch directory. Prints the digests
# to record (release tag, archive, executable, bundle, manifest, both image digests).
scripts/verify-release.sh --tag "$LATEST" --install /tmp/talon-verify-install --all-archives --summary-json /tmp/talon-verify.json
# the same, on a clean GitHub runner; artifacts carry the verdict and the summary json
gh workflow run install-smoke.yml -f tag="$LATEST"
docker pull ghcr.io/dativo-io/talon:latest
# re-run the full verification against any published release (audit mode, changes nothing)
gh workflow run release.yml -f tag="$LATEST"
```

The offline failure-injection test behind these scripts is `make test-release-verify`
(`scripts/test-verify-release.sh`, a PR CI step): a fake release built like the real one is
served from 127.0.0.1 and an altered binary (with and without regenerated checksums), a
modified or missing `artifacts.talon.sha256`, a version or commit mismatch, a private image,
a draft and an unknown version pin must each fail closed, for the verifier and for
`install.sh` run under `sh`. That test is source-only; the published artifact is proven by
`release-verify` and by `install-smoke.yml` against the real release.

**Minimal release checklist (one supported path: linux/amd64).**

1. `main` green, including `make test-release-verify` (verifier, installer and platform-report failure injection) and `make test-openshell-showcase-contract`.
2. `## [Unreleased]` complete; an unpublished earlier section (a tag that published nothing) is folded into the new one and named there.
3. Pipeline change since the last release (`release.yml`, `.goreleaser.yml`, `scripts/build-showcase-bundle.sh`, `scripts/verify-release.sh`, `scripts/install.sh`)? Tag `vX.Y.Z-rc.N` first and let it publish as a pre-release.
4. Tag the merged commit on `main`; `release.yml` must reach "Publish the release" and finish green (draft verification, platform assets report, image visibility, customer path, released image, publication, alias promotion, public re-verification). Read the "Platform assets" table in the job summary: an absent darwin archive must say why; a "build FAILED" is an issue to file and fix forward.
5. From a machine that is not the runner: `scripts/verify-release.sh --tag vX.Y.Z --install <dir>` → `PASS verify-release: vX.Y.Z`; then `gh workflow run install-smoke.yml -f tag=vX.Y.Z` → green.
6. Record the printed digests (archive, executable, bundle, manifest, both images) wherever the release is consumed (for example a demo's proof manifest). A FAIL anywhere is fixed forward in the next version, never by editing published assets.

Check that release notes link at least one share artifact (screenshot, GIF, or migration snippet). To refresh Mission Control screenshots, see [docs/contributor/mission-control-screenshots.md](docs/contributor/mission-control-screenshots.md).

## Weekly Repo Quality Scorecard (maintainers)

- Broken markdown links: target `0`
- Missing contributor-path links: target `0`
- New trust/proof artifacts added this week
- `good first issue` count and freshness
- README install/proof commands still reproducible

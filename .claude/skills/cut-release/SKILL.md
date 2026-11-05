---
name: cut-release
description: Cut a Talon release the way the repository does it — changelog section and compare link, release branch and PR, annotated tag on merged main, release workflow verification, and the re-cut rule when a release job fails.
disable-model-invocation: true
---

Cut release $ARGUMENTS (a semver `X.Y.Z`).

Every step marked **[human]** mutates GitHub, tags or registries and runs only on the user's explicit instruction; otherwise hand over the exact commands.

## Preconditions

1. `main` is green: CI, Docs, Security (govulncheck, gitleaks), CodeQL, Shortlist Demo, OpenShell Live (v0.1.3 required).
2. `## [Unreleased]` in `CHANGELOG.md` is complete and every entry meets the quality bar (problem, who cares, how to verify, upgrade impact, share artifact when applicable). Nothing in it describes unshipped behaviour.
3. `govulncheck ./...` is clean; if it is not, the fix (toolchain or dependency bump) ships in this release and is named in the notes.
4. Decide the version: patch for fixes and security, minor for features, following the previous section headers.

## Prepare the release commit

1. Branch from current `main`: `release-vX.Y.Z`.
2. `CHANGELOG.md`:
   - rename the Unreleased content to `## [X.Y.Z] - YYYY-MM-DD` and leave a fresh empty `## [Unreleased]` (keep the "Release Note Quality Bar" block under it);
   - open the section with a one-paragraph theme when the release has one;
   - add the compare link at the bottom: `[X.Y.Z]: https://github.com/dativo-io/talon/compare/vPREV...vX.Y.Z` (the first release of a line uses `releases/tag/vX.Y.Z`).
3. Nothing else carries the version: binaries use `git describe` (`VERSION` in the Makefile) and the release workflow derives the version from the tag.
4. Commit: `chore(release): cut vX.Y.Z — <one-line theme>`.
5. Run `/verify-change` at least to the static layer and `go test ./tests`; a release PR still passes the full CI.

## Ship

1. **[human]** Push the branch and open the PR; merge after green.
2. **[human]** Tag the merged commit **on `main`**, not the branch commit: merges are rebase merges, so a tag on the branch is never an ancestor of `main` (that happened to v1.15.0 and v1.15.2; cosmetic but confusing). Annotated tag:
   ```
   git switch main && git pull --ff-only
   git tag -a vX.Y.Z -m "vX.Y.Z — <theme>" && git push origin vX.Y.Z
   ```
3. The tag push runs `.github/workflows/release.yml` (build → verify → publish, #507): GoReleaser creates a **draft** release (linux archive, `checksums.txt`, the version-tagged images `ghcr.io/dativo-io/talon:<X.Y.Z>` and `ghcr.io/dativo-io/talon-openshell-agent:<X.Y.Z>`); the showcase bundle job reads `talon` back from that archive and writes its digest into the manifest; the darwin job adds its archives; `release-verify` checks every digest and runs the showcase customer path from the draft's assets, then publishes the release and moves `:latest` / `:<X.Y>`. A failed verification leaves a draft — fix forward, next patch version; never upload to or edit a published release (`scripts/release-guard.sh` refuses). A failure AFTER "Publish the release" (alias promotion, anonymous re-download) is recovered with `gh workflow run release.yml -f tag=vX.Y.Z` (audit mode: re-verifies, re-applies the movable image tags, rewrites nothing). When `release.yml`, `.goreleaser.yml` or the bundle script changed since the last release, tag `vX.Y.Z-rc.1` first: the pre-release runs the whole path for real while `releases/latest`, `install.sh` and the movable tags ignore it.

## Verify (CONTRIBUTING "Release Artifact Verification")

```
LATEST=$(gh release view --json tagName -q .tagName)
gh release view "$LATEST" --json isDraft,assets -q '"draft=\(.isDraft)", .assets[].name'
gh api "/repos/dativo-io/talon/actions/workflows/release.yml/runs?per_page=1" -q '.workflow_runs[0].conclusion'
docker pull ghcr.io/dativo-io/talon:latest
gh workflow run release.yml -f tag="$LATEST"   # audit mode: re-verifies the published assets, changes nothing
```

Also check: `draft=false`; the showcase bundle, its `.sha256` and its `.manifest.json` are among the assets and the manifest's `artifacts.talon.sha256` equals the sha256 of the `talon` inside `talon_<X.Y.Z>_linux_amd64.tar.gz`; both GHCR packages are public — `scripts/check-image-public.sh ghcr.io/dativo-io/talon:<X.Y.Z> ghcr.io/dativo-io/talon-openshell-agent:<X.Y.Z>` (the verify job runs the same check; a private package fails the rehearsal, as v1.15.4-rc.1 did); the release notes link at least one share artifact.

## When the release job fails after tagging

Do not delete or move the tag and do not re-run with the same version. Fix forward on `main`, cut the next patch version, and state in its CHANGELOG section that the earlier tag exists but published nothing (precedent: v1.15.1 → v1.15.2, where a timing-dependent test tripped the release gate).

## Handoff

Report the tag, the release URL, which verification commands ran and their output, and anything still unverified (for example GHCR visibility or the clean-host showcase run).

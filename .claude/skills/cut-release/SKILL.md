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
3. The tag push runs `.github/workflows/release.yml`: GoReleaser (linux archives, `ghcr.io/dativo-io/talon:<X.Y.Z>` and `:latest`, the sandbox agent image `ghcr.io/dativo-io/talon-openshell-agent:<X.Y.Z>`), the OpenShell showcase bundle uploaded next to the archives, and native darwin binaries.

## Verify (CONTRIBUTING "Release Artifact Verification")

```
LATEST=$(gh release view --json tagName -q .tagName)
gh release view "$LATEST" --json assets -q '.assets[].name'
gh api "/repos/dativo-io/talon/actions/workflows/release.yml/runs?per_page=1" -q '.workflow_runs[0].conclusion'
docker pull ghcr.io/dativo-io/talon:latest
```

Also check: the showcase bundle and its `.sha256` are among the assets; the agent image package on GHCR is public (the customer path pulls it without credentials); the release notes link at least one share artifact; a clean host can run the showcase from the published bundle per `examples/openshell/showcase/README.md`.

## When the release job fails after tagging

Do not delete or move the tag and do not re-run with the same version. Fix forward on `main`, cut the next patch version, and state in its CHANGELOG section that the earlier tag exists but published nothing (precedent: v1.15.1 → v1.15.2, where a timing-dependent test tripped the release gate).

## Handoff

Report the tag, the release URL, which verification commands ran and their output, and anything still unverified (for example GHCR visibility or the clean-host showcase run).

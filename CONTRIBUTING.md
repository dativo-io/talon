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

1. Install Go 1.22+
2. Install dependencies: `go mod download`
3. Build: `make build`
4. Test: `make test`
5. Lint: `make lint`

## Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes following this guide and [AI_ASSISTANCE.md](AI_ASSISTANCE.md)
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
- For compliance wording, use "supports controls" language; do not claim guaranteed compliance.

## Testing

- **Unit tests:** `go test -race -coverprofile=coverage.out ./internal/... ./cmd/...` (or `make test`, which also runs integration)
- **Integration tests:** `make test-integration` — runs `./tests/integration/...` with `-tags=integration`
- **E2E tests:** `make test-e2e` — runs `./tests/e2e/...` with `-tags=e2e` (builds binary in TestMain, 5m timeout)
- **All tiers:** `make test-all` — unit + integration + e2e

Test layout:

- Unit tests live next to code in `internal/*` and `cmd/*` (no build tags).
- Integration tests are in `tests/integration/` and use `//go:build integration`.
- E2E tests are in `tests/e2e/` and use `//go:build e2e`; they run the real CLI against a mock LLM (set `OPENAI_BASE_URL` to a mock server).

CI runs all three tiers; coverage is computed from unit tests only. Coverage target: ≥65% (CI fails if below; goal 70%). The coverage run excludes `cmd/talon` (main) and `internal/testutil` (test helpers).

### Mission Control Screenshot Refresh Workflow

When updating the mission-control dashboard or any UI components, you may need to refresh screenshots for documentation or marketing materials. Follow this workflow:

1. **Start the Talon server** with the dashboard enabled:
   ```bash
   talon serve --port 8080
   ```

2. **Navigate to the mission-control dashboard** in your browser:
   - Main dashboard: `http://localhost:8080/dashboard?talon_admin_key=YOUR_TALON_ADMIN_KEY`
   - Gateway dashboard: `http://localhost:8080/gateway/dashboard?talon_admin_key=YOUR_TALON_ADMIN_KEY`

3. **Generate sample data** (if needed) using the demo recorder script:
   ```bash
   bash scripts/demo-recorder.sh
   ```

4. **Take screenshots** using your preferred method:
   - Browser developer tools (screenshot node or full page)
   - Command-line tools (e.g., `chromium --headless --screenshot`)
   - Manual screenshots for interactive elements

5. **Store screenshots** in the appropriate documentation directory:
   - UI screenshots: `docs/images/ui/`
   - Dashboard screenshots: `docs/images/dashboard/`

6. **Update references** in documentation to point to the new screenshots.

**Note:** Ensure screenshots are taken with consistent window sizes and themes to maintain visual coherence across documentation.

## Release Notes Quality Bar

When your PR changes user-facing behavior, include a release-note friendly summary in your PR description:

- Problem solved
- Who should care
- How to verify
- Upgrade or migration impact

## Release Artifact Verification (maintainers)

After tagging a release:

```bash
LATEST=$(gh release view --json tagName -q .tagName)
gh release view "$LATEST" --json assets -q '.assets[].name'
gh api "/repos/dativo-io/talon/actions/workflows/release.yml/runs?per_page=1" -q '.workflow_runs[0].conclusion'
docker pull ghcr.io/dativo-io/talon:latest
```

Check that release notes link at least one share artifact (screenshot, GIF, or migration snippet).

## Weekly Repo Quality Scorecard (maintainers)

- Broken markdown links: target `0`
- Missing contributor-path links: target `0`
- New trust/proof artifacts added this week
- `good first issue` count and freshness
- README install/proof commands still reproducible

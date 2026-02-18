# Contributing to Talon

## Development Setup

1. Install Go 1.22+
2. Install dependencies: `go mod download`
3. Build: `make build`
4. Test: `make test`
5. Lint: `make lint`

## Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes following `.cursorrules`
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

Follow `.cursorrules` and `CLAUDE_PROJECT_INSTRUCTIONS.md`.

## Testing

- **Unit tests:** `go test -race -coverprofile=coverage.out ./internal/... ./cmd/...` (or `make test`, which also runs integration)
- **Integration tests:** `make test-integration` — runs `./tests/integration/...` with `-tags=integration`
- **E2E tests:** `make test-e2e` — runs `./tests/e2e/...` with `-tags=e2e` (builds binary in TestMain, 5m timeout)
- **All tiers:** `make test-all` — unit + integration + e2e

Test layout:

- Unit tests live next to code in `internal/*` and `cmd/*` (no build tags).
- Integration tests are in `tests/integration/` and use `//go:build integration`.
- E2E tests are in `tests/e2e/` and use `//go:build e2e`; they run the real CLI against a mock LLM (set `OPENAI_BASE_URL` to a mock server).

CI runs all three tiers; coverage is computed from unit tests only. Coverage target: ≥70% (CI fails if below). The coverage run excludes `cmd/talon` (main) and `internal/testutil` (test helpers).

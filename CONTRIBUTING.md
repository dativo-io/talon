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
4. Run `make check` (must pass)
5. Commit using conventional commits: `type(scope): description`
6. Push and create PR

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

- Unit tests: `make test`
- Integration tests: `make test-integration`
- Coverage target: ≥70%

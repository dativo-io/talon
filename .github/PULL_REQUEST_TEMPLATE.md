## Description

Initial project bootstrap: CLI framework, OpenTelemetry, and full directory scaffold for Dativo Talon (Prompt 1: Bootstrap + CLI + OTel).

## Type of Change

- [x] New feature (non-breaking change which adds functionality)
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)

## What's included

### Go module & dependencies
- **Module:** `github.com/dativo-talon/talon`, Go 1.22
- **Deps:** Cobra, Viper, OPA, SQLite, zerolog, OpenTelemetry SDK (stdout trace/metric exporters), uuid, x/time, x/crypto, cron/v3, chi/v5, testify

### CLI (Cobra)
- **Root command** with global flags: `--config`, `--verbose`, `--log-level`, `--log-format`; Viper config (TALON_ env, ~/.talon)
- **Commands:** `version`, `init`, `validate`, `run`, `serve`, `audit`, `costs`, `secrets`, `memory` (stubs with OTel spans)
- **OTel:** Package-level tracer, shutdown on exit (5s timeout)

### OpenTelemetry
- `internal/otel/setup.go` — TracerProvider, stdout exporter, resource (service name/version)
- `internal/otel/genai.go` — GenAI semantic attribute keys and helpers for LLM observability

### Structure
- `cmd/talon/main.go`, `internal/cmd/`, `internal/otel/`, `internal/{config,policy,classifier,llm,agent,evidence,tenant,secrets,memory,trigger,attachment,context,mcp,server}/`
- `policies/rego/`, `templates/init/`, `examples/`, `web/`, `docs/`, `scripts/`, `tests/integration/`

### Build & CI
- **Makefile:** build, install, test, lint, fmt, vet, clean, check, docker-build
- **Dockerfile:** Multi-stage (Alpine), CGO + SQLite
- **docker-compose.yml:** Talon service with env, volumes, healthcheck
- **.github/workflows:** ci.yml (test, lint, build, docker), release.yml (GoReleaser, Docker push)
- **.goreleaser.yml**, **.golangci.yml**

### Tests
- **Unit:** `internal/otel` (Setup, Tracer, LLMRequestAttributes, LLMUsageAttributes), `internal/cmd` (subcommands, help, flags)
- **Integration:** placeholder in `tests/integration/` (build tag `integration`)

### Docs
- README.md, CONTRIBUTING.md, CHANGELOG.md; .gitignore (binaries, coverage, IDE, .cursor, config, DB, .talon)

## Verification

- [x] `make build` — binary builds at `bin/talon`
- [x] `make test` — all tests pass (race, coverage)
- [x] `./bin/talon version` — prints version and OTel span to stderr
- [x] `./bin/talon --help` — lists all commands
- [x] Aligned with `.cursor/rules/main_rules.md` (package-level tracer, error wrapping, unit tests, OTel patterns)

## Related

- Implements **Prompt 1** from `internal_docs/PROMPT_01_BOOTSTRAP_CLI_OTEL.md`
- Next: Prompt 2 (Policy Engine + v2.0 Schema)

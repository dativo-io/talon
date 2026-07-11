# Coding-agents demo: multi-model orchestration, governed

One command shows an orchestrator fanning out to **two model providers**
through Talon — and leaves you holding **signed evidence** of everything.
Offline and deterministic: the mock provider speaks both the Anthropic
Messages API and the OpenAI Responses API (including SSE streaming with
cache-token usage), so **no real API key exists anywhere in this stack**.

```bash
make coding-agents-demo          # from the repo root
# or:
cd examples/coding-agents-demo
docker compose up -d --build && ./demo.sh all
```

Port busy? The gateway publishes host port 8080 by default (the mock is
network-internal and publishes nothing). If another stack or a local
`talon serve` holds 8080:

```bash
DEMO_GATEWAY_PORT=18080 docker compose up -d --build
GATEWAY=http://localhost:18080 ./demo.sh all
```

The same sequence is smoke-run in CI without Docker:
`go test -tags=integration ./tests/integration -run TestCodingAgentsDemo_EndToEnd`.

## Run it without Docker

The mock provider is a plain zero-dependency Go binary — Docker is packaging,
not a requirement. Two paths:

**Path A — one command, CI-identical:**

```bash
go test -tags=integration ./tests/integration -run TestCodingAgentsDemo_EndToEnd -v
```

Compiles the real mock, drives a real gateway through the full sequence
(cross-provider session, subagent rollup, budget deny with structured detail,
cache tokens from both SSE wires, signature verification), ~2s.

**Path B — hands-on, both processes under your control:**

```bash
# Terminal 1 — the dual-wire mock (Anthropic Messages + OpenAI Responses + Chat, all SSE)
cd examples/docker-compose/mock-provider && go run . -port 9090
```

```bash
# Terminal 2 — gateway in a scratch dir, pointed at the mock
mkdir /tmp/talon-demo && cd /tmp/talon-demo
cat > talon.config.yaml <<'EOF'
gateway:
  enabled: true
  mode: enforce
  providers:
    anthropic:
      enabled: true
      base_url: "http://localhost:9090"
      secret_name: "anthropic-api-key"
      api_family: "anthropic"
    openai:
      enabled: true
      base_url: "http://localhost:9090"
      secret_name: "openai-api-key"
  organization_policy:
    response_pii_action: "allow"
EOF
# The demo runs as the claude-code agent (agent.talon.yaml in this directory
# carries the identity + overrides, #266).
export TALON_SECRETS_KEY=$(openssl rand -hex 16) TALON_SIGNING_KEY=$(openssl rand -hex 16) TALON_ADMIN_KEY=demo-admin-key
talon secrets set anthropic-api-key fake   # the mock ignores auth
talon secrets set openai-api-key fake
talon secrets set claude-code-talon-key talon-gw-demo-coding-0001   # the agent traffic key
talon serve --gateway --gateway-config talon.config.yaml --port 8080
```

Then run the whole walk-through from a third terminal — `TALON_BIN` routes
the script's CLI steps to your local binary instead of the container:

```bash
cd <repo>/examples/coding-agents-demo
TALON_BIN=talon TALON_DATA_DIR=$HOME/.talon ./demo.sh all
```

(Use the same shell env — `TALON_SIGNING_KEY` etc. — as the serve terminal so
`talon audit verify` checks against the right key.) This is also the setup
for iterating on the mock itself: edit `main.go`, restart `go run`, re-fire
a curl.

## What you'll watch (about 30 seconds)

**1. One session, two providers.** A `generator` subagent calls the
*anthropic* route and an `executor` subagent (child of `generator`) calls the
*openai Responses* route — both carrying `X-Talon-Session-ID: sess-coding-demo`.
Talon records them as **one session** with per-subagent attribution
(`provenance: client_asserted` — attribution, not authentication).

> **The cast is made up.** `generator` and `executor` are arbitrary labels
> `demo.sh` passes in `X-Talon-Agent-ID`; Talon assigns them no meaning and
> validates them against no list — it records and rolls up whatever your
> fleet sends (see [Governing coding agents →
> Terminology](../../docs/guides/governing-coding-agents.md)). Only
> `X-Talon-Stage` has a fixed vocabulary.

**2. A PII event.** A prompt containing an email address is scanned, warned,
and evidenced (`pii_action: warn`) — the request still flows, because
blocking a coding agent on every address in a test fixture is how governance
tools get uninstalled.

**3. The session budget trips.** The caller has `max_session_cost: 0.02`.
After a few requests the gateway denies with a **provider-native** error:

```
request 4 → HTTP 403
deny body: session_budget_exceeded: session spend 0.02 + estimate 0.00 exceeds limit 0.02
```

The same session is denied on the *other* provider's route too — spend
accumulates per session, not per provider. It is a **soft cap**: an in-flight
request can overshoot before the next one is denied (atomic reservation is
tracked in #144).

**4. The session as a unit.**

```
Session sess-coding-demo
  Caller:    claude-code
  Source:    claude-code (client_asserted)
  Requests:  N (M allowed, 1 denied, 0 error)
  Providers: anthropic, openai
  Tokens:    in … / out … / cache-read 2048+ / cache-write …
  Cost:      €0.0…

  Per-agent:
    generator                 K req  €…
    executor  ←generator      1 req  €…
```

`talon costs --session … --json` returns the same numbers the dashboard's
**Coding Sessions** panel shows — both are produced by the same aggregation
function over the same signed records, so they cannot disagree.

**5. Hold the evidence.** `talon audit export --session … --format signed-json`
writes HMAC-SHA256-signed records to `./out/session-signed.json`;
`talon audit verify --session …` proves none were tampered with. The deny
record carries the structured `session_budget: {limit, spent, estimate}` the
decision was made on.

## Determinism notes

Mock IDs are counter-based (`msg_mock_000001`, …) and token counts derive
from fixed canned text, so transcripts are reproducible; only timestamps and
gateway correlation ids vary run-to-run. The mock always reports
`cache_read_input_tokens: 2048` / `cache_creation_input_tokens: 120`
(Anthropic wire) and `cached_tokens: 16` (Responses wire) so cache-aware
pricing is visible in evidence.

## Files

- `docker-compose.yml` — Talon (enforce mode) + dual-wire mock; vault seeded
  with fake keys inside the container.
- `talon.config.yaml` — one `claude-code` caller, `max_session_cost: 0.02`,
  `response_pii_action: allow` (the honest streaming default — see
  `LIMITATIONS.md`).
- `demo.sh` — the walk-through above; each step also runs standalone
  (`./demo.sh budget`).

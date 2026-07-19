# How to govern Claude Code with Talon

This guide shows how to route Claude Code's Anthropic API traffic through Talon so every request is audited, attributed per session and subagent, and policy-checked. Allow about 15 minutes.

One boundary up front, because it decides whether this guide applies to you: **Talon can only govern Claude Code when Claude Code authenticates with an API key, not a Claude subscription login.** Setting only `ANTHROPIC_BASE_URL` makes Claude Code send its subscription OAuth token, which Talon rejects as an unknown agent key. Governed operation is always *Talon agent key in, vault-stored provider key out*. See [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary).

## Prerequisites

- Talon installed (`go install github.com/dativo-io/talon/cmd/talon@latest` or `curl -sL https://install.gettalon.dev | sh`). On macOS, if `go install` fails with a linker error (e.g. `unsupported tapi file type`), use `CC=/usr/bin/clang go install ...@latest` or `make install` from a clone.
- Claude Code installed
- A real Anthropic API key (`sk-ant-...`) with billing set up — subscription-only accounts cannot be governed (see above)

## Steps

### 1. Install Talon and generate the coding-agents config

```bash
mkdir talon-coding && cd talon-coding
talon init --pack coding-agents
```

This creates four files:

- `agent.talon.yaml` — the **`claude-code` agent**: Claude Code's Talon traffic identity (`agent.key.secret_name: claude-code-talon-key`) plus its policy override with coding-tuned defaults — `session_limits.max_cost: 10.00`, `cost_limits.daily: 50.00` / `monthly: 500.00`, `input_scan: true` (input PII action `warn`), `allowed_providers: ["anthropic"]` — and high-precision credential recognizers (PEM private-key blocks, AWS `AKIA...` key IDs, GitHub `ghp_`/`github_pat_` tokens, Anthropic/OpenAI `sk-ant-...`/`sk-proj-...` keys) so leaked credentials in prompt traffic land in evidence.
- `agents/codex/agent.talon.yaml` — the `codex` agent for Codex CLI (see the [Codex guide](codex-cli-integration.md)). To serve both agents from one `talon serve`, set `agents_dir: "."` in `talon.config.yaml` (the pack ships it commented out): discovery (#267, shipped) loads every file named exactly `agent.talon.yaml` under it — provision both agents' keys first. Without `agents_dir`, `talon serve` runs the single default `agent.talon.yaml`.
- `talon.config.yaml` — gateway config with the Anthropic provider, the **organization baseline** (`organization_policy.defaults`: `pii_action: warn`, `response_pii_action: allow`), **shadow mode**, and a raised `request_timeout: 600s` (the response-header wait follows it by default).
- `pricing/models.yaml` — the LLM cost-estimation table (a copy of the embedded default). The relative `pricing_file` resolves against the active policy file's directory in single-file mode: in this guide's flow (policy at the project root) that's the project root, so edits work; in the Codex single-file flow (`TALON_DEFAULT_POLICY=agents/codex/...`) they are silently ignored — see the [Codex guide's pricing caveat](codex-cli-integration.md#5-verify).

These defaults are deliberate — see [Why the pack defaults look like this](#why-the-pack-defaults-look-like-this) below before changing them.

### 2. Set the vault key, store the real Anthropic key, mint the agent key

Talon encrypts secrets with `TALON_SECRETS_KEY`. Use the **same** value when storing the secrets and when starting the server, or the gateway returns "Service configuration error" / "cipher: message authentication failed".

```bash
# 1. Set the vault encryption key once; keep it for the next steps (save it somewhere safe)
export TALON_SECRETS_KEY=$(openssl rand -hex 32)

# 2. Store your real Anthropic key (secret name must match the config's secret_name)
talon secrets set anthropic-api-key "sk-ant-your-key"

# 3. Mint the claude-code agent's traffic key (bound via agent.key.secret_name);
#    keep $CLAUDE_CODE_KEY — Claude Code will present it to the gateway
CLAUDE_CODE_KEY="$(openssl rand -hex 24)"
talon secrets set claude-code-talon-key "$CLAUDE_CODE_KEY"

# 4. Start Talon with the gateway — same shell so TALON_SECRETS_KEY is still set
talon serve --gateway
```

**Vault-secret is the only upstream auth mode for the Anthropic API family.** There is no "pass the client's own key through" option: setting `upstream_auth_mode: client_bearer` on an anthropic-family provider is rejected at config load with:

```
gateway provider "anthropic": upstream_auth_mode client_bearer is not supported for the anthropic API family (Anthropic uses x-api-key, not bearer tokens)
```

(enforced in `internal/gateway/config.go`). Claude Code presents its agent key; Talon resolves it to the `claude-code` agent and injects the vault-stored provider key upstream. Your real `sk-ant-...` key never reaches developer machines.

**Three different keys (do not confuse):**

| Key | Purpose | Where it lives |
|-----|---------|----------------|
| **TALON_SECRETS_KEY** | Encrypts/decrypts the vault. Must be the **same** for `talon secrets set` and `talon serve`. | Environment. Set before the steps above. |
| **Agent key** (`$CLAUDE_CODE_KEY`) | Workload identity Claude Code sends to Talon; resolves to the `claude-code` agent and its derived tenant. Not used for encryption. | Vault secret `claude-code-talon-key` (referenced by `agent.key.secret_name`), and in Claude Code's environment as `ANTHROPIC_AUTH_TOKEN`. Rotate with `talon secrets set claude-code-talon-key <new>` + restart — one active key, never two. |
| **Provider key** (`sk-ant-...`) | Talon's upstream credential. | Vault secret `anthropic-api-key` only. |

### 3. Confirm the gateway is running

Leave `talon serve --gateway` running. Optional: test with curl (the agent key is accepted as `Authorization: Bearer` or as `x-api-key` — `extractKey` in `internal/gateway/resolve.go` checks both):

```bash
curl -s -X POST http://localhost:8080/v1/proxy/anthropic/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $CLAUDE_CODE_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-opus-4-8","max_tokens":32,"messages":[{"role":"user","content":"Say hi"}]}'
```

You should get a JSON completion, not "Invalid or missing agent key" (unknown key) or "Service configuration error" (vault key mismatch).

The Anthropic wire path — streaming SSE, cache-token accounting, `count_tokens` — is covered by conformance fixtures in `internal/gateway/conformance_anthropic_test.go` and `internal/gateway/testdata/conformance/anthropic/`. Note that `count_tokens` calls (Claude Code makes them constantly) are fully governed — PII-scanned, policy-checked, evidenced as `invocation_type: gateway_count_tokens` — but recorded at **cost 0** with zero budget impact: the endpoint is free at the provider, and a fabricated estimate would corrupt signed spend totals.

### 4. Point Claude Code at the gateway

Two environment variables:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080/v1/proxy/anthropic
export ANTHROPIC_AUTH_TOKEN=$CLAUDE_CODE_KEY
claude
```

`ANTHROPIC_AUTH_TOKEN` sends the agent key as `Authorization: Bearer ...`; `ANTHROPIC_API_KEY=$CLAUDE_CODE_KEY` also works, because the gateway accepts the agent key on either header (`internal/gateway/resolve.go`). If Talon runs on another host, replace `localhost:8080` accordingly.

**Important:**

- The token here is the Talon **agent key**, not your real Anthropic key. Talon resolves this key to the `claude-code` agent (and its derived tenant) and injects the vault-stored provider key upstream.
- **Setting only `ANTHROPIC_BASE_URL` does not work.** Without an explicit token, Claude Code sends its subscription OAuth token, which Talon rejects as an unknown agent key — you'll see authentication errors on every request. Subscription/OAuth billing cannot be governed; this is a hard boundary, not a configuration gap ([LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary)).
- Your real Anthropic key stays only in Talon's encrypted vault — Claude Code never sees it.

Claude Code's identity headers (`X-Claude-Code-Session-Id`, `X-Claude-Code-Agent-Id`, `X-Claude-Code-Parent-Agent-Id`) are recognized automatically by the built-in vendor adapter (`vendorAdapters` in `internal/gateway/orchmeta.go`) and recorded in signed evidence as orchestration metadata. Two honest caveats: values are **attribution, not authentication** — they are recorded with `provenance: "client_asserted"` and are never a policy input (budgets bind to the Talon agent and the agent-scoped session, never to subagent labels; backed by `TestPolicyInputParity_WithAssertedSession`). And header values are validated at ingestion: longer than 128 bytes or outside the HTTP token charset means the request is rejected, not truncated.

### 5. Verify

Run any prompt in Claude Code, then check the audit trail:

```bash
talon audit list
# Traffic for this agent only:
talon audit list --agent claude-code
```

Session-level views (all built on the same aggregation, `evidence.BuildSessionSummary`):

```bash
# Per-session summary + per-subagent rollup + the session's records
talon audit list --session <session-id>

# Per-session cost rollup, machine-readable
talon costs --session <session-id> --json

# Verify the HMAC signature of every record in a session
talon audit verify --session <session-id>
```

The dashboard (`talon serve` HTTP UI) shows the same data in the **Coding Sessions** panel.

**Troubleshooting**

- **Claude Code gets authentication errors on every request, but `claude` worked before** — You are logged in with a subscription and only set `ANTHROPIC_BASE_URL`. The subscription OAuth token is not an agent key and Talon rejects it. Set `ANTHROPIC_AUTH_TOKEN=$CLAUDE_CODE_KEY` (or `ANTHROPIC_API_KEY`) so Claude Code presents the agent key. [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary).
- **`talon serve --gateway` fails at startup after you edited the provider block** — If the error is the `upstream_auth_mode client_bearer is not supported for the anthropic API family` message quoted in step 2, remove `upstream_auth_mode: client_bearer`; vault-secret is the only supported mode for Anthropic.
- **`gateway_secret_get_failed` / "cipher: message authentication failed" / "Service configuration error"** — Vault decryption failed. Use the **same** `TALON_SECRETS_KEY` for `talon secrets set` and `talon serve`. If you lost it, set a new one and re-run `talon secrets set anthropic-api-key "sk-ant-..."`.
- **Long generations are cut off mid-response** — Your `request_timeout` is too low. The pack sets `600s` for exactly this reason; the server-wide default of `120s` hard-cuts long coding generations. The response-header wait defaults to `request_timeout` (tunable via `response_header_timeout`), so large non-streaming prompts get the same budget.
- **Streaming shows nothing for a long time, then everything at once** — A `response_pii_action` other than `allow` buffers the entire SSE stream before release; time-to-first-token becomes total generation time. Set the organization baseline back to `response_pii_action: allow` ([LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary)).
- **`talon audit list --session` finds nothing** — The session ID must match what Claude Code sent in `X-Claude-Code-Session-Id`. Check a recent record with `talon audit list --agent claude-code` and read the session ID from its orchestration metadata. Also note that orchestration header values over 128 bytes or containing non-token characters are rejected at ingestion (`internal/gateway/orchmeta.go`).

### 6. Session budgets

The pack sets a per-session spending cap in the agent file:

```yaml
policies:
  session_limits:
    max_cost: 10.00
```

This is a **soft cap**: a new request is denied once accrued session spend plus the pre-request estimate exceeds the limit. The denial is rendered in Anthropic's native error format so Claude Code displays it cleanly, with deny reason `session_budget_exceeded`, and the evidence record carries a structured `session_budget` detail (`limit`, `spent`, `estimate`) so you can see exactly why the deny fired.

Honest semantics, stated plainly ([LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary)): one in-flight request whose real cost exceeds its estimate can overshoot the cap, and N concurrent first requests are bounded only by N × per-request cost. Atomic reservation is tracked as #144. The behavior — including the overshoot and the concurrent-burst bound — is pinned by `TestSessionBudget_SoftCapOvershoot`, `TestSessionBudget_ConcurrentBurstBound`, and the rest of `TestSessionBudget_*` in `internal/gateway/session_budget_test.go`.

Session budgets stack with the agent's daily/monthly caps (`policies.cost_limits`), and sessions from one agent never affect another agent's budget (`TestSessionBudget_AgentAndTenantIsolation`).

### 7. Roll out enforcement

The generated config starts in `mode: "shadow"`: nothing is blocked, and every request that *would have been* denied is recorded as a shadow violation in signed evidence (`TestSessionBudget_ShadowMode` covers the session-budget case). Run in shadow until the dashboards look right, then:

```bash
# Review what would have been blocked
talon enforce report

# Flip to enforce mode
talon enforce enable
```

`talon enforce status` shows the current mode; `talon enforce disable` drops back to shadow.

---

## Why the pack defaults look like this

| Default | Reason |
|---|---|
| `response_pii_action: allow` (organization baseline) | Any other value (`warn`/`redact`/`block`) buffers the **entire** SSE stream before releasing it — time-to-first-token becomes total generation time, which is unusable for interactive coding. Input-side scanning (warn) still applies, and a per-agent downgrade to `allow` is deliberately not expressible. [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary). |
| Input PII action `warn` (`input_scan: true`, no redact), not `redact` | Redaction mangles code. `warn` records findings in evidence and lets the request flow. |
| `request_timeout: 600s` | The 120s default hard-cuts long coding generations. The response-header wait defaults to `request_timeout`, so slow non-streaming prompts are covered too. |
| `session_limits.max_cost` as a soft cap | Denies the *next* request over the limit rather than killing in-flight streams; see step 6 for the overshoot bounds. |
| Credential recognizers, not a secret scanner | The `agent.talon.yaml` recognizers cover high-precision formats only (PEM, `AKIA...`, `ghp_...`, `sk-ant-...`) in prompt/response traffic. Talon is not a repository secret scanner — keep gitleaks/trufflehog in pre-commit. |

## What Talon does not see

Talon governs **model API traffic**. Claude Code's local tool executions — file edits, shell commands, anything it does on the developer's machine — never transit the gateway. Evidence shows the model's tool_use *intentions*, not local execution results. Client-asserted session/subagent identity is attribution within an already-authenticated agent, not authentication of subagents. Both boundaries are documented in [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary).

---

## Failure mode → defense mapping

| Failure mode | Talon defense | Config / control |
|---|---|---|
| Developer routes Claude Code via Talon on a subscription login | Gateway rejects the OAuth token as an unknown agent key — ungoverned traffic cannot masquerade as governed | Agent-key auth required; [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary) |
| Real Anthropic key spread across developer laptops | Vault-stored key injected upstream; `client_bearer` rejected at config load for the anthropic family | `talon secrets set anthropic-api-key`, `providers.anthropic.secret_name` |
| Agent loop burns budget inside one session | Soft session cap denies the next request with `session_budget_exceeded` + structured `session_budget` evidence | `session_limits.max_cost` (`TestSessionBudget_*`) |
| Slow-burn overspend across sessions | Per-agent daily/monthly caps | `policies.cost_limits.daily` / `.monthly` |
| Credentials pasted into prompts (AWS keys, GitHub tokens, PEM blocks, `sk-ant-...`) | Input-side scan with high-precision recognizers; findings recorded in signed evidence | `agent.talon.yaml` `custom_recognizers`, input `warn` |
| Long generation hard-cut mid-stream | Raised coding timeouts | `request_timeout: 600s` (header wait follows it by default) |
| Subagent spend invisible in aggregate numbers | Per-agent rollup inside the session summary | `talon audit list --session` (`evidence.BuildSessionSummary`) |
| Hostile/oversized orchestration header values | Validated at ingestion: 128-byte cap, HTTP token charset, rejected not truncated; recorded as `client_asserted`, never a policy input | `internal/gateway/orchmeta.go`, `TestPolicyInputParity_WithAssertedSession` |
| Enforcement flipped on blind | Shadow mode records would-have-denied violations first | `mode: "shadow"`, `talon enforce report` / `enable` |
| Evidence tampering | HMAC-signed evidence chain, verifiable per session | `talon audit verify --session <id>` |

---

## Summary

| Before | After |
|---|---|
| Claude Code → Anthropic directly | Claude Code → Talon → Anthropic |
| Real API key on every laptop | Key in Talon's encrypted vault only |
| No central audit | Every request in `talon audit`, attributed per session and subagent |
| No cost controls | Session, daily, and monthly caps per agent |

---

## You're done

Claude Code now sends all Anthropic API traffic through Talon. Talon logs every request into signed evidence, attributes sessions and subagents, scans inputs for leaked credentials, and enforces (or shadow-records) session and agent budgets.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap spend per team or application | [How to cap daily spend per team or application](cost-governance-by-agent.md) |
| Export evidence for auditors | [How to export evidence for auditors](compliance-export-runbook.md) |
| Respond to a misbehaving agent | [Incident Response Playbook](incident-response-playbook.md) |
| Add another app through the gateway | [Add Talon to your existing app](add-talon-to-existing-app.md) |
| Understand the hard boundaries | [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary) |

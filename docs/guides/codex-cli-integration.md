# How to govern Codex CLI with Talon

This guide shows how to route Codex CLI's OpenAI traffic through Talon so every request is audited, attributed per session and subagent, and policy-checked. Allow about 15 minutes.

One boundary up front, because it decides whether this guide applies to you: **Talon can only govern Codex when Codex authenticates with an API key, not a ChatGPT subscription login.** Codex sends subscription OAuth tokens when `requires_openai_auth = true` is set on a provider — Talon rejects those as unknown tenant keys. Governed operation is always *tenant key in, vault-stored API key out*. See [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary).

Two wire facts shape everything below (verified 2026-07 against the `openai/codex` source; see the pin notes in `internal/gateway/testdata/conformance/responses/README.md`): Codex speaks the **OpenAI Responses API only** (`wire_api = "responses"`; the `"chat"` value was removed in Feb 2026), and Codex **always streams** — token usage arrives only inside the terminal `response.completed` SSE event, which Talon parses into signed cost evidence (`extractUsageFromJSONPayload` in `internal/gateway/forward.go`, pinned by `TestExtractUsage_ResponsesCompleted` in `internal/gateway/cache_pricing_test.go`, including `input_tokens_details.cached_tokens`).

## Prerequisites

- Talon installed (`go install github.com/dativo-io/talon/cmd/talon@latest` or `curl -sL https://install.gettalon.dev | sh`). On macOS, if `go install` fails with a linker error (e.g. `unsupported tapi file type`), use `CC=/usr/bin/clang go install ...@latest` or `make install` from a clone.
- Codex CLI installed
- A real OpenAI API key (`sk-...`) with billing set up — subscription-only accounts cannot be governed (see above)

## Steps

### 1. Install Talon and generate the coding-agents config

```bash
mkdir talon-coding && cd talon-coding
talon init --pack coding-agents
```

This creates two files (source of truth: `internal/pack/templates/coding-agents/`):

- `talon.config.yaml` — gateway config with the OpenAI provider, a pre-configured `codex` caller (tenant key `talon-gw-codex-001`), and a `claude-code` caller for Claude Code. The gateway starts in **shadow mode** and the caller ships with coding-tuned defaults: `pii_action: warn`, `response_pii_action: allow`, `max_session_cost: 10.00`, `max_daily_cost: 50.00`, `max_monthly_cost: 500.00`, and raised timeouts (`connect_timeout: 60s`, `request_timeout: 600s`).
- `agent.talon.yaml` — agent policy with high-precision credential recognizers (PEM private-key blocks, AWS `AKIA...` key IDs, GitHub `ghp_`/`github_pat_` tokens, Anthropic/OpenAI `sk-ant-...`/`sk-proj-...` keys) so leaked credentials in prompt traffic land in evidence.

These defaults are deliberate — see [Why the pack defaults look like this](#why-the-pack-defaults-look-like-this) below before changing them.

### 2. Set the vault key and store the real OpenAI key

Talon encrypts secrets with `TALON_SECRETS_KEY`. Use the **same** value when storing the secret and when starting the server, or the gateway returns "Service configuration error" / "cipher: message authentication failed".

```bash
# 1. Set the vault encryption key once; keep it for steps 2 and 3 (save it somewhere safe)
export TALON_SECRETS_KEY=$(openssl rand -hex 32)

# 2. Store your real OpenAI key (secret name must match the config's secret_name)
talon secrets set openai-api-key "sk-your-openai-key"

# 3. Start Talon with the gateway — same shell so TALON_SECRETS_KEY is still set
talon serve --gateway
```

Callers present a tenant key; Talon injects the vault-stored provider key upstream. Your real `sk-...` key never reaches developer machines.

**Two different keys (do not confuse):**

| Key | Purpose | Where it lives |
|-----|---------|----------------|
| **TALON_SECRETS_KEY** | Encrypts/decrypts the vault. Must be the **same** for `talon secrets set` and `talon serve`. | Environment. Set before steps 2 and 3 above. |
| **Caller tenant_key** (`talon-gw-codex-001`) | Token Codex sends to Talon as its "OpenAI API key". Not used for encryption. | `talon.config.yaml` → `gateway.callers[].tenant_key`, and in Codex's environment via the provider's `env_key` (step 4). |

### 3. Confirm the gateway is running

Leave `talon serve --gateway` running. Optional: test the Responses route with curl:

```bash
curl -s -X POST http://localhost:8080/v1/proxy/openai/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer talon-gw-codex-001" \
  -d '{"model":"gpt-5.3-codex","input":"Say hi"}'
```

You should get a JSON response, not "Invalid or missing API key" (wrong tenant key) or "Service configuration error" (vault key mismatch).

The Responses wire path — streaming SSE with tool calls, `client_metadata`/`prompt_cache_key` passthrough, full-transcript resend, `store` semantics — is covered by conformance fixtures in `internal/gateway/conformance_responses_test.go` and `internal/gateway/testdata/conformance/responses/`. The fixtures assert SSE streams reach the client **byte-identical including the terminal `response.completed` event** — Codex treats a stream that never ends with `response.completed` as an error and retries.

### 4. Point Codex CLI at the gateway

Edit `~/.codex/config.toml` and add a Talon provider plus a profile that uses it:

```toml
[model_providers.talon]
name = "Talon gateway"
base_url = "http://localhost:8080/v1/proxy/openai/v1"
wire_api = "responses"
env_key = "TALON_CODEX_KEY"

[profiles.talon]
model_provider = "talon"
model = "gpt-5.3-codex"
```

Then run Codex with the tenant key in the environment variable named by `env_key`:

```bash
export TALON_CODEX_KEY=talon-gw-codex-001
codex --profile talon
```

(Or set `model_provider = "talon"` at the top level of `config.toml` to make it the default instead of a profile.)

**Important:**

- **The trailing `/v1` in `base_url` is required.** Codex builds `POST {base_url}/responses`, and Talon's Responses handling matches the `/v1/responses` path (`isResponsesAPIPath` in `internal/gateway/responses_api.go`). Without it the joined path misses both Talon's Responses handling and OpenAI's endpoint — you get 404 on every request. Note: the pack wizard's printed next-steps currently omit the `/v1` (#235); use the value shown here.
- **Never set `requires_openai_auth = true` on the Talon provider.** That makes Codex send its ChatGPT-subscription OAuth token, which Talon rejects as an unknown tenant key. Subscription billing cannot be governed; this is a hard boundary, not a configuration gap ([LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary)).
- The value in `TALON_CODEX_KEY` is the Talon **tenant key**, not your real OpenAI key. Talon identifies the caller by this key and injects the vault-stored key upstream — Codex never sees your `sk-...` key.
- The Codex IDE extension reads the same `~/.codex/config.toml`, including `model_providers`, so this configuration governs it too (verified 2026-07 against the `openai/codex` source; re-verify on Codex majors per the recapture notes in `internal/gateway/testdata/conformance/responses/README.md`).

Codex's native identity headers (`session-id` for the session, `x-openai-subagent` for the subagent) are recognized automatically by the built-in `codex` vendor adapter (`vendorAdapters` in `internal/gateway/orchmeta.go`, pinned by the "codex vendor adapter" case in `TestResolveOrchestration_Precedence`) and recorded in signed evidence as orchestration metadata. Codex's `client_metadata` body object and `prompt_cache_key` are forwarded untouched — the `client_metadata_passthrough` conformance fixture asserts no transform drops them.

Two honest caveats: header values are **attribution, not authentication** — they are recorded with `provenance: "client_asserted"` and are never a policy input (budgets bind to the caller and the caller-scoped session, never to `agent_id`; backed by `TestPolicyInputParity_WithAssertedSession`). And header values are validated at ingestion: longer than 128 bytes or outside the HTTP token charset means the request is rejected, not truncated (`internal/gateway/orchmeta.go`).

**Optional — cross-tool session continuity:** to group Codex work into an orchestrator-chosen session (e.g. spanning Claude Code and Codex), inject the generic header from an environment variable:

```toml
[model_providers.talon]
# ... as above ...
env_http_headers = { "X-Talon-Session-ID" = "TALON_SESSION_ID" }
```

When `TALON_SESSION_ID` is set in Codex's environment, every request carries the generic session header, and generic beats the vendor `session-id` on conflict (`TestResolveOrchestration_Precedence`). See [Governing coding agents](governing-coding-agents.md) for the full contract.

### 5. Verify

Run any prompt in Codex, then check the audit trail:

```bash
talon audit list
# Traffic for this caller only:
talon audit list --agent codex
```

Session-level views (all built on the same aggregation, `evidence.BuildSessionSummary`):

```bash
# Per-session summary + per-agent (subagent) rollup + the session's records
talon audit list --session <session-id>

# Per-session cost rollup, machine-readable
talon costs --session <session-id> --json

# Verify the HMAC signature of every record in a session
talon audit verify --session <session-id>
```

The dashboard (`talon serve` HTTP UI) shows the same data in the **Coding Sessions** panel.

Because Codex always streams, cost figures depend on Talon parsing the usage block out of the terminal `response.completed` event — that parsing is shipped (`internal/gateway/forward.go`, `TestExtractUsage_ResponsesCompleted`); without it streamed cost would be estimate-only. One pricing caveat from [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary): a pricing entry without cache rates bills cache tokens at the full input rate (`pricing_basis: "cache_fallback_input_rate"`) — keep the pricing table current.

**Troubleshooting**

- **404 on every request** — The `base_url` is missing the trailing `/v1`. Codex appends `/responses`, so `.../v1/proxy/openai` becomes `.../v1/proxy/openai/responses`, which matches neither Talon's `/v1/responses` handling nor OpenAI's endpoint. Set `base_url = "http://localhost:8080/v1/proxy/openai/v1"` (#235).
- **Authentication errors on every request** — Either `TALON_CODEX_KEY` is unset in the shell running Codex (the `env_key` mechanism sends nothing), or the provider has `requires_openai_auth = true` and Codex is sending subscription OAuth, which Talon rejects. Remove `requires_openai_auth`, export the tenant key, restart Codex. [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary).
- **`gateway_secret_get_failed` / "cipher: message authentication failed" / "Service configuration error"** — Vault decryption failed. Use the **same** `TALON_SECRETS_KEY` for `talon secrets set` and `talon serve`. If you lost it, set a new one and re-run `talon secrets set openai-api-key "sk-..."`.
- **Long generations are cut off mid-response** — Your `request_timeout` is too low. The pack sets `600s`; the server-wide default of `120s` hard-cuts long coding generations. Note that `connect_timeout` currently doubles as the response-header wait budget (issue #230) — the pack's `60s` covers what the `10s` default would kill. Also note Codex itself aborts a stream that has been idle for ~300 seconds and retries; Talon cannot extend that client-side limit.
- **Streaming shows nothing for a long time, then everything at once** — A `response_pii_action` other than `allow` buffers the entire SSE stream before release; time-to-first-token becomes total generation time. Set the caller back to `response_pii_action: allow` ([LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary)).
- **A Responses client (not Codex) fails with "Item with id 'rs_...' not found. Items are not persisted when store is set to false"** — That client relies on `previous_response_id` continuity while sending `store: false` or no `store` field. Codex does not — it resends the full transcript each turn (`full_transcript_resend` conformance fixture). For clients that do, set `responses_store_mode: force_if_absent` on the provider (step 6).
- **`talon audit list --session` finds nothing** — The session ID must match what Codex sent in its `session-id` header. Check a recent record with `talon audit list --agent codex` and read the session ID from its orchestration metadata.

### 6. `store` semantics — respect Codex's retention decision

Codex sends `store: false` on every request (except Azure) and resends the full transcript each turn. `store: false` is a **retention decision**: the provider is being asked not to persist the conversation. Talon's handling is configured per provider:

```yaml
gateway:
  providers:
    openai:
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
      responses_store_mode: preserve   # default
```

| Mode | Behaviour | Use when |
|---|---|---|
| `preserve` **(default)** | Forwards the client's `store` field untouched; explicit `store: false` is honored, an absent field stays absent | Codex, and any client that manages its own transcript |
| `force_if_absent` | Injects `store: true` only when the client sent no `store` field; explicit `store: false` is still honored | Clients that need `previous_response_id` continuity (e.g. OpenClaw) |
| `force_true` | Reverses an explicit `store: false` — and records that in signed evidence (`gateway_annotations: ["responses_store_overridden"]`) | Only if you knowingly accept that the provider then retains data the client asked not to store |

All three modes are pinned end-to-end by `TestConformanceResponses_StoreModes` in `internal/gateway/conformance_responses_test.go`. For Codex, leave the default alone: `preserve` honors Codex's `store: false`, and Codex never uses `previous_response_id` over HTTP, so it loses nothing.

### 7. Session budgets

The pack sets a per-session spending cap on the `codex` caller:

```yaml
policy_overrides:
  max_session_cost: 10.00
```

This is a **soft cap**: a new request is denied once accrued session spend plus the pre-request estimate exceeds the limit — HTTP 403 with a provider-native error body (deny reason `session_budget_exceeded`), and the evidence record carries a structured `session_budget` detail (`limit`, `spent`, `estimate`).

Honest semantics, stated plainly ([LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary)): one in-flight request whose real cost exceeds its estimate can overshoot the cap, and N concurrent first requests are bounded only by N × per-request cost. Atomic reservation is tracked as #144. The behavior is pinned by `TestSessionBudget_SoftCapOvershoot`, `TestSessionBudget_ConcurrentBurstBound`, and the rest of `TestSessionBudget_*` in `internal/gateway/session_budget_test.go`.

Session budgets stack with the per-caller `max_daily_cost` and `max_monthly_cost` caps; session spend accumulates across provider routes for one caller (`TestSessionBudget_CrossProviderDeny`), and sessions from one caller never affect another caller's budget (`TestSessionBudget_CallerAndTenantIsolation`).

### 8. Roll out enforcement

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
| `response_pii_action: allow` | Any other value (`warn`/`redact`/`block`) buffers the **entire** SSE stream before releasing it — time-to-first-token becomes total generation time, and Codex always streams. Input-side scanning (`pii_action: warn`) still applies. [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary). |
| `pii_action: warn`, not `redact` | Redaction mangles code. `warn` records findings in evidence and lets the request flow. |
| `request_timeout: 600s`, `connect_timeout: 60s` | The 120s default hard-cuts long coding generations, and `connect_timeout` currently doubles as the response-header wait budget (issue #230). Codex additionally aborts idle streams at ~300s on its side. |
| `responses_store_mode: preserve` | Codex's `store: false` is an explicit retention decision; the gateway must not silently reverse it (`TestConformanceResponses_StoreModes`). |
| `max_session_cost` as a soft cap | Denies the *next* request over the limit rather than killing in-flight streams; see step 7 for the overshoot bounds. |
| Credential recognizers, not a secret scanner | The `agent.talon.yaml` recognizers cover high-precision formats only (PEM, `AKIA...`, `ghp_...`, `sk-ant-...`/`sk-proj-...`) in prompt/response traffic. Talon is not a repository secret scanner — keep gitleaks/trufflehog in pre-commit. |

## What Talon does not see

Talon governs **model API traffic**. Codex's local tool executions — file edits, shell commands, anything it does on the developer's machine — never transit the gateway. Evidence shows the model's tool-call *intentions*, not local execution results. Client-asserted session/subagent identity is attribution within an already-authenticated caller, not authentication of subagents. Both boundaries are documented in [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary).

---

## Failure mode → defense mapping

| Failure mode | Talon defense | Config / control |
|---|---|---|
| Developer routes Codex via Talon with `requires_openai_auth = true` (subscription OAuth) | Gateway rejects the OAuth token as an unknown tenant key — ungoverned traffic cannot masquerade as governed | Tenant-key auth via `env_key`; [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary) |
| Real OpenAI key spread across developer laptops | Vault-stored key injected upstream; clients only ever hold the tenant key | `talon secrets set openai-api-key`, `providers.openai.secret_name` |
| Gateway silently reverses Codex's `store: false` retention decision | Default `preserve` forwards it untouched; a `force_true` override is recorded in signed evidence (`responses_store_overridden`) | `responses_store_mode` (`TestConformanceResponses_StoreModes`) |
| Gateway transforms mangle Codex body shapes (`client_metadata`, `prompt_cache_key`, full-transcript resend) or the SSE stream | Conformance fixtures assert unknown fields forwarded untouched and streams delivered byte-identical incl. the terminal `response.completed` | `TestConformanceResponses_Fixtures`, `internal/gateway/testdata/conformance/responses/` |
| Streamed spend invisible (Codex always streams) | Usage parsed from the terminal `response.completed` event into signed cost evidence, incl. cached tokens | `internal/gateway/forward.go` (`TestExtractUsage_ResponsesCompleted`) |
| Agent loop burns budget inside one session | Soft session cap denies the next request with `session_budget_exceeded` + structured `session_budget` evidence | `max_session_cost` (`TestSessionBudget_*`) |
| Slow-burn overspend across sessions | Per-caller daily/monthly caps | `max_daily_cost`, `max_monthly_cost` |
| Credentials pasted into prompts (AWS keys, GitHub tokens, PEM blocks, `sk-...`) | Input-side scan with high-precision recognizers; findings recorded in signed evidence | `agent.talon.yaml` `custom_recognizers`, `pii_action: warn` |
| Long generation hard-cut mid-stream | Raised coding timeouts | `request_timeout: 600s`, `connect_timeout: 60s` (issue #230) |
| Subagent forges its identity | Attribution, not authentication: `provenance: "client_asserted"`, never a policy input; budgets bind to the caller | `TestPolicyInputParity_WithAssertedSession`; [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary) |
| Hostile/oversized orchestration header values | Validated at ingestion: 128-byte cap, HTTP token charset, rejected not truncated | `internal/gateway/orchmeta.go` |
| Enforcement flipped on blind | Shadow mode records would-have-denied violations first | `mode: "shadow"`, `talon enforce report` / `enable` |
| Evidence tampering | HMAC-signed evidence chain, verifiable per session | `talon audit verify --session <id>` |

---

## Summary

| Before | After |
|---|---|
| Codex CLI → OpenAI directly | Codex CLI → Talon → OpenAI |
| Real API key on every laptop | Key in Talon's encrypted vault only |
| No central audit | Every request in `talon audit`, attributed per session and subagent |
| No cost controls | Session, daily, and monthly caps per caller |
| No proof `store: false` survived the middlebox | Retention decision preserved by default; any override signed into evidence |

---

## You're done

Codex CLI now sends all OpenAI traffic through Talon. Talon logs every request into signed evidence, attributes sessions and subagents, parses streamed usage into cost evidence, preserves Codex's `store: false` retention decision, scans inputs for leaked credentials, and enforces (or shadow-records) session and caller budgets.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Govern Claude Code through the same gateway | [How to govern Claude Code with Talon](claude-code-integration.md) |
| Run an orchestrated fleet across both providers | [Governing coding agents](governing-coding-agents.md) |
| Cap spend per team or application | [How to cap daily spend per team or application](cost-governance-by-caller.md) |
| Export evidence for auditors | [How to export evidence for auditors](compliance-export-runbook.md) |
| Understand the hard boundaries | [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary) |

Conformance fixtures: #200 / PR #224.

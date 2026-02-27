# What Talon Does to Your Request

A technically precise, no-marketing explanation of every step Talon's gateway
performs on an HTTP request. Written for engineers who want to know exactly what
happens to their traffic.

## Request Lifecycle

When you send an HTTP request to `POST /v1/proxy/{provider}/v1/chat/completions`,
Talon runs a 10-step pipeline before returning the response. The request body
is forwarded to the upstream provider; Talon does not modify it in shadow mode.

```
Client                         Talon Gateway                    LLM Provider
  │                                  │                               │
  │  POST /v1/proxy/openai/v1/...   │                               │
  │─────────────────────────────────▶│                               │
  │                                  │  1. Route request             │
  │                                  │  2. Identify caller (<1ms)    │
  │                                  │  3. Rate limit check (<1ms)   │
  │                                  │  4. Extract model + text      │
  │                                  │  5. PII scan input (2-5ms)    │
  │                                  │  6. Classify data tier        │
  │                                  │  7. Policy eval / OPA (1-3ms) │
  │                                  │  8. Tool governance           │
  │                                  │  9. Redact (if enforcing)     │
  │                                  │                               │
  │                                  │  POST /v1/chat/completions    │
  │                                  │──────────────────────────────▶│
  │                                  │                               │
  │                                  │◀──────────────────────────────│
  │                                  │  Response                     │
  │                                  │                               │
  │                                  │  10. Response PII scan        │
  │                                  │  11. Evidence generation      │
  │                                  │  12. Cost tracking            │
  │◀─────────────────────────────────│                               │
  │  Response (byte-identical*)      │                               │
```

*In shadow mode, the response body is byte-identical to what the upstream
provider returned. In enforce mode with `pii_action: redact`, PII in the
response may be replaced.

## Step-by-Step Breakdown

### Step 1: Route Request

Talon examines the URL path to determine which upstream provider to use.
`/v1/proxy/openai/v1/chat/completions` routes to the OpenAI provider
configured in `talon.config.yaml`. The provider config specifies the upstream
base URL (e.g., `https://api.openai.com`).

- **Bytes read:** URL path only
- **Bytes modified:** None
- **Latency:** <1ms (string match)
- **On failure:** 404 if provider not configured

### Step 2: Identify Caller

Talon looks up the caller using the `Authorization: Bearer <key>` header.
The key is matched against the `callers` list in the gateway config. If
matched, the caller's name, tenant ID, team, and policy overrides are loaded.

- **Bytes read:** `Authorization` header
- **Bytes modified:** None
- **Latency:** <1ms (in-memory map lookup, timing-safe comparison)
- **On failure:** In enforce mode with `require_caller_id: true`, returns
  401. In shadow mode, continues with a `"default"` caller.

### Step 3: Rate Limit Check

A token-bucket rate limiter checks both global and per-caller request rates.
Configured via `rate_limits.global_requests_per_min` and
`rate_limits.per_caller_requests_per_min`.

- **Bytes read:** None (uses caller identity from step 2)
- **Bytes modified:** None
- **Latency:** <1ms
- **On failure:** 429 Too Many Requests (with `Retry-After` header)

### Step 4: Extract Model and Text

The JSON request body is parsed to extract the model name, message content,
and tool call names. This is provider-aware: OpenAI uses `messages[].content`,
Anthropic uses a different structure.

- **Bytes read:** Full request body (JSON parse)
- **Bytes modified:** None (the parsed body is used for scanning, the
  original bytes are forwarded)
- **Latency:** 1-2ms (JSON unmarshal)

### Step 5: PII Scan (Input)

The extracted text content is scanned for PII using regex-based recognizers
(email, phone, IBAN, credit card, VAT IDs, national IDs across 27 EU member
states). Each match returns a type, sensitivity level (1-3), and byte offset.

- **Bytes read:** Extracted message content
- **Bytes modified:** None at this stage
- **Latency:** 2-5ms (regex matching over message text)
- **Evidence recorded:** PII types found, count, sensitivity tiers

Validation: IBAN (MOD-97 + country-specific length), credit cards (Luhn
algorithm), Dutch BSN (11-test), Polish PESEL (check digit).

### Step 6: Classify Data Tier

Based on PII findings, the request is classified into a data tier (0 = public,
1 = internal, 2 = confidential). The highest-sensitivity PII finding determines
the tier.

- **Bytes read:** PII scan results
- **Bytes modified:** None
- **Latency:** <1ms (max over sensitivity scores)

### Step 7: Policy Evaluation (OPA)

The policy engine (embedded OPA/Rego, no sidecar) evaluates the request against
the caller's policy. Inputs include: model name, data tier, estimated cost,
daily cost accumulator, allowed models list.

Checks performed:
- Is the requested model in the caller's allowlist?
- Does the estimated cost exceed per-request/daily/monthly limits?
- Does the data tier exceed the model's allowed tier?
- Is the caller authorized for this provider?

- **Bytes read:** Extracted metadata (model, tier, cost estimate)
- **Bytes modified:** None
- **Latency:** 1-3ms (compiled Rego evaluation, no I/O)
- **On denial (enforce mode):** Returns a provider-native error response
  (e.g., OpenAI-format JSON with appropriate HTTP status)
- **On denial (shadow mode):** Logs the denial but forwards the request anyway

### Step 8: Tool Governance

If the request includes function/tool calls, Talon checks them against the
caller's allowed/forbidden tool lists. Tools matching `forbidden_tools` patterns
(including glob patterns like `admin_*`) are filtered out.

- **Bytes read:** Tool/function names from the parsed request
- **Bytes modified:** In enforce mode, forbidden tools may be stripped from
  the request body before forwarding
- **Latency:** <1ms

### Step 9: Redact (Enforce Mode Only)

If the policy action is `redact`, PII found in step 5 is replaced in the
request body before forwarding. Replacement preserves JSON structure. In shadow
mode this step is skipped entirely.

- **Bytes read:** Original request body + PII locations
- **Bytes modified:** PII tokens replaced with `[REDACTED:<type>]`
- **Latency:** <1ms

### Step 10: Forward to Upstream

The request is forwarded to the upstream provider URL. Talon creates a new HTTP
connection to the provider (it does not pass through the client's TLS session).

**Non-streaming:** The full response body is read, token usage is extracted
from the JSON `usage` field, and the response is written to the client.

**Streaming (SSE):** Talon detects `text/event-stream` in the response
`Content-Type` and enters streaming mode. SSE chunks are forwarded as received
using a `bufio.Scanner` with 512KB buffer. Each chunk is flushed immediately.
Token usage is extracted incrementally from `data:` lines. The client sees the
first token at the same time it would without Talon (minus the ~15ms pipeline
overhead on the initial request).

Headers forwarded to upstream: `Content-Type`, `Authorization` (replaced with
the real provider API key from the secrets vault). Headers forwarded to client:
`Content-Type`, `X-Request-Id`, rate-limit headers.

- **Latency:** Network RTT to provider (pass-through, no additional buffering
  for streaming responses)

### Step 11: Response PII Scan

For non-streaming responses, the LLM-generated content is extracted from the
response JSON (e.g., `choices[].message.content` for OpenAI) and scanned for
PII using the same recognizers as step 5.

For streaming responses, content is accumulated from SSE delta chunks and
scanned after the stream completes.

Actions on PII detection in response (configurable):
- `allow` — log only
- `warn` — log with elevated severity
- `redact` — rewrite response with PII replaced (non-streaming: JSON rewrite;
  streaming: buffer, redact, re-emit as SSE)
- `block` — return `503 Unavailable For Legal Reasons`

- **Bytes read:** Response body content
- **Bytes modified:** Only if `pii_action: redact` or `block`
- **Latency:** 2-5ms (non-streaming); streaming scan happens after final chunk

### Step 12: Evidence Generation and Cost Tracking

An evidence record is created and signed with HMAC-SHA256. The record includes:

| Field | Source |
|-------|--------|
| `id` | Generated (`req_` + UUID prefix) |
| `correlation_id` | From `X-Request-Id` or generated |
| `timestamp` | `time.Now()` |
| `tenant_id` | From caller config |
| `agent_id` | Caller name |
| `request_source_id` | Caller API key prefix |
| `policy_decision` | Allow/deny + reasons from step 7 |
| `classification.input_tier` | Data tier from step 6 |
| `classification.pii_detected` | PII types from step 5 |
| `classification.output_pii_detected` | PII types from step 11 |
| `execution.model_used` | Model from response |
| `execution.cost` | Calculated from token usage |
| `execution.tokens` | Input + output token counts |
| `execution.duration_ms` | End-to-end latency |
| `audit_trail.input_hash` | SHA-256 of request content |
| `audit_trail.output_hash` | SHA-256 of response content |
| `signature` | HMAC-SHA256 over all other fields |

The record is written to SQLite asynchronously (<1-2ms). Cost is added to the
caller's daily/monthly accumulator (in-memory counter, periodically flushed).

## Latency Budget

| Step | Operation | Typical Latency | Notes |
|------|-----------|----------------|-------|
| 1 | Route request | <1ms | String match on URL path |
| 2 | Identify caller | <1ms | In-memory map lookup |
| 3 | Rate limit check | <1ms | Token bucket |
| 4 | Extract model + text | 1-2ms | JSON unmarshal |
| 5 | PII scan (input) | 2-5ms | Regex over message content |
| 6 | Classify data tier | <1ms | Max over sensitivity scores |
| 7 | Policy evaluation | 1-3ms | Compiled Rego, no I/O |
| 8 | Tool governance | <1ms | List matching |
| 9 | Redact (enforce only) | <1ms | String replacement |
| 10 | Forward | Network RTT | No buffering for streams |
| 11 | Response PII scan | 2-5ms | Non-streaming only |
| 12 | Evidence + cost | 1-2ms | Async SQLite write + HMAC |
| **Total overhead** | | **<15ms** | **Excluding network RTT** |

## What Talon Does NOT Do

- **Does not modify request bodies in shadow mode.** The upstream provider
  receives exactly what your client sent. PII is scanned and logged but not
  altered.
- **Does not buffer streaming responses.** SSE chunks are forwarded to the
  client as they arrive from the provider. There is no full-response buffering
  for streaming requests.
- **Does not decrypt TLS to the upstream.** Talon terminates the client's
  HTTP connection and creates a new HTTPS connection to the provider. It does
  not act as a TLS-intercepting proxy.
- **Does not store prompt or response content by default.** Evidence records
  contain metadata (model, cost, PII types, hashes) but not the actual text.
  Content logging is opt-in via `log_prompts: true` / `log_responses: true`.
- **Does not phone home.** Talon sends no telemetry, analytics, or usage data
  to Dativo or anywhere else. OpenTelemetry export is configured by you and
  points where you choose.
- **Does not require an internet connection for policy evaluation.** OPA is
  embedded in the binary. Policies are evaluated locally.

## Streaming Behavior

SSE (Server-Sent Events) streaming works as follows:

1. Client sends request with `"stream": true`
2. Talon runs steps 1-9 (same as non-streaming)
3. Talon forwards the request to the upstream provider
4. Provider responds with `Content-Type: text/event-stream`
5. Each SSE chunk (`data: {...}\n\n`) is forwarded to the client immediately
   after Talon receives it, with an `http.Flusher.Flush()` call
6. Token usage is extracted from `data:` lines as they arrive (OpenAI includes
   usage in the final chunk; Anthropic uses `message_start`/`message_delta`)
7. After the stream completes (`data: [DONE]`), response PII scanning runs on
   the accumulated content
8. Evidence is generated with the full token counts

The client sees the first token at the same latency as a direct connection to
the provider, minus the ~15ms pipeline overhead on the initial request.

## Source Code

The gateway pipeline implementation lives in these files:

| File | Responsibility |
|------|---------------|
| `internal/gateway/gateway.go` | Main `ServeHTTP` handler — 10-step pipeline |
| `internal/gateway/router.go` | Provider routing from URL path |
| `internal/gateway/caller.go` | Caller identification from API key |
| `internal/gateway/forward.go` | HTTP forwarding + SSE streaming |
| `internal/gateway/response_pii.go` | Response PII scanning |
| `internal/gateway/tool_filter.go` | Tool governance / filtering |
| `internal/gateway/ratelimit.go` | Token-bucket rate limiting |
| `internal/gateway/attachment.go` | Attachment extraction + injection scanning |
| `internal/classifier/scanner.go` | PII regex recognizers |
| `internal/evidence/store.go` | Evidence storage + HMAC signing |
| `internal/evidence/generator.go` | Evidence record creation |

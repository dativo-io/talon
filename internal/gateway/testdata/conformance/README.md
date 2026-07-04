# Gateway protocol conformance fixtures

Recorded request/response shapes replayed through the **full** gateway pipeline
(extraction → PII scan/redaction → tool governance → forward → evidence) by
`conformance_anthropic_test.go`. No live provider calls in CI.

## Fixture schema

```json
{
  "name": "unique_snake_case_name",
  "path": "/v1/messages",                    // appended to /v1/proxy/anthropic
  "caller_pii_action": "warn" | "redact",    // selects the test caller
  "request_body": { ... },                   // raw provider-wire request
  "upstream": {
    "status": 200,
    "json": { ... }                          // OR "sse_events": ["event: ...\ndata: {...}", ...]
  },
  "expect": {
    "status": 200,
    "forwarded_contains": ["..."],           // substrings of the body that reached the upstream
    "forwarded_not_contains": ["..."],
    "forwarded_json_valid": true,
    "response_equals_upstream": true,        // byte-identical passthrough (SSE) / JSONEq (non-stream)
    "evidence": {                            // all optional
      "input_tokens": 0, "output_tokens": 0,
      "cost_zero": false,
      "invocation_type": "..."
    }
  }
}
```

Assertions not expressible in the schema live as dedicated Go tests in
`conformance_anthropic_test.go` (transform determinism, ~50KB system prompt —
the large prompt is generated with `strings.Repeat`, not stored).

## Sanitization rules (enforced in review)

- **No real credentials.** Keys look like `sk-ant-test-000-*`.
- **No real PII.** Emails come from the test corpus (`*@example.com`) only.
- Upstream response IDs are synthetic (`msg_conf_*`).

## Provenance and recapture

Last verified against: **Claude Code v2.1.x (2026-07)** — fixtures hand-authored
from the Anthropic Messages API reference and the Claude Code LLM gateway
protocol docs (code.claude.com/docs/en/llm-gateway-protocol.md), then verified
once against a live endpoint by the author.

To recapture against current client/provider versions:

```
RECORD=1 ANTHROPIC_API_KEY=... scripts/record-conformance-fixtures.sh
```

then sanitize per the rules above and update the version line here. Client
protocol drift (renamed headers, new usage fields) is expected — recapture on
every Claude Code major and on any Anthropic API version bump.

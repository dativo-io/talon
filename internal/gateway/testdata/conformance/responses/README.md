# OpenAI Responses API conformance fixtures (Codex CLI)

Recorded Codex-CLI-shaped request/response shapes replayed through the full
gateway pipeline by `conformance_responses_test.go`. Codex speaks the OpenAI
Responses API (`/v1/responses`), Responses-only — `wire_api = "chat"` was
removed in Feb 2026. No live provider calls in CI.

## Fixture schema

Same envelope as the Anthropic suite (see `../anthropic/README.md`), minus the
`path` field (Responses fixtures always POST `/v1/proxy/openai/v1/responses`):

```json
{
  "name": "...",
  "caller_pii_action": "warn" | "redact",
  "request_body": { ... },                     // raw Codex Responses request
  "upstream": { "status": 200, "json": {...} } // OR "sse_events": ["event: response.created\ndata: {...}", ...]
  "expect": { "status", "forwarded_contains", "forwarded_not_contains", "forwarded_json_valid", "response_equals_upstream" }
}
```

The `responses_store_mode` matrix (`preserve` / `force_if_absent` /
`force_true`) is covered by dedicated Go subtests, not fixtures.

## Codex facts (verified 2026-07 against the `openai/codex` source)

- **Responses-only.** `wire_api = "responses"` is the only value; `"chat"` is
  removed.
- **Native correlation.** Codex sends `session-id` / `thread-id` headers and a
  body `client_metadata` object (`session_id`, `thread_id`, `turn_id`, …) plus
  `prompt_cache_key` = the thread UUID. The gateway must forward these unknown
  body fields untouched — fixtures assert that.
- **`store: false` everywhere except Azure.** Codex resends the full transcript
  each turn and does not use `previous_response_id` over HTTP; the gateway's
  `responses_store_mode` defaults to `preserve` so that intent is honored
  (#213).
- **SSE terminated by `response.completed`.** A stream that never ends with
  `response.completed` is an error Codex retries; fixtures assert byte-identical
  passthrough including the terminal event. Usage (with
  `input_tokens_details.cached_tokens`) arrives inside `response.completed` —
  parsing it into evidence cost is PR-E / #196, not this suite.

## Sanitization & recapture

Synthetic keys (`sk-test-000-*`), `*@example.com` corpus emails only, synthetic
response IDs (`resp_conf_*`). Last verified against Codex CLI (2026-07),
hand-authored from the `openai/codex` source and the OpenAI Responses API
reference; recapture with a logging proxy in front of `api.openai.com` and
sanitize per these rules. Re-pin on every Codex major.

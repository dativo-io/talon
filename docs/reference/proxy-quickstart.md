# Reference: proxy quickstart

`talon serve --proxy-quickstart` enables a dev/local OpenAI-compatible host-root proxy.

## Scope

Supported host-root endpoints:

- `POST /v1/chat/completions`
- `POST /v1/responses`

Unsupported in quickstart host-root mode:

- `POST /v1/embeddings`
- `GET /v1/responses/{id}`
- `DELETE /v1/responses/{id}`

Unsupported paths return `404` with a partial-compatibility message.

## Flags

| Flag | Meaning |
|---|---|
| `--proxy-quickstart` | Enable quickstart mode. |
| `--unsafe-listen` | Allow non-loopback bind with quickstart mode. |
| `--host` | Host/IP for bind. Loopback only unless `--unsafe-listen`. |
| `--port` | Listen port. |

## Environment variables

| Variable | Meaning |
|---|---|
| `OPENAI_API_KEY` | Upstream fallback when caller bearer is absent. |
| `TALON_QUICKSTART_OPENAI_BASE_URL` | Upstream OpenAI-compatible base URL. |
| `TALON_QUICKSTART_MODE` | Set to `shadow` to opt into shadow mode; any other value uses default `enforce`. |
| `TALON_QUICKSTART_ALLOW_ALL_MODELS` | `1/true` clears quickstart model allowlist. |

## Auth model

Quickstart uses upstream BYOK as a scoped exception:

- Caller `Authorization: Bearer <key>` is forwarded to upstream.
- If missing, Talon tries `OPENAI_API_KEY`.
- If neither exists, request fails with `401`.

## Governance defaults

- Enforcement mode: `enforce`.
- PII default action: `redact`.
- Default model allowlist: `gpt-4o-mini`, `gpt-4o` (use `TALON_QUICKSTART_ALLOW_ALL_MODELS=1` to disable for local-only experiments).
- Evidence includes `upstream_auth_mode`, `upstream_key_source`, `upstream_key_fingerprint`, and optional `gateway_annotations` (e.g. `quickstart_mode`, `quickstart_shadow_mode`, `quickstart_model_allowlist_disabled`, `quickstart_unsafe_listen`).

## Live operational feed

Quickstart traffic is projected into the same operational feed used by the dashboard and CLI:

- `GET /api/v1/events/recent?limit=50`
- `GET /api/v1/events/stream` (SSE, supports `Last-Event-ID`)

Each event includes an `evidence_id` pointer to the signed evidence record.

## Common errors

- `401` with `no upstream credential: set OPENAI_API_KEY or send Authorization: Bearer ...` means Talon received neither a client bearer key nor a usable `OPENAI_API_KEY`.
- `404` with `partial OpenAI compatibility in quickstart mode; see docs` means the requested `/v1/*` path is outside quickstart scope.

## Tenant auth boundary

Quickstart is strictly a host-root OpenAI-compatibility facade backed by a synthetic in-process identity. It does **not** register a synthetic agent key and does **not** unlock Talon's tenant-auth surface.

The relocated tenant agent chat route `POST /v1/agents/chat/completions` is only mounted when the operator has configured real agent keys (for example through a keyed agent policy). In default quickstart (no agent keys), this route is not mounted at all and returns `404 Not Found`, preserving a clean facade-only boundary and avoiding any dev-mode-open backdoor to tenant APIs. When agent keys are configured, the relocated route sits behind standard tenant-auth middleware and returns `401 Unauthorized` without a valid key.

## Bind safety

- `--host` omitted: binds to `127.0.0.1:<port>`.
- Loopback hosts (`127.0.0.1`, `::1`, `localhost`): allowed.
- Non-loopback host without `--unsafe-listen`: startup error.

## Mutual exclusivity

`--proxy-quickstart` cannot be used with:

- `--gateway`
- `--gateway-config`

Use `--gateway` for production-style caller mapping and vaulted provider auth.

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
| `TALON_QUICKSTART_MODE` | `shadow` to opt into shadow mode (default `enforce`). |
| `TALON_QUICKSTART_ALLOW_ALL_MODELS` | `1/true` clears quickstart model allowlist. |

## Auth model

Quickstart uses upstream BYOK as a scoped exception:

- Caller `Authorization: Bearer <key>` is forwarded to upstream.
- If missing, Talon tries `OPENAI_API_KEY`.
- If neither exists, request fails with `401`.

## Governance defaults

- Enforcement mode: `enforce`.
- PII default action: `redact`.
- Evidence includes `upstream_auth_mode`, `upstream_key_source`, `upstream_key_fingerprint`, and optional `gateway_annotations` (e.g. `quickstart_mode`, `quickstart_shadow_mode`, `quickstart_model_allowlist_disabled`, `quickstart_unsafe_listen`).

## Tenant auth boundary

Quickstart is strictly a host-root OpenAI-compatibility facade backed by a synthetic in-process caller. It does **not** register a synthetic tenant key and does **not** unlock Talon's tenant-auth surface. Tenant endpoints such as the relocated `POST /v1/agents/chat/completions` still require a real tenant key configured by the operator; without it, those routes return `401 Unauthorized` as expected from Talon's normal auth middleware.

## Bind safety

- `--host` omitted: binds to `127.0.0.1:<port>`.
- Loopback hosts (`127.0.0.1`, `::1`, `localhost`): allowed.
- Non-loopback host without `--unsafe-listen`: startup error.

## Mutual exclusivity

`--proxy-quickstart` cannot be used with:

- `--gateway`
- `--gateway-config`

Use `--gateway` for production-style caller mapping and vaulted provider auth.

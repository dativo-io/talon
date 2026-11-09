# Console process and browser access

The operations console (#533) is **its own process**: `talon ui` / `talon ui serve` read the installation's store read-only and serve the embedded console app plus the read API of [the console read contract](console-read-contract.md). This page is the contract of that process (#536) and of how a browser gets in (#537). Nothing here changes how `TALON_ADMIN_KEY`, agent keys or approver credentials work on the data plane.

## The process (#536)

| Command | What it does |
|---|---|
| `talon ui` | Starts the console on `127.0.0.1:8787`, prints a one-time pairing code to the terminal, opens the browser on the console page (`--no-browser` to skip). Blocks until interrupted. |
| `talon ui serve` | The headless form: same process without the browser; Docker Compose runs it as the `talon-ui` service. |
| `talon ui pair` | Asks the running console (found through its pid file, default `<data_dir>/console.pid`, or `--pid-file`) to void the current code and print a fresh one **to its own output**. The code never appears in `talon ui pair`'s output. |

Resolution is fail-closed and creates nothing:

- the configuration is the ordinary one (`--config`, `TALON_*` environment, `talon.config.yaml`); `data_dir` must exist, otherwise the process exits with `no Talon installation at <dir>` and nothing listens;
- the evidence store must exist and carry the data plane's schema; the process waits up to `--store-wait` (default 30 s, for a Compose stack where `talon` is still starting) and then exits with `start 'talon serve' for this installation first`;
- the store is opened `mode=ro` (`evidence.OpenReadOnly`, `session.OpenReadOnly`): no schema statement, migration or write can run through the console's connection, and a live writer is never blocked;
- the fleet view is the offline projection `talon agents` uses (`agents_dir` / `default_policy` and the gateway config named by `--gateway-config`, `TALON_GATEWAY_CONFIG` or `talon.config.yaml`); amounts are in the active pricing table's currency;
- the listener refuses a non-loopback address unless `--allow-non-loopback` is given (a container needs it to publish its port; the Compose files publish it to `127.0.0.1:8787` on the host). Nothing in the process terminates TLS: a remote-reachable console belongs behind a TLS terminator with `--secure-cookie` and `--allowed-host <public name>`.

The process holds no provider key, admin key or secrets key. It needs the evidence signing key only to verify the signatures it shows (`TALON_SIGNING_KEY`, the same value as the data plane; both default to the derived key when unset). Restarting or stopping the console restarts nothing else: `TestE2E_ConsoleUI_PairingReadOnlyProcess` kills the console while a governed request goes through the gateway, and `scripts/console-compose-smoke.sh` restarts the `talon-ui` service and checks the data plane's health across it.

Flags: `--listen host:port`, `--allow-non-loopback`, `--allowed-host name[:port]` (repeatable), `--secure-cookie`, `--code-ttl` (≤ 10m), `--session-ttl` (default 8h), `--session-idle` (default 1h), `--store-wait`, `--pid-file`, `--gateway-config`.

## Browser access (#537)

1. **Pairing code.** On start (and on every `talon ui pair` or `SIGUSR1`) the process prints one code to its stdout, in the form `XXXXX-XXXXX-XXXXX-XXXXX` over a 30-symbol alphabet (about 98 bits), together with its expiry. Only its SHA-256 stays in memory. A code is **single use**, expires after `--code-ttl` (at most ten minutes), is voided after five failed attempts, and attempts closer than 500 ms apart are answered `429 pairing_throttled` without being counted. Issuing a code voids the previous one; existing browser sessions are unaffected.
2. **Exchange.** The app posts the code as JSON to `POST /console/auth/pair`. The request must be same-origin: `Sec-Fetch-Site` (when present) must be `same-origin` or `none`; `Origin` (when present) must equal the request's own origin **exactly**, scheme, host and port (`http://<Host>`, or `https://<Host>` under TLS or `--secure-cookie`), so an allowed-host alias (`localhost` for `127.0.0.1`), another scheme or another port is refused; and the body must be declared `application/json` (an HTML form cannot send that). Anything else is `403 cross_origin_rejected` and does not count as an attempt.
3. **Session.** Success mints a 256-bit opaque id, tracked server-side with an absolute lifetime (`--session-ttl`) and an idle timeout (`--session-idle`), bounded to 32 live sessions, and sets it as the cookie `talon_console_session`: `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` under TLS or `--secure-cookie`. The cookie value is the id and nothing else; no pre-existing cookie is ever adopted (no fixation). Sessions live in the console's memory: a console restart forgets them and operators pair again.
4. **Reads.** Every `GET /console/v1/*` route validates the cookie server-side on each request; without a live session the answer is `401 console_session_required`. `POST /console/auth/logout` revokes the session server-side and clears the cookie. `GET /console/auth/session` says whether the browser is paired. `GET /healthz` is liveness only.
5. **Host check.** Every request's `Host` must be one of the loopback names on the listen port, the concrete listen host, or an `--allowed-host`; otherwise `421 host_not_allowed`. This defeats DNS rebinding (a hostile page resolving its own name to `127.0.0.1`).
6. **Headers.** Every response carries `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; … frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`; `/console/*` responses are `Cache-Control: no-store`. The app has no inline script or style.

### What the browser credential can reach

Only the console process, and only reads. The process has **no** `/v1/*`, `/api/v1/*`, `/mcp*` or legacy dashboard route: `/v1/secrets`, `/v1/runs/*`, `/v1/policies/*`, approval decisions, `/v1/agents/run` and every other data-plane path are `404` there, with or without a cookie (`TestServer_NoPrivilegedRouteExists`). Write verbs on `/console/v1/*` are `405`. On the data plane, the console cookie is not a carrier the admin middleware reads (`TestAdminKey_QueryAndCookieNoLongerAuthenticate`), so a stolen read-only session cannot become an admin call. No key or code is placed in a URL, in the DOM, in `localStorage` or in the cookie value.

### Threat model, stated plainly

- **Whoever can read the console's log can pair.** `docker compose logs talon-ui` and the terminal running `talon ui` are the trust boundary; do not forward that stream to a shared or central log system, and reissue (`talon ui pair`) after an unintended exposure, which voids the earlier code. Restarting the process rotates the code too.
- **A paired browser reads what the CLI reads** for the installation (same redaction, same scoping rules as `talon agents/costs/session/audit --json`), not more.
- **Loopback is the default exposure, for the data plane too.** The default and demo Compose files publish the console **and** the data-plane API on the host's `127.0.0.1` only; anyone with a shell on that host and the log can pair, which is the same trust the CLI already grants them. The data-plane API is development-open when `TALON_ADMIN_KEY` is unset, and console pairing does nothing for it: pairing secures the console process, not `/v1/*`. To expose the API, set `TALON_ADMIN_KEY` and change the port binding deliberately; the production stack (`deploy/docker-compose/full.yml`), which publishes on every interface, refuses to start without the key. `TestCompose_DefaultStacksPublishToLoopbackOnly` and `TestCompose_ProductionStackRequiresAdminKey` pin this; the Compose smoke asserts both port scopes on the running stack.
- **No TLS inside the process.** Remote exposure needs a terminator in front, `--secure-cookie`, and `--allowed-host`.
- **Not covered here:** approval decisions and any write to configuration, budgets, agents or secrets (none exist in the console), multi-user roles (Enterprise scope), and the runtime probe (#538: the Runtime sections stay `unknown`).

## Verification

| Test | Proves |
|---|---|
| `go test ./internal/console/access` | code shape and entropy; single use, expiry, exhaustion, throttle; session TTL, idle, bound, revoke; cookie attributes; host, origin, `Sec-Fetch-Site` and content-type rejections; brute-force path |
| `go test ./internal/console/server` | listener policy; app document and `/healthz` open, read API gated; code printed exactly once and never echoed; no privileged route exists with or without a cookie |
| `go test ./internal/server -run TestAdminKey_QueryAndCookieNoLongerAuthenticate` | the console cookie authenticates nothing on the data plane |
| `make test-console-smoke` (`TestE2E_ConsoleUI_PairingReadOnlyProcess`, real binary) | fail-closed starts (no installation, no store, non-loopback), pairing from the printed code, CLI/console parity, 404 on privileged paths, reissue via `talon ui pair`, logout, restart independence, store readable with the data plane stopped |
| `make test-console-compose-smoke` (Docker, CI Docker job) | `talon-ui` **and** the data plane published on `127.0.0.1` only; pairing from `docker compose logs`; reissue via `docker compose exec`; console restart leaves the data plane healthy; no key in the console log |
| `go test ./tests -run TestCompose` | every port of the default and demo stacks is bound to `127.0.0.1`; the network-published production stack requires `TALON_ADMIN_KEY` |
| `make test-browser-console` (Playwright/Chromium, CI job `browser`, `tests/browser/`) | a real browser against the packaged shell from the built binary: wrong code shows the server's reason and sets no cookie; pairing with the logged code stores an `HttpOnly` `SameSite=Strict` cookie invisible to script, renders the connected panel from `/console/v1/system`, leaves no code in the URL, document or `localStorage`; the spent code is refused; a cross-origin page gets no read; logout clears the cookie and the server session; the log holds the code exactly once |

The browser job runs in CI on every PR; it needs Node and a Chromium download, so it does not run on hosts without them.

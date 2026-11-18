# Upgrading from v1.16 to v1.17

v1.17 replaces both legacy browser dashboards with the read-only [operations console](operations-console.md), removes the dashboard-only API, and closes one fail-open start-up path. It is a minor release with documented breaking changes for browser users and `/v1/dashboard/*` scripts. Everything else is additive. The full list is in [CHANGELOG.md](../../CHANGELOG.md).

## Before you upgrade

1. **Back up the data directory** (`~/.talon`, or the `talon-data` Compose volume): `evidence.db`, `sessions.db`, `secrets.db` and their `-wal`/`-shm` files, with the processes stopped. v1.17 only adds an index and a `runtime/` directory, but returning to v1.16 after v1.17 has written to the stores has not been tested. Treat a restore of this backup as the rollback path.
2. **Keep the same `TALON_SECRETS_KEY` and `TALON_SIGNING_KEY`.** A different secrets key makes the vault undecryptable (see the security change below), and a different signing key makes existing evidence fail verification.

## Breaking changes and what to do

| Change | Action |
|---|---|
| `/`, `/dashboard`, `/gateway/dashboard` and `GET /v1/dashboard/*` return `404` (no redirect) | Use the operations console (below). For scripts, the per-widget replacement and remaining gaps are in the [legacy dashboard migration map](../reference/legacy-dashboard-migration-map.md). |
| The admin key is accepted only in `X-Talon-Admin-Key` or `Authorization: Bearer` | Replace any `?talon_admin_key=` or `?token=` URL, and any reliance on the `talon_admin_session` cookie, with the header. |
| `talon serve --dashboard` and `gateway.dashboard_listen` are removed | Drop the flag; delete the key from `talon.config.yaml` (config loading fails with a migration error that names it). |
| `talon metrics` no longer falls back to local numbers after a server error | Set `TALON_ADMIN_KEY` when the server requires it, or pass `--url ""` for the local projection. |
| Compose publishes `8080` on `127.0.0.1` only; `deploy/docker-compose/full.yml` refuses to start without `TALON_ADMIN_KEY` | Set `TALON_ADMIN_KEY` in `.env` before exposing the API to a network, and change the binding deliberately. |
| **Security:** a declared agent key that cannot be resolved (undecryptable, ACL-denied, unreadable vault) stops `talon serve` from starting, instead of serving without that key | Restore the original `TALON_SECRETS_KEY`, or re-mint the key with `talon secrets set`. A key that was never minted still leaves plain `talon serve` development-open when `TALON_ADMIN_KEY` is unset ([LIMITATIONS.md](../../LIMITATIONS.md)). |

## Start the console

The console is its own process with its own port (`127.0.0.1:8787`). It holds no provider, admin, vault or agent key.

- **Compose:** the `talon-ui` service starts with the stack. Read the one-time pairing code with `docker compose logs talon-ui`, open `http://127.0.0.1:8787/` and enter it. Reissue a code with `docker compose exec talon-ui talon ui pair`.
- **Binary:** `talon ui serve` prints the code; `talon ui` also opens the browser.

**Volume mounts:** the console opens the stores through a read-only SQLite connection, but SQLite's WAL mode needs the reader to create the shared-memory file. Mount the data volume **read-write** at the filesystem level, as `examples/docker-compose` does. A read-only mount (`:ro`) is not supported. Details: [console access](../reference/console-access.md).

**Signing key:** the console verifies evidence signatures. Give the console the same `TALON_SIGNING_KEY` as the data plane, or leave it unset on both.

## Run the published image instead of building

`examples/docker-compose` builds both Talon services from the checkout by default. To run the published release image, pulled anonymously from GHCR:

```bash
cd examples/docker-compose
TALON_IMAGE=ghcr.io/dativo-io/talon:<version> TALON_PULL_POLICY=always docker compose up
```

Only the stack's mock provider is built locally. The same image runs both the data plane and the console.

## Verify the upgrade

```bash
talon version                       # Talon <version>
talon audit list --limit 5          # existing evidence still listed
talon audit verify <evidence-id>    # existing evidence still verifies with your signing key
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/dashboard   # 404
```

Then pair the console and check that the **System** page shows your running processes and the **Overview** reads the traffic you already had.

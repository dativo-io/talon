# Upgrading from v1.16 to v1.17

v1.17 replaces both legacy browser dashboards with the read-only [operations console](operations-console.md), removes the dashboard-only API, and closes one fail-open start-up path. It is a minor release with documented breaking changes for browser users and `/v1/dashboard/*` scripts. Everything else is additive. The full list is in [CHANGELOG.md](../../CHANGELOG.md).

## Before you upgrade

The supported backup is a **cold** one: taken with the Talon processes stopped. Restoring it is the rollback path.

1. **Stop every Talon process of the installation**: `talon serve` (LLM gateway, MCP proxy, Action Gateway) and, if one runs, `talon ui`. With Compose: `docker compose stop` (do not use `down -v`, which deletes the data volume). A copy taken while a process writes can be inconsistent.
2. **Back up the persistent state**: the whole data directory (`~/.talon`, or the `talon-data` Compose volume), including `evidence.db`, `sessions.db`, `secrets.db` and any `-wal`/`-shm` files beside them.
3. **Back up the deployment and policy configuration** you run with: `talon.config.yaml`, the agent files (`agent.talon.yaml`, or the `agents_dir` tree), the MCP proxy config if you use one, your pricing table if you changed it, and the Compose file, environment file or service unit that starts Talon.
4. **Preserve the signing key and the vault key** (`TALON_SIGNING_KEY`, `TALON_SECRETS_KEY`) the way you already keep them, in your secret manager or protected environment file. Do not copy them in clear text into the backup of the data directory. Without the same vault key the vault is undecryptable (see the security change below); without the same signing key existing evidence fails verification. Leaving both unset before and after (the derived default, as in the demo stack) is also "the same key".
5. Upgrade, then start the processes again.

**Rollback is a restore**: stop the processes, put back the data directory and configuration from this backup, and start the previous version with the same keys. v1.17 only adds an index and a `runtime/` directory, but running a v1.16 binary on stores that v1.17 has written to has **not been tested**; do not treat a binary downgrade in place as a supported rollback.

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

- **Compose:** the `talon-ui` service starts with the stack. Read the one-time pairing code with `docker compose logs talon-ui`, open `http://127.0.0.1:8787/` and enter it. `docker compose exec talon-ui talon ui pair` makes the running console print a fresh code to its own output: read it with `docker compose logs talon-ui` again (the `pair` command itself prints no code).
- **Binary:** `talon ui serve` prints the code; `talon ui` also opens the browser. `talon ui pair` (in another terminal) makes that running process print a fresh code in its own terminal.

Keep the console's output out of shared or central logging systems: whoever reads a valid pairing code can pair. Pairing secures the console only; it does nothing for the data-plane API on port 8080 ([console access](../reference/console-access.md)).

**Volume mounts:** the console opens the stores through a read-only SQLite connection, but SQLite's WAL mode needs the reader to create the shared-memory file. Mount the data volume **read-write** at the filesystem level, as `examples/docker-compose` does. A read-only mount (`:ro`) is not supported. Details: [console access](../reference/console-access.md).

**Signing key:** the console verifies evidence signatures. Give the console the same `TALON_SIGNING_KEY` as the data plane, or leave it unset on both.

## Run the published image instead of building

`examples/docker-compose` builds both Talon services from the checkout by default. To run a published release image, pulled anonymously from GHCR, add the override file:

```bash
cd examples/docker-compose
TALON_IMAGE=ghcr.io/dativo-io/talon:<version> \
  docker compose -f docker-compose.yml -f docker-compose.published.yml up
```

Only the stack's mock provider is built locally. The same image runs both the data plane and the console, and an image that cannot be pulled stops the stack instead of falling back to a source build. Use an explicit version (or its digest) for production and reproducible demos; details in the [stack's README](../../examples/docker-compose/README.md).

## Verify the upgrade

```bash
talon version                       # Talon <version>
talon audit list --limit 5          # existing evidence still listed
talon audit verify <evidence-id>    # existing evidence still verifies with your signing key
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/dashboard   # 404
```

Then pair the console and check that the **System** page shows your running processes and the **Overview** reads the traffic you already had.

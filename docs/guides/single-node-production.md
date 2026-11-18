# Single-node production profile

This is the one deployment profile Talon supports for a production pilot: **one Talon installation on one host**. The host runs one serving process (`talon serve`), optionally the read-only console (`talon ui serve`), and local SQLite stores. This guide covers what the profile stores, how to run it, what restarts preserve, how to back up and restore, what it does when something is unavailable, and its limits.

It is not a high-availability deployment. There is no second node, no replication and no shared database. See [Limits](#limits).

## What the installation consists of

| Part | Where (systemd profile) | Back up how |
|---|---|---|
| Durable state: `evidence.db` (signed evidence, sessions, approver principals, action operations and approvals), `secrets.db` (encrypted vault: agent keys, provider keys), `memory.db` (agent memory) | `TALON_DATA_DIR=/var/lib/talon` | `talon backup create` (below) |
| Keys: `TALON_SECRETS_KEY` (vault encryption, 32 bytes), `TALON_SIGNING_KEY` (evidence HMAC, ≥ 32 bytes), `TALON_ADMIN_KEY` | `/etc/talon/talon.env` (mode 0600, owner root) | your secret manager. **Without the same two keys a restore is useless:** the vault cannot be decrypted and the evidence cannot be verified |
| Configuration: `talon.config.yaml` (company policy, providers), `agents/<name>/agent.talon.yaml` (one per AI use case) | `/etc/talon` | version control |
| Rebuildable: `cache.db`; transient: `runtime/` (process heartbeats), `console.pid` | data directory | not backed up |

Set `agents_dir: /etc/talon/agents` in `talon.config.yaml` (or `TALON_AGENTS_DIR`) so that `talon agents add` can register use cases.

## Run it

Install the verified binary (`scripts/install.sh` or the release archive, checked with `scripts/verify-release.sh`), then:

```bash
sudo useradd --system --home-dir /var/lib/talon --shell /usr/sbin/nologin talon
sudo install -d -o talon -g talon -m 0700 /var/lib/talon
sudo install -d -m 0755 /etc/talon /etc/talon/agents
sudo install -m 0600 /dev/null /etc/talon/talon.env       # TALON_SECRETS_KEY=…, TALON_SIGNING_KEY=…, TALON_ADMIN_KEY=…
sudo cp deploy/systemd/talon.service /etc/systemd/system/  # WorkingDirectory=/etc/talon, TALON_DATA_DIR=/var/lib/talon
sudo systemctl daemon-reload && sudo systemctl enable --now talon
```

`talon doctor` checks the configuration, data directory, keys and stores. Run it after every change, as the `talon` user with the same environment.

**Run it with these settings:**
- **Set `TALON_ADMIN_KEY`:** without it the data-plane API is open to unauthenticated callers.
- **Keep listeners on loopback or behind a TLS terminator.** Talon terminates no TLS.
- **Run the console with the same `TALON_DATA_DIR` and `TALON_SIGNING_KEY`** (`talon ui serve`). It opens the stores through a read-only connection, but SQLite's WAL mode needs the data directory to be **writable at the filesystem level** for its shared-memory file. A read-only mount is not supported.

## What a restart preserves

**Preserved:**
- Every committed record and every operation's state.
- A **pending approval stays pending** and can be decided after the restart.
- An **approved but unclaimed operation** can be claimed once.
- A **succeeded operation is never dispatched again.**
- An attempt interrupted by a crash **after** Talon armed the dispatch is closed as `unknown` and never retried blindly. One interrupted **before** arming is closed as not dispatched and may be claimed again.

**Not preserved:**
- In-memory state: console sessions, pairing codes, and the process-local in-flight budget ledger.
- An unrecorded provider charge remembered by the gateway process is forgotten on restart (LIMITATIONS §7).

The company action policy (`talon.config.yaml`) is read at start. Changing it requires a restart, and that restart invalidates approvals granted under the old policy (`approval_binding_stale`). Agent files reload safely while serving, every `agents_reload_interval` (default 30s).

## Back up

```bash
sudo -u talon env $(sudo cat /etc/talon/talon.env | xargs) TALON_DATA_DIR=/var/lib/talon \
  talon backup create /var/backups/talon/$(date -u +%Y%m%dT%H%M%SZ)
```

`talon backup create` is safe while `talon serve` runs:
- **Consistent per store:** each store is copied in one read transaction (SQLite `VACUUM INTO` over a read-only connection).
- **Not one cross-store transaction:** the three stores are copied one after another, so a vault change made during the backup can be missing from the copied vault.
- **Never overwrites:** it writes into a new or empty directory only, with a `manifest.json` of SHA-256 checksums.
- **Keys and configuration are not included.**

Schedule it (a systemd timer or cron) and copy the directory off the host. Then **verify** each backup:

```bash
talon backup verify /var/backups/talon/<backup>
```

`verify` reads the backup only. It checks every checksum, SQLite `integrity_check`, **every evidence signature under the configured `TALON_SIGNING_KEY`**, and that every vault entry decrypts under the configured `TALON_SECRETS_KEY`. Entries whose ACL names specific tenants or agents are counted but not decrypted. It prints `PASS backup verify: …` or `FAIL …` and exits non-zero on any failure.

## Restore

Restore is a deliberate stop, copy and start. No command replaces the stores of a running installation.

```bash
sudo systemctl stop talon talon-ui 2>/dev/null
talon backup verify /var/backups/talon/<backup>            # with the keys you will run with
sudo mv /var/lib/talon /var/lib/talon.before-restore       # keep what you are replacing
sudo install -d -o talon -g talon -m 0700 /var/lib/talon
sudo install -o talon -g talon -m 0600 /var/backups/talon/<backup>/*.db /var/lib/talon/
sudo systemctl start talon
talon audit verify --operation <a recent operation_id>     # Lifecycle: VALID
```

Restore onto a host that has the **same `TALON_SECRETS_KEY` and `TALON_SIGNING_KEY`** and the same configuration files.

After the restore:
- **The state is the backup's.** Operations established after the backup do not exist. Pending approvals from the backup are pending again. Succeeded operations stay succeeded and are never re-dispatched.
- **Actions dispatched after the backup are not recorded.** If the downstream system received such an action, Talon has no record of it. Reconcile it with the downstream system. Talon cannot report effects it no longer has evidence of.

The restore path is exercised by `TestE2E_BackupRestore_SingleNode`:
1. State is created: a succeeded refund, a pending approval and a denial.
2. An online backup is taken while `talon serve` runs, and verified.
3. The stores are deleted, then restored by stop, copy and start.
4. The pending approval is dispatched once after the decision (at most one effect per operation), the succeeded refund is refused a second claim, and every lifecycle verifies.
5. A tampered backup and a wrong signing key fail verification.

## When something is unavailable

| Situation | What Talon does |
|---|---|
| A declared agent key cannot be resolved (vault undecryptable, ACL-denied) | `talon serve` refuses to start; the console shows *failed to start* |
| Evidence or session store unreadable while a spending cap binds | request denied `budget_unavailable` (503, retriable), nothing dispatched |
| Pricing unknown for a model under a cap | denied `pricing_unavailable` (403) |
| Action payload key missing or rotated | claim refused `payload_unavailable`, nothing dispatched |
| Approval expired, missing, or granted under another policy | claim refused (`approval_expired`, `approval_required`, `approval_binding_stale`), nothing dispatched |
| Ambiguous outcome after dispatch (no response) | operation `unknown`; no automatic retry |
| Invalid agent-file edit while serving | last-known-good keeps serving; the rejection is logged and recorded |
| Gateway or MCP proxy stopped | the console reads it *offline* or *stale*, never healthy |

## Upgrade and rollback

Upgrade with the same binary path. Back up and verify first. Stop the service, replace the binary, run `talon doctor`, start the service, and check `talon version` and a recent `talon audit verify`. Read the release's upgrade notes in `CHANGELOG.md` (and the version's upgrade guide where one exists) before you start.

The in-place upgrade from the previous stable release (v1.16.1) is exercised by `TestE2E_UpgradeFromPreviousStable`: the released v1.16.1 binary writes a succeeded action, a pending approval, evidence, the vault and an approver; the new binary takes the same data directory over; the old evidence verifies, the old succeeded action is refused a second claim, the old pending approval is decided with the old approver credential and dispatched once, and a backup of the upgraded stores verifies.

**Rollback is restore.** Returning to an older binary after the new one has written to the stores is not tested. To roll back, stop the service, put the old binary back and restore the pre-upgrade backup. Everything recorded after the upgrade is then lost, and the downstream reconciliation from [Restore](#restore) applies.

## Limits

- **One node.** SQLite with one writer process per data directory. Two `talon serve` processes on one data directory are not supported. The in-flight budget ledger is process-local.
- **No HA and no automatic failover.** Recovery time is how long a restore takes. Recovery point is the time since the last backup.
- **Cross-store snapshot is not atomic** (see [Back up](#back-up)).
- **Capacity is not benchmarked for this profile.** Size the host on your own load test. Evidence grows with every request; plan disk and retention (`audit.retention_days`).
- **Keys are your responsibility.** Losing `TALON_SECRETS_KEY` makes the vault unrecoverable. Losing `TALON_SIGNING_KEY` makes existing evidence unverifiable, though still readable.

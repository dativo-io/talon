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
sudo install -d -o root  -g talon -m 0750 /etc/talon
sudo install -d -o talon -g talon -m 0750 /etc/talon/agents   # talon agents add (run as talon) writes here
sudo install -m 0600 /dev/null /etc/talon/talon.env       # TALON_SECRETS_KEY=…, TALON_SIGNING_KEY=…, TALON_ADMIN_KEY=…
sudo cp deploy/systemd/talon.service /etc/systemd/system/  # WorkingDirectory=/etc/talon, TALON_DATA_DIR=/var/lib/talon
sudo systemctl daemon-reload && sudo systemctl enable --now talon
```

The unit starts Talon on `127.0.0.1:8080`. To serve other machines, put a TLS-terminating proxy in front of it; change the listener only with a drop-in that you have reviewed.

**The keys stay in `/etc/talon/talon.env`.** The file is `0600 root:root`; systemd reads it for the service (`EnvironmentFile=`). Never put its contents on a command line: process arguments are visible to every user of the host (`ps`), and end up in shell history and logs. For operator commands, let systemd load the same file. Define this once in your shell:

```bash
# Run a talon command as the service user, with the service's environment.
# systemd reads /etc/talon/talon.env; no key is passed as an argument or
# exported into your shell.
talonctl() {
  sudo systemd-run --quiet --wait --collect --pipe \
    --property=User=talon --property=Group=talon \
    --property=WorkingDirectory=/etc/talon \
    --property=EnvironmentFile=/etc/talon/talon.env \
    --setenv=TALON_DATA_DIR=/var/lib/talon \
    /usr/local/bin/talon "$@"
}
```

Check the result once:

```bash
sudo stat -c '%a %U:%G %n' /etc/talon/talon.env /var/lib/talon      # 600 root:root …talon.env, 700 talon:talon /var/lib/talon
ps -eo args= | grep -c 'TALON_.*_KEY='                               # 1: only this grep itself; no key in any process's arguments
sudo journalctl -u talon --no-pager | grep -c 'TALON_.*_KEY='        # 0: no key in the service's log
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

A production restore point is a **cold** backup: stop Talon, snapshot, start.

```bash
sudo install -d -o talon -g talon -m 0700 /var/backups/talon
sudo systemctl stop talon talon-ui 2>/dev/null          # a graceful stop: Talon records its shutdown
talonctl backup create --cold /var/backups/talon/$(date -u +%Y%m%dT%H%M%SZ)
sudo systemctl start talon
```

Do not run other `talon` commands or edit the configuration while the backup runs.

What a backup contains:
- **The durable stores:** `evidence.db`, `secrets.db`, `memory.db`. A store that does not exist is recorded as absent, never silently omitted.
- **The configuration in force:** the gateway config (which carries the company policy) and every agent file, under `config/`, with a digest.
- **A manifest** (`manifest.json`) with a backup id, the mode, and a SHA-256 checksum of every file.
- **Not the keys.** `TALON_SECRETS_KEY` and `TALON_SIGNING_KEY` stay in your secret manager.

**Cold and online are different things:**
- **`--cold`** produces **one coherent recovery point** across the stores and the configuration, and enforces what that needs:
  - it refuses while a Talon process of this installation reports running, was killed less than a minute ago, or when that cannot be established;
  - that no process reports running is not enough (a status record is not a lock, and a command can still write), so for the whole snapshot it holds the installation's registration lock and a write lock on every store: no `talon` command and no process can commit to a store or complete a registration meanwhile. If one of these is held by someone else, it refuses;
  - the configuration files cannot be locked: they are captured first and compared again at the end. If one changed, the backup fails and writes no manifest.
  What it does not cover: the keys (never in a backup), your downstream systems, and anything outside this installation's data directory and configuration files.
- **Without `--cold`**, a backup can be taken while `talon serve` runs. Each store is then copied consistently (one read transaction), but the stores are copied one after another, so a change made during the backup can be in one store and not in another. Such a backup is labelled `online` and is **not a coherent recovery point**. Use it for extra copies between cold backups, not as your restore point.

A backup never overwrites one: it writes into a new or empty directory only.

Then **verify** it, with the keys you would restore with:

```bash
talonctl backup verify /var/backups/talon/<backup>
```

`verify` only reads the backup. It fails, and exits non-zero, when:
- the manifest is malformed, incomplete or inconsistent (an unknown or duplicate store, a store neither present nor recorded as absent, a configuration path outside `config/`);
- the directory contains a file the manifest does not account for, or lacks one it lists;
- a checksum, size or SQLite `integrity_check` is wrong;
- **any evidence record's signature** does not verify under the configured `TALON_SIGNING_KEY`;
- **any vault entry** does not decrypt under the configured `TALON_SECRETS_KEY`. Every entry is checked, including the ACL-restricted keys `talon agents add` creates; no value is read out and the backup is not modified;
- the evidence snapshot does not carry its recovery hold (below).

It also notes when this installation's configuration files differ from those in the backup.

## Restore

**What a restore is.** It returns the installation to the moment of the backup. Everything Talon did after that moment is gone from its records: operations established later do not exist, and operations that were *executed* later look unexecuted again (authorized, or awaiting an approval that had in fact been given). **Talon's restored ledger therefore cannot tell you whether an action already happened.** A restored installation must not be allowed to dispatch on that basis.

**What the hold covers.** The hold stops the **dispatch of governed actions through the Action Gateway**: every claim is refused, so Talon calls no business system. It is enforced in the store itself (the store refuses the attempt record every dispatch starts with), so it binds any Talon binary that serves the restored store, including an older release. Governed MCP tool calls on `POST /mcp` are Action Gateway operations, so the hold refuses their dispatch too (#431). It does **not** stop model traffic through the LLM gateway: that is not an operation of the ledger, and it is served. `talon doctor` shows the hold as `recovery_hold`, with the backup it came from.

**The recovery hold.** Every backup's evidence snapshot carries a hold. An installation started on restored stores refuses **every** claim of a governed action (`503 recovery_hold`, nothing dispatched) until an operator resumes it. The hold is in the snapshot itself, so it applies however the files were copied back. Model traffic, policy decisions, establishing operations and approvals keep working; only dispatch is held.

```bash
sudo systemctl stop talon talon-ui 2>/dev/null
talonctl backup verify /var/backups/talon/<backup>         # with the keys you will run with
sudo mv /var/lib/talon /var/lib/talon.before-restore       # keep what you are replacing
sudo install -d -o talon -g talon -m 0700 /var/lib/talon
sudo install -o talon -g talon -m 0600 /var/backups/talon/<backup>/*.db /var/lib/talon/
# restore the configuration from <backup>/config/ too, unless you are deliberately keeping the current one
sudo systemctl start talon
```

**Reconcile, then resume.**

```bash
talonctl doctor            # recovery_hold: FAIL, with the backup this installation runs on
talonctl backup resume
```

This prints the hold and every operation that was still open in the backup, with the `Idempotency-Key` Talon sends for it. For each one, look in the downstream system (your refund service, for example) for that key:
- **It was executed after the backup:** keep it held for good with `--hold-operation <operation_id>`. It will never be dispatched again; a genuinely new action needs a new `operation_id`. A held id is held for the **whole installation**: every tenant and use case that uses that `operation_id` is refused it, because the downstream system that shows the effect may not say which use case asked for it. Holding too much is recoverable (use a new id); holding too little would repeat an effect.
- **It was not executed:** leave it. It becomes claimable again.
- **You cannot tell:** hold it.

Operations established after the backup are not listed, because Talon no longer knows them. Find those in the downstream system and in the calling application, and hold their operation ids as well if the application may retry them.

```bash
talonctl backup resume --reconciled --hold-operation refund-T-1842 --hold-operation refund-T-1850
```

A resume that ends no hold (it was already resumed, or another operator's resume won) says so, writes no evidence and names none; if you asked it to hold operation ids, it exits non-zero and lists them as not held.

- **Configuration:** if the company policy or agent files now differ from those captured with the backup, the resume is refused until you have reviewed them and pass `--accept-config-change`. A restore must not silently change which policy is enforced.
- **Record:** the held operation ids, the end of the hold and a signed `recovery_resumed` evidence record (backup id, number of open operations, held ids; an installation event, shown in the console under System › Installation activity) are committed in one transaction. If the record cannot be written, nothing changes: the hold stays active and dispatch stays refused.

**What Talon guarantees after a restore, and what it does not:**
- Until you resume: no governed action is dispatched.
- After you resume: an operation id you held is never dispatched; a succeeded operation that was in the backup is never dispatched again.
- **Not guaranteed:** that an operation you did not hold was not executed in the lost interval. That is exactly what the reconciliation establishes; Talon cannot know it from a restored ledger. If your downstream system honours the `Idempotency-Key` header, a repeated dispatch of an operation that existed in the backup carries the same key and can be deduplicated there. An operation established after the backup gets a new key when it is established again.
- Restore onto a host with the **same `TALON_SECRETS_KEY` and `TALON_SIGNING_KEY`**.

The recovery path is exercised over real processes:
- `TestE2E_Restore_DoesNotRepeatEffectsExecutedAfterTheBackup`: one operation is authorized and one awaits approval at backup time; both are executed afterwards (two downstream effects); the backup is restored. Replaying, re-establishing and re-approving produce no third effect (`recovery_hold`). `talon backup resume` lists both with the key the downstream saw; held, they never dispatch again; a new operation works.
- `TestE2E_BackupRestore_SingleNode`: backup while serving (labelled online; `--cold` refuses), restore, hold, resume; a succeeded refund cannot be claimed again; a tampered backup and a wrong signing key fail verification.
- `TestE2E_Restore_AnUnknownOutcomeIsNeverReplayed`: an operation whose outcome was unknown before a cold backup is still unknown after the restore and after the resume; the downstream service was called once in all.
- `TestE2E_RollbackOnARestoredStore_ThePreviousStableDispatchesNothing`: see [Upgrade and rollback](#upgrade-and-rollback).

These run against a binary built from source, with processes started by the test, not under systemd. The systemd unit, the `talonctl` wrapper and the file permissions above are the documented procedure; run the checks of this page once on your host.

## When something is unavailable

| Situation | What Talon does |
|---|---|
| A declared agent key cannot be resolved (vault undecryptable, ACL-denied) | `talon serve` refuses to start; the console shows *failed to start* |
| Evidence or session store unreadable while a spending cap binds | request denied `budget_unavailable` (503, retriable), nothing dispatched |
| Pricing unknown for a model under a cap | denied `pricing_unavailable` (403) |
| Action payload key missing or rotated | claim refused `payload_unavailable`, nothing dispatched |
| Approval expired, missing, or granted under another policy | claim refused (`approval_expired`, `approval_required`, `approval_binding_stale`), nothing dispatched |
| Ambiguous outcome after dispatch (no response) | operation `unknown`; no automatic retry |
| The installation runs on a restored backup and was not resumed | every claim refused `recovery_hold` (503), nothing dispatched |
| Invalid agent-file edit while serving | last-known-good keeps serving; the rejection is logged and recorded |
| Gateway or MCP endpoint (`talon serve`) stopped | the console reads it *offline* or *stale*, never healthy |

## Upgrade and rollback

Read the release's upgrade notes in `CHANGELOG.md` (and the version's upgrade guide where one exists) before you start. Upgrade with the same binary path:

```bash
sudo systemctl stop talon talon-ui 2>/dev/null                 # a graceful stop
TS=$(date -u +%Y%m%dT%H%M%SZ)
# 1. A plain copy of the stopped installation. It is the recovery point if the
#    upgrade fails before the new release has served: the previous release runs on it.
#    (A release before v1.17.0 has no `talon backup`; this copy works for every release.)
#    With Talon stopped, every SQLite store is complete on disk; copy each with its
#    -wal and -shm files (cp -a of the directory does).
sudo install -d -o root -g root -m 0700 /var/backups/talon/pre-upgrade-$TS
sudo cp -a /var/lib/talon /var/backups/talon/pre-upgrade-$TS/
sudo tar -C /etc --exclude=talon/talon.env -cf - talon | sudo tar -C /var/backups/talon/pre-upgrade-$TS --transform 's,^talon,etc-talon,' -xpf -
#    The keys are NOT in the copy. The copy is useless without the same TALON_SECRETS_KEY
#    and TALON_SIGNING_KEY: confirm they are in your secret manager (or keep a separate
#    root-only file, never next to the copy).
sudo install -m 0755 talon-NEW /usr/local/bin/talon            # the verified new binary
# 2. Before the first start: a cold backup with the NEW binary, of the untouched store.
#    It only reads the store; it is the recovery point after the upgrade, with its hold.
talonctl backup create --cold /var/backups/talon/upgrade-$TS
talonctl backup verify /var/backups/talon/upgrade-$TS
talonctl doctor
sudo systemctl start talon
talonctl version
```

**If the upgrade fails before the new release has served** (step 2 or `doctor` fails, the service does not start): stop the service, put the previous binary back, put the copy back (`/var/lib/talon` from `pre-upgrade-$TS/talon`, `/etc/talon` from `pre-upgrade-$TS/etc-talon`, keeping the current `talon.env`; owners as in [Run it](#run-it)) and start. Nothing was dispatched after the copy was taken, so there is nothing to reconcile. **Once the new release has served**, the plain copy is no longer a safe recovery point: it carries no recovery hold, and the previous release would dispatch from it actions executed since. Use the cold backup of step 2 and the procedure below.

`TestE2E_PreUpgradeBackup_FromThePreviousStable` runs this with the actual previous stable release: the previous release writes an executed and an authorized operation; the plain copy runs under it again with no repeated dispatch; the new binary's cold backup of its store verifies and does not change the store; after the upgrade executes the authorized operation, a restore of that backup holds it until the operator reconciles and holds it.

The in-place upgrade from the **immediately preceding stable release** is the release gate: CI resolves that release from the published releases (`scripts/previous-stable.sh`), downloads its checksum-verified binary, and `TestE2E_UpgradeFromPreviousStable` lets it write state that the new binary takes over. v1.16.1 additionally runs as a historical compatibility check (`TestE2E_UpgradeFromHistoricalReleases`) when it is not the preceding release itself. In the test the earlier binary writes a succeeded action, a pending approval, evidence, the vault and an approver; the new binary takes the same data directory over; the old evidence verifies, the old succeeded action is refused a second claim, the old pending approval is decided with the old approver credential and dispatched once, and a backup of the upgraded stores verifies.

**Rollback is restore.** Returning to an older binary after the new one has written to the stores is not supported as such. To roll back, restore a backup, and reconcile before anything is dispatched:

1. Use a cold backup taken by this release: the one of step 2 above, or a later one.
2. To roll back: stop the service and restore that backup as described under [Restore](#restore). The restored store is held.
3. Reconcile and resume **with the release that took the backup** (`talonctl backup resume`, then `--reconciled`). The older release has no such command.
4. Only then put the older binary back and start it.

An older release does not know the recovery hold. Started on a restored store before step 3, it still dispatches nothing, because the store refuses the attempt record: `TestE2E_RollbackOnARestoredStore_ThePreviousStableDispatchesNothing` runs the actual previous stable release against a store restored from a cold backup, and neither the operation executed after the backup nor a new one is dispatched. That is a safeguard, not the procedure: the older release reports the refusal as a store error, and it cannot reconcile or hold operations for you. Everything recorded after the backup is lost, as with any restore.

## Limits

- **One node.** SQLite with one writer process per data directory. Two `talon serve` processes on one data directory are not supported. The in-flight budget ledger is process-local.
- **No HA and no automatic failover.** Recovery time is how long a restore takes. Recovery point is the time since the last backup.
- **Only a cold backup is a coherent recovery point** (see [Back up](#back-up)). An online backup is a set of per-store snapshots.
- **A restore loses everything after the backup,** including which actions were dispatched. Dispatch stays held until an operator reconciles and resumes (see [Restore](#restore)). The hold covers the Action Gateway, including governed MCP tool calls on `POST /mcp`; model traffic is not consequential-action dispatch in this sense and is not held.
- **Capacity is not benchmarked for this profile.** Size the host on your own load test. Evidence grows with every request; plan disk and retention (`audit.retention_days`).
- **Keys are your responsibility.** Losing `TALON_SECRETS_KEY` makes the vault unrecoverable. Losing `TALON_SIGNING_KEY` makes existing evidence unverifiable, though still readable.

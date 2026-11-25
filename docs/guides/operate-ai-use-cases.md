# Operate AI use cases: task reference

Questions an operator has after an application is connected, each with the command that answers it. Two commands cover most days:

```bash
talon agents                  # every use case on one screen
talon agents show <name>      # one use case: what is happening, and what to do next
```

Both read the files, the running processes' own records and signed evidence. Neither writes anything. For scripts use `--json`; the human views can change their layout, the JSON rows do not.

Both show **this machine's installation**, from its own files, evidence store and runtime records. They ask no server, so run them on the host of the installation, with its configuration and keys. With `--url <server>` they show the fleet facts that server reports, alone, and say that no verification was performed: nothing in what a server reports establishes that it belongs to this machine's installation (two installations with the same configuration look alike), so a server's rows are never shown next to this machine's evidence. `talon agents show <name> --effective` is always this machine's report and refuses `--url`. The machine contract is unchanged: `--json` returns the fleet rows from the server at `--url` (default `http://localhost:8080`) when one answers, and says with `offline` when it did not.

| Question | Section |
|---|---|
| How do I connect an application? | [Connect](#how-do-i-connect-an-application) |
| How do I know it is working? | [Working](#how-do-i-know-it-is-working) |
| Why is this application blocked, or flagged? | [Blocked](#why-is-this-application-blocked-or-flagged) |
| Why is the company policy not active? | [Policy not active](#why-is-the-company-policy-not-active) |
| How do I investigate its cost or a failure? | [Investigate](#how-do-i-investigate-its-cost-or-a-failure) |
| How do I safely stop it? | [Stop](#how-do-i-safely-stop-it) |
| How do I replace a compromised key? | [Replace a key](#how-do-i-replace-a-key) |
| How do I remove an application? | [Remove](#how-do-i-remove-an-application) |
| How do I recover from an interrupted registration? | [Interrupted registration](#how-do-i-recover-from-an-interrupted-registration) |
| How do I check a record independently? | [Verify evidence](#how-do-i-check-a-record-independently) |
| Where is this in the console? | [Console](#where-is-this-in-the-console) |

## How do I connect an application?

`talon agents add <name> --owner <team>`, then two settings in the application. The whole path, including the one-time preparation, is [connect an existing application](add-talon-to-existing-app.md). Every application after the first is that one command.

## How do I know it is working?

```bash
talon agents show customer-support
```

The first line under the name is the answer:

| Status | It means |
|---|---|
| **Working** | a running Talon process serves the use case **and** its newest request was authenticated, verifies and was evaluated under the policy the current files compile to |
| **Waiting for its first request** | a running process serves it; nothing has arrived from the application |
| **Not active** | no running process serves it |
| **Needs attention** | the `Next` line says what |
| **Blocked** | new requests are refused (a budget cap is exhausted, or the policy denies all new work). It leads the status and the next step even when earlier traffic verified |
| **Disabled** | its file says `enabled: false` |

`Next` is one sentence and, where a Talon command exists for it, that command. It is derived from the facts on the screen; it starts nothing by itself.

Four facts are shown side by side and none stands for another:

- **Configured:** what the file says.
- **Runtime:** whether a running process has loaded exactly this file, from that process's own record (written when it activates a fleet, and at least every five seconds). A file on disk is not a use case that is served.
- **Traffic:** what was observed. No observation is shown as "no request observed", never as a healthy application.
- **Health:** budget, denial and failure signals. The absence of a signal says nothing about whether the application is connected.

`talon agents` shows the same four as columns (`STATE`, `RUNTIME`, `LAST REQUEST`, `ATTENTION`) for every use case.

**What counts as traffic.** A registration, an enable or disable, a configuration reload, a budget warning, a provider sub-attempt, an imported external event, a native `talon run` and a reviewer's decision are not application traffic. A request with an unknown or invalid key is rejected before any record is written, so it counts for no use case.

**What a record says about the caller** differs by boundary. At the **LLM gateway** and the **Action Gateway** a record under a use case exists only when that use case's Talon key (or a verified workload identity) was presented. At the Action Gateway only the application's own requests count (establishing an operation, re-sending one, claiming one); a reviewer's decision, a refused authorization and the execution record do not. A governed MCP call on `POST /mcp` is an Action Gateway operation and counts there. Records of the MCP proxy of earlier releases (removed in #431) do not say how the caller was identified, so they are shown as "caller's identity not established" and never count as an authenticated connection.

A request that Talon **denied** shows that the application is connected and that the policy was evaluated. It does not show that a provider was reached.

### Which credential a request used

A use-case name can be registered again after it was removed, and a key can be replaced. Signed records made with the earlier key stay in the store under the same name. Talon keeps three things apart:

- **history:** records from before the key that is in the vault now was written. They stay readable and verifiable, and are labelled as an earlier credential;
- **traffic since the current key was stored;**
- **proof that the current key was used.**

Evidence does not record which key a request presented. Talon infers it from recorded facts, and says so: the vault's own record of when the current value was written and whether another existed under the name (the record commits together with every write of a value; never the value itself), and when the serving process started. A request counts for the current key only when the runtime records still say which Talon processes can have served it, at least one can, and none of them can hold another key: each started after the current key was stored (a process reads its keys from the vault when it starts), or the key is the only value this vault file has ever held under the name and each started after the vault file was created. Only a process that serves the boundary counts (a `talon serve` without `--gateway` serves no LLM gateway request), a process that stopped reporting without recording a stop is taken to have served for up to a minute longer, and a process that was already running is not proof, even after a reload. When the runtime records no longer cover the request (they are kept for seven days after a process stops) nothing is concluded: the key reads as not established when another value existed before, and as not known otherwise. It is never reported as current. So after replacing a key or registering a name again:

1. restart `talon serve` (for a replaced key you must anyway);
2. send one request from the application with the new key;
3. look again: `talon agents show <name>` reads **Working**.

Until then the view reads **Needs attention** and says which it is: only earlier-key traffic, a request served by a process that was already running, or a running process that still holds the earlier key (also when the newest request did not use a key at all).

Two things are outside what this inference can see, so do them as a key replacement (restart, then one request): replacing or restoring the vault file (`secrets.db`) while Talon runs, and pointing a use case at another secret by editing `agent.key.secret_name`. A process that started before the current vault file existed is reported as not established; a restored older vault file under a process that started later is not detected.

A vault created by an earlier Talon version has no such record for the keys it already held: for those the report says that the credential's history is not recorded, and attributes nothing to it, until the key is written again. A use case configured by hand, without `talon agents add`, is treated the same way as a registered one. When the vault cannot be read (or the reader, for example a console on another host, cannot see the vault file), the report says that the credential is not known. In these cases a verified request under the current policy still reads **Working**, and the next step states what it does not rest on: which key the request used.

## Why is this application blocked, or flagged?

`talon agents` puts it in the `ATTENTION` column; `talon agents show <name>` has it on the `Health` line with the cause:

| Health | Typical cause | Look at |
|---|---|---|
| `blocked` | a budget cap is exhausted, or the effective policy denies all new work | `talon costs --agent <name>`; the `Policy` line |
| `needs-attention` | a high share of denied requests, failed sessions, provider fallbacks | `Last request` on the view; `talon audit list --agent <name>` |
| `stopped` | disabled by an operator | [stop](#how-do-i-safely-stop-it) |
| `config rejected` | the running process refused the current file and serves the last good one | `talon validate` |

For one denied request, `Last request` gives the reason code, and `talon audit show <evidence-id>` the whole signed record. The reason codes are stable (`POLICY_DENIED_PII_INPUT`, a budget code, a forbidden tool); the application received the corresponding API error.

## Why is the company policy not active?

The company policy lives in the `gateway:` block of `talon.config.yaml`. `talon serve` reads it **when it starts**; a change needs a restart. A use case's own file is different: a running process picks up a changed or new `agent.talon.yaml` at its next re-scan of `agents_dir` (`agents_reload_interval`, default 30s).

```bash
talon agents show <name> --effective
```

Section 3 says, for each enforcement boundary, whether the policy compiled from the current files is **proven active**: a running process reports that it loaded exactly these files. "Compiled from current files, not proven active" means that nothing running has loaded them, or that the running process loaded other files. `talon agents add` warns when a running gateway has not loaded the current gateway config.

When one file in the fleet is invalid, the running process rejects the whole re-scan and keeps serving the previous fleet: nothing that changed since is active, including a disable. `talon validate` names the file.

## How do I investigate its cost or a failure?

```bash
talon costs --agent <name>              # spend against the daily and monthly caps
talon audit list --agent <name>         # its signed records, newest first
talon audit show <evidence-id>          # one record in full
talon session list                      # sessions, newest first
talon session show <session-id>         # what happened in one session, in order
```

`talon agents show <name>` names the newest request's evidence and session, so an investigation usually starts by copying one of those two ids. The [Operations Console](operations-console.md) shows the same records as pages you can follow: use case, session, evidence.

## How do I safely stop it?

```bash
talon agents disable <name>
talon agents show <name>
```

`disable` sets `agent.enabled: false` in the use case's file and writes a signed record. **It is not immediate.** It takes effect when the running process has loaded the change: at most one `agents_reload_interval`. Requests already in flight finish. Confirm it rather than assume it:

- the view reads **Disabled**, and `Runtime` reads *loaded by the running Talon process*. While it reads *reports ANOTHER version* (`other version` in the listing), the process still serves the enabled file: it has not re-scanned yet, or it rejected the re-scan. Look again;
- a request with the use case's key is refused as that use case (HTTP 403 `agent_disabled`), not as an unknown key, and the provider is not called.

If another file in the fleet is invalid, the re-scan is rejected and the disable is **not** active although the file says disabled. Fix the fleet (`talon validate`) or restart `talon serve`; a start reads the files as they are.

`talon agents enable <name>` reverses it, with the same delay.

## How do I replace a key?

Each use case has exactly one active key. There is no second key and no overlap period. This is also the procedure for a key that was lost or exposed.

```bash
printf '%s' "$NEW_KEY" | talon secrets set <name>-talon-key --tenant <tenant> --agent <name>
```

Generate `NEW_KEY` yourself (for example `openssl rand -hex 32`); the value is given on stdin and never on the command line. Then **restart `talon serve`**. A secret-only change is not a configuration change: the periodic re-scan does not pick it up, and until the restart the running process still accepts the old key and rejects the new one. After the restart the old key gets 401 and the new one works. Update the application's secret manager in the same maintenance step.

A restart affects every use case the process serves. Stop it gracefully (SIGTERM, Ctrl-C): it stops accepting new connections and lets requests in flight finish, for up to 30 seconds. A killed process cuts them off.

Replacing the key does not show that the application uses the new one. `talon agents show <name>` reads **Needs attention** until a request arrives that the restarted process served ([which credential a request used](#which-credential-a-request-used)).

`talon secrets rotate <name>` is **not** a key replacement: it re-encrypts the same value. The same key keeps working after it, and it is not counted as a new credential.

## How do I remove an application?

Remove the use case from the fleet, then its key:

```bash
rm -r agents/<name>
# wait for the re-scan (or restart), confirm that the key now gets 401
talon secrets delete <name>-talon-key
```

Its evidence stays in the store. The name can be registered again later; it gets a new key, and the earlier records then read as history of an earlier credential, not as traffic of the new registration.

Deleting only the secret does not stop a running process that already holds the key. Remove or disable the use case first.

## How do I recover from an interrupted registration?

Run the registration again:

```bash
talon agents add <name> --owner <team>
```

A registration writes to three places that share no transaction (the evidence store, the vault, the agent file), so it is not atomic. Three things make it safe to repeat:

- **One at a time.** `talon agents add` holds the installation's registration lock from before it writes anything until its last record. A second registration waits up to 30 seconds, then refuses without writing. The operating system releases the lock when the process ends, however it ends. Where that lock does not exist (platforms other than Linux and macOS) registration refuses to run.
- **A fixed order:** signed intent, key, file, fleet check, signed completion. The key is printed only after the completion record.
- **Ownership.** The signed intent records what the registration is about to create: the ownership token of the key version (a random value the vault assigns to that version; not the key) and, for the agent file, its path, its SHA-256 and a random registration marker written into the file. Only something that matches these is ever removed.

What you see in each case:

- **It failed with an error.** It removed exactly what it created, wrote a signed rollback record and told you whether anything was left. Run it again.
- **Another registration is running.** Its intent has no completion record *yet*. `talon doctor` reports **IN PROGRESS**; a second registration waits. Nothing of the running one is touched or judged: a key or a file it has already created is not reported as a taken name.
- **The process died** (killed, power loss). No key was shown, so nobody can use what it left. `talon doctor` reports **INTERRUPTED**. The next registration of the name removes the key version and the agent file that the signed intent proves the interrupted one created, records it as rolled back and registers. The output lists each step as `Recovered`.
- **The interrupted registration used another `agents_dir`** (the same data directory, another agents directory). Its signed intent names an agent file this run does not look at. Nothing is changed or recorded; the message names that file. Run the registration with the `agents_dir` it used.
- **Something under the name is not what the intent committed to:** a file with other content or without that registration's marker, a symbolic link, a secret someone stored, an intent written before markers existed, an intent whose signature no longer verifies. Nothing is changed. The message says what exists and what it was compared with. It does not tell you to delete anything: an unfinished intent is not a reason to delete something that may be in use. Find out who uses it (`talon agents show <name>`, `talon secrets list`), or register under another name.
- **It completed but you did not capture the key.** The key cannot be shown again. [Replace it](#how-do-i-replace-a-key).

The marker is a comment line in the generated file. It is not a secret and not configuration. Its one job is to make the file of one registration different from every other, so that a matching digest means "this registration's file" and not "a file with the same content". A copy of the file made byte for byte, marker included, cannot be told from the original; nothing claims otherwise.

A registration never overwrites an existing agent file or vault secret, and never changes the company policy or another use case. `--dry-run` reads only.

## How do I check a record independently?

```bash
talon audit verify <evidence-id>
```

It checks the record's signature with the installation's `TALON_SIGNING_KEY`. A record that does not verify establishes nothing, and every view says so before anything else about it.

## Where is this in the console?

The [Operations Console](operations-console.md) is read-only and shows the same projections:

| CLI | Console |
|---|---|
| `talon agents` | **AI Use Cases** (and the attention list on **Overview**) |
| `talon agents show <name>` | the use case's page, **Summary**: the same Status and Next, readiness and the one-line reading; **AI Use Cases** shows the Status of every use case |
| `talon agents show <name> --effective` | the use case's page, **Policy & Runtime** |
| `talon session show`, `talon audit show` | **Sessions**, and each record's evidence page |
| `talon costs` | **Costs** |

Commands that change something (`agents add`, `agents enable|disable`, `secrets set`) exist only in the CLI, on the installation's host.

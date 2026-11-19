# How to connect an existing AI application to Talon

You have an application that calls a model provider. This guide takes you from a Talon installation to that application's requests arriving at Talon under your company policy, with the proof to check it, and then repeats it for a second, unrelated application without copying any policy.

Two different things are called "getting started". Pick the one you mean:

| | Try Talon | Connect an existing application |
|---|---|---|
| Purpose | See real policy decisions and signed evidence in a few minutes | Put a real application behind your company policy |
| Needs | Docker. No provider key | A provider key, a company policy, a Talon key per application |
| Guide | [Quickstart](../QUICKSTART.md) (published image, deterministic, no model call) or the [OpenAI proxy quickstart](../tutorials/proxy-quickstart.md) (`talon serve --proxy-quickstart`, one local identity) | This page |

The quickstarts prove that Talon decides and signs. They do not connect your application: they use a synthetic identity and no company baseline.

## What you end up with

- One `talon.config.yaml`: the provider and the **company policy** every application runs under.
- One AI use case per application: `<agents_dir>/<name>/agent.talon.yaml`, one identity, **one active Talon key** in the encrypted vault.
- The application sends its requests to Talon's gateway with its Talon key. It never holds the provider's key.
- For each application you can show: the file is loaded by the running process, an authenticated request was observed, its signed record verifies, and it was evaluated under the policy your files compile to.

Talon governs what reaches it. A request the application sends straight to the provider, or a tool it calls directly, is not seen, not governed and not recorded. Registering an application does not route its traffic.

## Prerequisites

- Talon installed ([installation](../../README.md#install)). The commands below are the `talon` CLI; the same steps work with the published image by running them in the container.
- A provider API key.
- `TALON_SECRETS_KEY` (vault encryption) and `TALON_SIGNING_KEY` (evidence signatures) set to the same values for every `talon` command and for `talon serve`. Generate each once (`openssl rand -hex 32`) and keep them in your secret manager.

## 1. Prepare the installation

Create a directory, work from it for every command below, and create `talon.config.yaml`:

```yaml
agents_dir: ./agents

gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    defaults:            # each use case may replace these where the precedence allows
      pii_action: block
      daily_cost: 50
      monthly_cost: 500
    constraints:         # always bind; no use case can lift them
      forbidden_tools: ["delete_*"]
```

`organization_policy` is the company policy. `talon agents add` refuses to register an application while it is missing, because the application would otherwise inherit rules nobody chose (`--no-company-policy` states that you intend that).

Store the provider key in the vault. The value comes from stdin, so it never appears in the process list or the shell history:

```bash
printf '%s' "$OPENAI_API_KEY" | talon secrets set openai-api-key
```

## 2. Register the application

```bash
talon agents add customer-support \
  --owner support-engineering \
  --description "AI customer support assistant"
```

The command works without prompts. It writes `agents/customer-support/agent.talon.yaml` with the identity, owner, tenant and key binding only, generates the application's Talon key, stores it in the vault as `customer-support-talon-key` and prints, in this order:

- the registered identity and owner, the configuration file and the signed registration record;
- the **company policy this use case runs under**, compiled by the resolver the gateway enforces with, each rule with the layer that won and its precedence;
- **activation**: whether a running process has loaded the company policy and this use case. Writing a file is not activation;
- how to **connect** the application: one endpoint per provider your gateway config enables;
- how to **verify** the first request, and what the command did not verify;
- last, in a block of its own, the **Talon key**. It is shown once. Everything above that block is safe to copy into a ticket.

`--dry-run` prints the file and writes nothing. `--tenant` sets the tenant (default `default`). `talon validate` checks the whole fleet as `talon serve` will load it.

Put the key into the application's secret manager. Do not put it in source, YAML, a shell argument, a chat or a ticket.

## 3. Start the gateway

```bash
talon serve --port 8080 --gateway --gateway-config talon.config.yaml
```

A running `talon serve` re-scans `agents_dir` every `agents_reload_interval` (default 30s), so later registrations need no restart. The company policy (`gateway:` block) is read at start: changing it needs a restart.

## 4. Point the application at Talon

Two settings change in the application: the base URL and the API key.

- **Base URL:** `<talon-url>/v1/proxy/<provider>/v1`, for example `http://localhost:8080/v1/proxy/openai/v1`.
- **API key:** the application's **Talon key**. Talon identifies the use case by it and uses the provider key from its vault when forwarding.

Node.js (official `openai` package; the acceptance suite runs this client with version 7.59.0, see `tests/onboarding/client.mjs`):

```javascript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: `${process.env.TALON_URL}/v1/proxy/openai/v1`,
  apiKey: process.env.TALON_USE_CASE_KEY, // the Talon key, from your secret manager
});
const res = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Say hello in one word." }],
});
```

Python (official `openai` package, 1.x; the same two settings, not part of the automated acceptance):

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url=os.environ["TALON_URL"] + "/v1/proxy/openai/v1",
    api_key=os.environ["TALON_USE_CASE_KEY"],  # the Talon key, from your secret manager
)
res = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Say hello in one word."}],
)
```

A request Talon denies surfaces in the SDK as an API error: for example HTTP 400 with code `pii_policy_violation` when the company policy blocks personal data. A request with an unknown key is HTTP 401 and is never forwarded.

Other supported ways to connect (coding agents, the MCP proxy, the HTTP Action Gateway, n8n, OpenShell) are in [choosing an integration path](choosing-integration-path.md). They are integration recipes for the same use case, not different kinds of application.

## 5. Verify

Send one request from the application, then:

```bash
talon agents show customer-support --effective
```

The report keeps five things apart. None implies another:

| Section | Question | Source |
|---|---|---|
| 1. Current files | What do the agent file and the gateway config say now? | the files, with their digests |
| 2. Loaded by a running process | Has a running Talon process loaded exactly this agent file? | each process's own runtime record |
| 3. Effective policy | Which policy do the files compile to, which layer wins each rule, and is that proven active at each enforcement boundary? | the resolver the gateway enforces with, and runtime records |
| 4. Last recorded decision | What was the newest request decision recorded for this use case, and how did Talon decide? | signed evidence, signature checked |
| 5. Connection and verification | At each interception boundary, has an authenticated request of this use case been observed, does its record verify, and was it evaluated under the policy the current files compile to? | signed evidence, compared by recorded policy digests |

Section 5 starts with one line, for example:

- *Registered, not loaded* or *Registered; activation unknown*: the file exists; no running process is proven to have loaded it; no traffic.
- *Loaded, no authenticated traffic observed*: the process has the use case; the application has not sent a request to Talon with its key.
- *Authenticated traffic observed under the expected policy*: a request arrived, its record's signature verifies and its recorded policy digests equal what the current files compile to.
- *Authenticated traffic observed under a DIFFERENT policy than the current files*: the newest record was evaluated before a policy change, or by a process running another configuration.
- *…the policy it was evaluated under is not proven*: the record carries no (or only part of the) policy digests.
- *Traffic attributed to this use case was observed, but an authenticated connection is not established*: no record establishes that the use case's own key was presented. The only records are at the MCP proxy, which does not record how the caller was identified (see below), or come from the no-key quickstart.
- *A record exists but does not verify*: the newest record's signature is invalid; nothing on it is established. This is stated first, whatever other records say.

The one-line reading speaks about the newest record that establishes the use case's own credential; the table lists every boundary.

What counts as traffic is explicit. A registration, an enable or disable, a configuration reload, a budget warning, a provider sub-attempt, an imported external event, a native `talon run`, and a reviewer's approval decision are **not** application traffic and never appear as the last decision. A request with an unknown or invalid key is rejected before any record is written, so it cannot count for any use case.

The boundaries differ in what a record establishes about the caller. At the **LLM gateway** and the **Action Gateway** a record under a use case exists only when that use case's Talon key (or a verified workload identity) was presented. At the **MCP proxy** it does not: the proxy attributes a call to the presented agent key when there is one, and to its own configured agent name on an admin-key or development-open request, and the record does not say which. The report therefore shows MCP proxy records as "caller's identity not established" and never counts them as an authenticated connection.

A request that Talon **denied** still proves the connection and the policy evaluation: the application reached Talon with its key and Talon decided. It does not prove that a provider was reached. The report says which of these the newest record establishes, and lists what the observations do not establish.

Check the signature of the record the report names, independently:

```bash
talon audit verify <evidence-id>
```

The same facts are in the [Operations Console](operations-console.md) on the use case's page (Summary and Policy & Runtime) and in `talon agents show customer-support --effective --json` (`verification`). All three read one projection.

## 6. Operate

```bash
talon agents                              # every use case: health, spend, requests
talon agents show customer-support        # one use case
talon agents disable customer-support     # stop new work (see "Emergency disable")
talon agents enable customer-support
talon costs --agent customer-support
talon audit list --agent customer-support
```

To tighten the policy for one application, edit its `agent.talon.yaml` (for example `policies.cost_limits.daily`). Company constraints cannot be lifted there. After the reload, section 5 reports earlier requests as evaluated under a different policy until a new request arrives.

## 7. Connect a second application

```bash
talon agents add hr-copilot --owner people-ops --description "HR policy assistant"
```

That is the whole step. The second application gets its own identity, key, budget accounting and evidence, and runs under the same company policy: nothing is copied into its file, the company configuration is not touched, and the first application keeps serving while the second is registered. Verify it with `talon agents show hr-copilot --effective`.

## Replace or revoke a key

Each use case has exactly one active key. There is no second key and no overlap period.

**Replace a key (also: the key was lost or exposed).** The value is given on stdin; the ACL flags keep it readable only as this use case:

```bash
printf '%s' "$NEW_KEY" | talon secrets set customer-support-talon-key --tenant default --agent customer-support
```

Generate `NEW_KEY` yourself (for example `openssl rand -hex 32`) and keep it out of the command line. Then **restart `talon serve`**. A secret-only change is not a configuration change: the periodic reload does not pick it up, and until the restart the running process still accepts the old key and rejects the new one. After the restart the old key is rejected (401) and the new one works. Update the application's secret manager in the same maintenance step.

A restart affects every use case this process serves, not only the one whose key changed. Stop the process gracefully (SIGTERM, Ctrl-C): it stops accepting new connections and lets requests that are already in flight finish, for up to 30 seconds, before it exits. A killed process cuts them off.

`talon secrets rotate <name>` is **not** a key replacement: it re-encrypts the same value with a fresh nonce. The same key keeps working after it.

**Emergency disable.** `talon agents disable <name>` sets `agent.enabled: false` in the file. It takes effect when the running process has loaded the change (at most one `agents_reload_interval`; requests already in flight finish). Confirm it: `talon agents show <name> --effective` reads *Configured as disabled* and section 2 reads loaded, and a request with the key is refused as that use case (not as an unknown key) with no call to the provider. If a reload is rejected because another file in the fleet is invalid, the previous generation keeps serving and the disable is **not** active: fix the fleet (`talon validate`) or restart.

**Revoke.** Remove the use case, then its key:

```bash
rm -r agents/customer-support
# wait for the reload (or restart), confirm the key now gets 401
talon secrets delete customer-support-talon-key
```

The use case's evidence stays in the store. The name can be registered again later; it gets a new key.

## When a registration fails or is interrupted

A registration writes to three places that share no transaction: the evidence store, the vault and the agent file. It is not atomic. It works in a fixed order (signed intent, key, file, fleet check, signed completion) and prints the key only after the completion record.

- **It fails with an error.** It removes exactly what it created, writes a signed rollback record that says what it removed, and tells you whether anything was left. You can run the command again.
- **The process dies** (killed, power loss). Nothing is cleaned up, but no key was shown, so nobody can use what it left. The next `talon agents add <name>` and `talon doctor` report the interrupted registration, name what it left and the commands to remove it:

  ```bash
  rm -r agents/customer-support                       # if the agent file was written
  talon secrets delete customer-support-talon-key     # if the key was stored
  talon agents add customer-support --owner support-engineering
  ```

  The new registration records the interrupted one as rolled back. A running server that had loaded the half-registered use case drops it at its next reload.
- **It completed but you did not capture the key.** The key cannot be shown again. Replace it (above).

A registration never overwrites an existing agent file or vault secret, and never changes the company policy or another use case.

## Limits

- Talon governs the supported interception boundaries: the LLM gateway, the MCP proxy, the HTTP Action Gateway, native runs and OpenShell-delegated decisions. Their guarantees differ; see [choosing an integration path](choosing-integration-path.md) and [LIMITATIONS](../../LIMITATIONS.md).
- "Loaded" and "traffic observed" are statements about a moment. A use case can be loaded with no traffic, and old traffic does not prove it is loaded now.
- Registration is local: the `talon` CLI on the installation's host. There is no remote registration API and the Operations Console is read-only.
- A use-case key is replaced, not rotated with overlap. Dedicated key lifecycle commands do not exist yet.
- The verification steps above were executed against a source build by the acceptance suite (`make test-onboarding`). Acceptance against the published release artifacts is part of the release process.

## Related

| I want to… | Doc |
|---|---|
| Understand every configuration key | [Configuration](../reference/configuration.md) |
| Understand keys and their scopes | [Authentication and key scopes](../reference/authentication-and-key-scopes.md) |
| Cap cost or restrict models for one application | [Cost governance by agent](cost-governance-by-agent.md) |
| Authorize a consequential business action | [Action Gateway](../reference/action-gateway.md) |
| Read the same facts in a browser | [Operations Console](operations-console.md) |

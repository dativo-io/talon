# How to connect an existing AI application to Talon

You have an application that calls a model provider. This guide puts it behind your company policy and shows you that it works. A second application is then one command.

There are two ways to start with Talon. Pick the one you mean:

| | Try Talon | Connect your existing application |
|---|---|---|
| Purpose | See real policy decisions and signed evidence in a few minutes | Put an application you run behind your company policy |
| Needs | Docker. No provider key, no application | A provider key, a company policy, one Talon key per application |
| Guide | [Quickstart](../QUICKSTART.md) | This page |

The quickstart proves that Talon decides and signs. It does not connect your application: it uses a synthetic identity and no company policy.

## The whole path

| Step | You do | How often |
|---|---|---|
| 1. Prepare Talon | keys, one config file with the provider and the company policy | once per installation |
| 2. Register the application | `talon agents add <name> --owner <team>` | once per application |
| 3. Start Talon | `talon serve …` | once |
| 4. Point the application at Talon | two settings: base URL and API key | once per application |
| 5. Verify | `talon agents show <name>` | whenever you want to know |

Talon governs what reaches it. A request the application sends straight to the provider, or a tool it calls directly, is not seen, not governed and not recorded. Registering an application does not route its traffic.

## Three credentials, three owners

Keep these apart. None of them substitutes for another.

| Credential | Who holds it | What it authorizes | Where it lives |
|---|---|---|---|
| **Operator: admin key** (`TALON_ADMIN_KEY`) | the people who run Talon | Talon's administrative endpoints: secrets metadata, runs, overrides, fleet state, compliance exports | the operator's secret manager and the environment of `talon serve` |
| **Application: Talon key** (one per use case, `talon_uc_…`) | the application | sending that use case's requests through the gateway and reading that use case's own records (evidence, costs). Nothing administrative | the application's secret manager; Talon's vault holds it encrypted |
| **Provider key** (for example the OpenAI API key) | Talon only | calling the model provider | Talon's encrypted vault. The application never holds it |

Without `TALON_ADMIN_KEY`, `talon serve` runs in development mode and its administrative endpoints accept every request. That is for experiments on your own machine. Every step below sets the admin key before the server starts.

## Prerequisites

- Talon installed ([installation](../../README.md#install)) on Linux or macOS. The commands below are the `talon` CLI; the same steps work with the published image by running them in the container.
- A provider API key.
- `openssl` (to generate keys).

## 1. Prepare Talon (once)

Create a directory, work from it for every command below, and generate the installation's three keys **into a file only you can read**:

<!-- onboarding-acceptance: keys -->
```bash
umask 077
cat > talon.env <<EOF
TALON_SECRETS_KEY=$(openssl rand -hex 32)
TALON_SIGNING_KEY=$(openssl rand -hex 32)
TALON_ADMIN_KEY=$(openssl rand -hex 32)
EOF
```

`TALON_SECRETS_KEY` encrypts the vault, `TALON_SIGNING_KEY` signs evidence and `TALON_ADMIN_KEY` is the operator credential. The values go straight into the file: they are never a command-line argument and never appear in the shell history. `umask 077` makes the file mode `0600`. Keep `talon.env` out of source control and copy the values into your secret manager: losing `TALON_SECRETS_KEY` loses the vault, and losing `TALON_SIGNING_KEY` means existing evidence can no longer be verified.

Load the file into the shell that runs the `talon` commands. Do this in every new shell:

<!-- onboarding-acceptance: load -->
```bash
set -a; . ./talon.env; set +a
```

On a server, give the same file to the service manager instead (for systemd: `EnvironmentFile=/etc/talon/talon.env`, mode `0600`, owned by the service user).

Create `talon.config.yaml`. It names the provider and holds the **company policy** every application runs under:

<!-- onboarding-acceptance: config -->
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

Store the provider key in the vault. The value comes from stdin, so it never appears in the process list or the shell history:

<!-- onboarding-acceptance: provider-key -->
```bash
printf '%s' "$OPENAI_API_KEY" | talon secrets set openai-api-key
```

That is all the company-wide setup. No application after the first repeats it.

## 2. Register the application

<!-- onboarding-acceptance: register -->
```bash
talon agents add customer-support \
  --owner support-engineering \
  --description "AI customer support assistant"
```

The command asks nothing and prints what you need next:

<!-- onboarding-acceptance: register-output -->
```text
Registered customer-support (tenant default)
  Owner     support-engineering
  Purpose   AI customer support assistant
  File      agents/customer-support/agent.talon.yaml
  Record    al_488283f9-bc4 (signed; check it with: talon audit verify al_488283f9-bc4)

Company policy: inherited (nothing is copied into the use case's file)
  defaults         daily_cost 50 · monthly_cost 500 · pii_action block
  always enforced  forbidden_tools delete_*
  The use case's own file can only tighten these. Why each rule applies: talon agents show customer-support --effective

Runtime
  Not active: no Talon process of this installation is running. `talon serve` loads this use case when it starts.

Connect your application
  Base URL  <talon-url>/v1/proxy/openai/v1   (<talon-url>: the address of the Talon gateway that serves this installation; you supply it)
  API key   the application key below (never the provider's key)
  Set these two in the application's OpenAI-compatible SDK. Other ways to connect: docs/guides/choosing-integration-path.md

Verify
  Send one request from the application, then:
    talon agents show customer-support

Application key — SECRET — shown once
  talon_uc_…
  Store it in the application's secret manager, never in source, YAML, a ticket or a shell argument.
  It cannot be shown again; a lost key is replaced (docs/guides/operate-ai-use-cases.md).
```

Everything above the key block is safe to copy into a ticket. The command states only what is established. It never names the gateway's address: a Talon server that answers somewhere is not thereby the gateway of this installation, so `<talon-url>` stays a placeholder for the address you supply (section 4). It calls the use case active only when a running process has loaded it.

It refuses, without registering anything, when the company policy is missing (`--no-company-policy` states that you intend that), the name is taken, or the existing fleet does not validate. `--dry-run` prints the file and writes nothing. `--tenant` sets the tenant (default `default`).

## 3. Start Talon

Start it bound to this machine only:

<!-- onboarding-acceptance: start -->
```bash
talon serve --host 127.0.0.1 --port 8080 --gateway --gateway-config talon.config.yaml
```

`--host 127.0.0.1` matters: without `--host`, `talon serve` listens on every network interface. The shell must have loaded `talon.env`, so the server starts with the admin key set. Check both facts before you connect anything:

<!-- onboarding-acceptance: check -->
```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/v1/secrets
curl -s -o /dev/null -w '%{http_code}\n' -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" http://127.0.0.1:8080/v1/secrets
```

The first line must print `401` (no credential) and the second `200` (the operator). A `200` on the first line means the server runs without an admin key: stop it, load `talon.env`, start again. The application's Talon key gets `401` on the administrative endpoints too ([key scopes](../reference/authentication-and-key-scopes.md)).

A running `talon serve` re-scans `agents_dir` every `agents_reload_interval` (default 30s), so later registrations need no restart. The company policy (`gateway:` block) is read at start: changing it needs a restart.

### When the application runs on another machine

`talon serve` speaks plain HTTP and does not terminate TLS. The supported way to serve applications on other machines is:

- keep `talon serve` on `127.0.0.1` (or on a private interface that only the proxy can reach);
- put a TLS-terminating reverse proxy or load balancer in front of it, and give applications its `https://` URL as `<talon-url>`;
- forward only what applications use: `/v1/proxy/` (and `/v1/action-operations` if you use the Action Gateway). Do **not** publish the administrative endpoints;
- never publish Talon's port to the Internet directly.

Talon keys and the admin key are bearer credentials: over plain HTTP on a network, anyone on the path can read them. The Operations Console has its own listener and its own rules ([console access](../reference/console-access.md)).

## 4. Point the application at Talon

Two settings change in the application:

- **Base URL:** `<talon-url>/v1/proxy/<provider>/v1`. On the same machine that is `http://127.0.0.1:8080/v1/proxy/openai/v1`; from another machine it is the `https://` URL of the proxy in front of Talon.
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

Coding agents, the governed MCP endpoint (`POST /mcp`), the HTTP Action Gateway, n8n and OpenShell connect the same use case in other ways: [choosing an integration path](choosing-integration-path.md). Their guarantees differ; that page says how.

## 5. Verify

Send one request from the application, then:

```bash
talon agents show customer-support
```

```text
customer-support — AI customer support assistant
tenant default · owner support-engineering · agents/customer-support/agent.talon.yaml

  Status      Working
  Configured  enabled
  Runtime     loaded by the running Talon process
  Traffic     last request 12s ago · 2 in the last hour (1 denied)
  Policy      daily_cost 50 · monthly_cost 500 · pii_action block · forbidden_tools delete_*
              the newest authenticated request was evaluated under this policy
  Cost        $0.0000 / $500.00 this month · $0.0000 / $50.00 today
  Health      no budget, denial or failure signal

Last request
  2026-11-20 11:09:52Z · LLM gateway · denied by Talon, not dispatched
  POLICY_DENIED_PII_INPUT: Request blocked because input PII was detected.
  evidence gw_1a57c581-366 (signature valid) · session sess_gw_5d47fb3e-982

Next
  Nothing to do: a running Talon process serves this use case, and the newest request was authenticated, verifies and was evaluated under the policy the current files compile to.

Full report: talon agents show customer-support --effective
```

`Status` is one of:

| Status | Meaning | What the view tells you to do |
|---|---|---|
| **Not active** | no running Talon process serves the use case | start `talon serve`, or fix the fleet the running process rejected |
| **Waiting for its first request** | a running process serves it; no request has arrived | point the application at Talon and send one |
| **Working** | a running process serves it **and** the newest request was authenticated, verifies and was evaluated under the current policy | nothing |
| **Needs attention** | something is established that you would want to know (an older policy, a replaced key, a record that does not verify) | the `Next` line says what, with the command |
| **Blocked** | new requests are refused: a budget cap is exhausted, or the policy denies all new work. This leads, whatever earlier traffic verified | which condition, and the command that shows it |
| **Disabled** | the file says `enabled: false` | `talon agents enable <name>` when you want it back |

The view keeps four facts apart and never lets one stand for another: the file (**Configured**), what a running process has loaded (**Runtime**), what was observed (**Traffic**) and the health signals. A request that Talon **denied** still shows that the application is connected and that the policy was evaluated; it does not show that a provider was reached.

`talon agents show <name> --effective` is the full report behind this view: the files and their digests, the policy with the layer that wins each rule, every interception boundary, and what the observations do not establish. `talon audit verify <evidence-id>` checks a record's signature independently. The [Operations Console](operations-console.md) shows the same facts on the use case's page.

## 6. Connect the next application

```bash
talon agents add hr-copilot --owner people-ops --description "HR policy assistant"
```

That is the whole step. Give the application its two settings and send a request. The second application gets its own identity, key, budget accounting and evidence, and runs under the same company policy: nothing is copied into its file, the company configuration is not touched, the running Talon loads it without a restart, and the first application keeps serving meanwhile.

See all of them at once:

```bash
talon agents
```

```text
USE CASE               STATE     RUNTIME        LAST REQUEST   COST THIS MONTH        ATTENTION
customer-support       enabled   loaded         4m ago         $0.0000 / $500.00      —
hr-copilot             enabled   loaded         9s ago         $0.0000 / $500.00      —
```

## When it does not work: `talon doctor`

Run `talon doctor` in the installation's directory, with the same environment as Talon (`set -a; . ./talon.env; set +a`). It reads only: it writes no file, creates no directory or store, changes no stored record, secret or schema, and prints no key or secret value (reading a store that is in SQLite's WAL mode lets SQLite itself create its `-shm` index file, which holds no data). It names the three failures a new installation meets first, each with its own fix:

| What doctor reports | What it means | Fix |
|---|---|---|
| `config_load` fails: `permission denied` / `While parsing config: … line N` | `talon.config.yaml` exists but cannot be read or parsed. Every `talon` command refuses it with the same cause; nothing falls back to defaults | make it readable by the user that runs Talon (`chmod 600`, its owner) or fix the YAML line |
| `use_case_key:<name>` fails: `not in the vault` / `ACL does not allow` / `empty` | that one application cannot authenticate; the others are listed separately | store the key for that use case: `printf '%s' "$KEY" \| talon secrets set <secret> --tenant <tenant> --agent <name>` |
| `secrets_key_decrypts_vault` fails, `use_case_key:*` / `gateway_secrets_*` say `cannot be decrypted` | `TALON_SECRETS_KEY` is not the key the vault was created with (a different `talon.env`) | restore the original `TALON_SECRETS_KEY`. Do **not** set the secrets again: that replaces them |
| `gateway_secrets_<provider>` fails: `not in the vault` | the provider key was never stored | `printf '%s' "$PROVIDER_KEY" \| talon secrets set <secret_name>` |
| `gateway_upstream_<provider>` fails: `connection refused` / timeout | the provider `base_url` cannot be reached from this host | fix `base_url`, DNS or the egress path |
| `action_source:<name>/<source>` fails | a declared MCP action source cannot be discovered; `talon serve` does not start while it is unreachable | start the MCP server or correct `actions.sources.<source>.url` and its credential |

`talon doctor --skip-upstream` skips the network checks (provider endpoints and MCP sources).

## Day two

[Operate AI use cases](operate-ai-use-cases.md) answers the questions that come next: why an application is blocked, how to stop one safely, how to replace a compromised key, what to do after an interrupted registration, and where the same facts are in the console.

To tighten the policy for one application, edit its `agent.talon.yaml` (for example `policies.cost_limits.daily`). Company constraints cannot be lifted there.

## Limits

- Talon governs the supported interception boundaries: the LLM gateway, the governed MCP endpoint (tools of declared MCP action sources), the HTTP Action Gateway, native runs and OpenShell-delegated decisions. Their guarantees differ; see [choosing an integration path](choosing-integration-path.md) and [LIMITATIONS](../../LIMITATIONS.md).
- "Loaded" and "traffic observed" are statements about a moment. A use case can be loaded with no traffic, and old traffic does not show that it is loaded now.
- Registration is local: the `talon` CLI on the installation's host (Linux or macOS). There is no remote registration API and the Operations Console is read-only.
- A use-case key is replaced, not rotated with overlap. Dedicated key lifecycle commands do not exist yet.
- The commands marked in this page's source (key file, configuration, provider key, registration, start, check) are executed as written by the acceptance suite (`make test-onboarding`) against a source build, together with the verification steps. Acceptance against the published release artifacts is part of the release process.

## Related

| I want to… | Doc |
|---|---|
| Operate what I connected | [Operate AI use cases](operate-ai-use-cases.md) |
| Understand every configuration key | [Configuration](../reference/configuration.md) |
| Understand keys and their scopes | [Authentication and key scopes](../reference/authentication-and-key-scopes.md) |
| Cap cost or restrict models for one application | [Cost governance by agent](cost-governance-by-agent.md) |
| Authorize a consequential business action | [Action Gateway](../reference/action-gateway.md) |
| Read the same facts in a browser | [Operations Console](operations-console.md) |

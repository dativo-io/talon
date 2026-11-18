# Production pilot runbook

This runbook takes an engineer who has never used Talon from a published release to one governed AI use case. It ends with a second use case registered, under one single-node installation. Every step uses a command that ships in the release; each section links to its full reference.

**What you get:**
- One self-hosted Talon governing an existing application's model traffic.
- One consequential business action (here a refund) that is allowed, held for a named reviewer, or denied before it reaches your system.
- Signed evidence you can verify yourself.
- A backup you can restore.

**What you do not get:** high availability, multi-node operation, an SSO-backed reviewer, a policy editor in the browser, or any compliance determination. See [LIMITATIONS.md](../../LIMITATIONS.md).

## 0. Prerequisites

- **Host:** one linux/amd64 host (the gated installer path), or Docker with Compose v2 for the image path.
- **Keys:** three secrets you generate and keep in your secret manager:
  ```bash
  export TALON_SECRETS_KEY=$(openssl rand -hex 16)   # exactly 32 characters: encrypts the vault
  export TALON_SIGNING_KEY=$(openssl rand -hex 32)   # signs evidence
  export TALON_ADMIN_KEY=$(openssl rand -hex 24)     # operator API key; without it the API is open
  ```
  Losing `TALON_SECRETS_KEY` makes the vault unrecoverable. Losing `TALON_SIGNING_KEY` makes existing evidence unverifiable.
- **Provider key:** only for step 4's real model request. Steps 1–3 and 5–8 need none.

## 1. Install from the published release

```bash
curl -fsSL https://raw.githubusercontent.com/dativo-io/talon/main/scripts/install.sh | TALON_VERSION=vX.Y.Z sh
talon version
```

The installer downloads the release archive and checks it against the release's `checksums.txt`. To check a release yourself before trusting it, run `scripts/verify-release.sh --tag vX.Y.Z`. It verifies every digest, the executable's version and commit against the tag, and anonymous image pulls.

For production, follow [single-node production](single-node-production.md): the `talon` system user, `/etc/talon`, `/var/lib/talon`, the systemd unit, and `talon doctor`.

**Image path:**

```bash
docker pull ghcr.io/dativo-io/talon:X.Y.Z
cd examples/docker-compose
TALON_IMAGE=ghcr.io/dativo-io/talon:X.Y.Z TALON_PULL_POLICY=always docker compose up
```

This no-key demo stack runs the published image for the data plane and the console, with a mock model provider.

## 2. Open the Operations Console

```bash
talon ui serve        # prints a one-time pairing code; Compose: docker compose logs talon-ui
```

Open `http://127.0.0.1:8787/` and enter the code. The browser gets a read-only session, and no admin, agent, vault or provider key reaches it. The six pages are Overview, AI Use Cases, Sessions, Costs, Configuration and System. They show what is configured, which processes run, and what Talon decided. [Operations console](operations-console.md) · [console access](../reference/console-access.md).

## 3. Set the company policy and register your first AI use case

The company policy lives in `talon.config.yaml` under `gateway.organization_policy`. It holds:
- **defaults** every use case starts from: budgets, PII handling;
- **constraints** no use case can lift: allowed providers and models, forbidden tools and actions, approval rules, and amount limits.

Start from `talon init --scaffold` and set `agents_dir: /etc/talon/agents`.

```bash
talon agents add support-assistant --tenant acme --owner support-ops@acme.example
```

The command writes `/etc/talon/agents/support-assistant/agent.talon.yaml` with only the use case's identity and key binding, so every policy is the company's. It stores a new key in the vault and prints it **once**: put it in your application's secret manager. It refuses, writing nothing, on an invalid fleet, a taken name or an existing key. [Configuration: `talon agents add`](../reference/configuration.md).

```bash
talon agents show support-assistant --effective   # the policy it runs under, with the layer each rule comes from
talon validate
```

## 4. Connect your application

Point the application's model client at Talon and give it the use-case key as its bearer token:

```
base URL      http://<talon-host>:8080/v1/proxy/<provider>/v1     (OpenAI-compatible; Anthropic: /v1/proxy/anthropic)
header        Authorization: Bearer <use-case key>
```

Talon applies the company and use-case policy before each provider call: models, budgets checked against pre-request estimates (not an invoice ceiling), PII and tools. It signs evidence of the decision. [Add Talon to an existing app](add-talon-to-existing-app.md) · [choosing an integration path](choosing-integration-path.md).

## 5. Govern one consequential business action

Declare the action in the use case's file, with its schema, its reviewer view and the destination Talon calls. Then set the policy that decides it by amount. This example allows up to 50 EUR, sends up to 500 EUR to a reviewer, and denies anything above. It is an example policy, not a built-in rule. The file to copy is [`examples/n8n-refund/agent.talon.yaml`](../../examples/n8n-refund/agent.talon.yaml).

```yaml
policies:
  approvals:
    amount_limits:
      refund-bands:
        actions: [create_refund_request]
        amount_argument: amount
        currency_argument: currency
        currency: EUR
        allow_up_to: "50.00"
        approval_up_to: "500.00"
        approver_groups: [support-leads]
```

Your application or workflow asks Talon to perform the action instead of calling the refund system:

```bash
POST /v1/action-operations            {"operation_id":"refund-T-1842","action":"create_refund_request","arguments":{...}}   → ALLOW | REQUIRE_APPROVAL | DENY
POST /v1/action-operations/<id>/attempts                                                                                   → Talon dispatches it, at most once
```

**What Talon guarantees:**
- **Denied, unapproved and expired actions are never dispatched.**
- **Changed arguments under the same `operation_id` are refused,** and an approval binds the exact arguments.
- **Replays and concurrent claims cannot cause a second effect.**
- **An ambiguous outcome is UNKNOWN and is never retried automatically.**

[Action Gateway](../reference/action-gateway.md) · [amount limits](../reference/action-gateway.md#amount-limits-205).

**n8n:** [`examples/n8n-refund`](../../examples/n8n-refund/README.md) is an importable workflow that does exactly this with stock n8n nodes.

## 6. Approve locally

```bash
talon approver add --name lead-1 --tenant acme --groups support-leads   # prints the reviewer credential once
export TALON_APPROVER_KEY=...                                         # the reviewer's own credential
talon approvals list
talon approvals show <approval-id>        # action, target, exact amounts, the rule that requires the decision
talon approvals approve <approval-id> --reason "customer verified"
```

The reviewer's credential is not the admin key or the application's key, and neither of those can decide. A decision dispatches nothing: the application claims the approved operation afterwards. [Reviewing approvals](../reference/action-gateway.md#reviewing-approvals-talon-approvals-433).

## 7. Inspect and verify the evidence

```bash
talon audit list --limit 20
talon audit verify --operation refund-T-1842      # every record's signature and the lifecycle: Lifecycle: VALID
talon audit show <evidence-id>
```

The console's Sessions and evidence pages show the same records and check each signature. A valid signature proves the record is unchanged since Talon signed it. It does not prove anything Talon did not see.

## 8. Operate and recover

```bash
talon backup create /var/backups/talon/$(date -u +%Y%m%dT%H%M%SZ)    # online, consistent per store
talon backup verify /var/backups/talon/<backup>                      # checksums, integrity, signatures, vault
```

Restore is stop, copy and start, with the same keys. Restarts keep pending approvals and never re-dispatch a succeeded action. [Single-node production](single-node-production.md) covers restore, behaviour when something is unavailable, upgrade, and rollback-is-restore.

## 9. Register a second use case

```bash
talon agents add hr-copilot --tenant acme
```

It inherits the same company policy, gets its own key, and a running server loads it within the reload interval (default 30 s) without a restart.

## Customer acceptance checklist

Record PASS, FAIL or NOT RUN for each item, with the command output.

| # | Criterion | How to check | Result |
|---|---|---|---|
| 1 | Installed from a published artifact, no source build | `scripts/verify-release.sh --tag vX.Y.Z` → `PASS`; `talon version` shows the tag | |
| 2 | The released console opens and pairs | pairing code from the console's output; the six pages load; the System page shows the running process | |
| 3 | An existing AI use case is registered and connected | `talon agents add`; the application's first request appears in `talon audit list` with that use case | |
| 4 | Company policy applies to one consequential action | `talon actions validate --action <a> --input <file>` shows the band and its reason for test amounts | |
| 5 | Allow, approval and deny work against your real destination | three test requests; **count the calls on your destination system**: allow 1, approval 0 until approved then 1, deny 0 | |
| 6 | Evidence inspected and verified | `talon audit verify --operation <id>` → `Lifecycle: VALID` for each test operation | |
| 7 | Restart and recovery | restart the service: pending approvals stay pending; `talon backup create` + `talon backup verify` → `PASS`; a test restore on a spare host | |
| 8 | Second use case | `talon agents add <second>`; its key authenticates without a restart | |

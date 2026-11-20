# Production pilot runbook

This runbook takes an engineer who has never used Talon from a published release to one governed AI use case with one governed business action, on one Linux host. Every command ships in the release. Replace `X.Y.Z` everywhere with the release you are piloting (for example `1.17.0`), and keep it the same in every step: scripts and documentation are fetched from that release's tag, not from `main`.

**What you get:**
- One self-hosted Talon governing an existing application's model traffic.
- One consequential business action (here a refund) that is allowed, held for a named reviewer, or denied before it reaches your system.
- Signed evidence you can verify yourself.
- A backup you can restore, and a defined procedure for what to do after a restore.

**What you do not get:** high availability, multi-node operation, an SSO-backed reviewer, a policy editor in the browser, or any compliance determination. See [LIMITATIONS.md](../../LIMITATIONS.md).

**Which path governs a business action.** In this release a consequential business action is governed through the **HTTP Action Gateway** (step 6), called by your application or by the n8n reference workflow. Talon's MCP proxy governs MCP tool calls by policy (allowed and forbidden tools, signed allow/deny evidence, visible in the console), but an MCP tool call does **not** get an approval bound to its arguments, at-most-one dispatch, `unknown` outcome handling or the recovery hold. Do not put an action that needs those guarantees behind the MCP proxy.

**n8n.** `examples/n8n-refund` is a reference workflow validated on **n8n 2.48.5** against a real Talon and a counting refund service (`scripts/n8n-refund-live.sh`). It requires an authenticated webhook caller and uses the use case's key as its identity towards Talon. Other n8n releases are untested. Nothing else in this runbook depends on it.

## 0. Prerequisites

- **Host:** one Linux x86-64 (amd64) host with systemd, `curl`, `tar`, `sha256sum` and `openssl`. This is the only platform the release gates verify for the installer path. Docker is needed only for the optional quickstart in step 1.
- **A user with `sudo`** for the installation steps.
- **Network:** Talon listens on `127.0.0.1` in this runbook. To reach it from another machine, put a TLS-terminating reverse proxy in front of it. Talon terminates no TLS, and every key in this runbook is a bearer credential: never send one over plain `http` across a network you do not control.
- **A model-provider key** for step 4 only.

## 1. Install and verify the release

See a governed decision from the published image first (optional; Docker, no clone, no provider key, about a minute plus the image pull):

```bash
curl -fsSL https://raw.githubusercontent.com/dativo-io/talon/vX.Y.Z/scripts/quickstart.sh | TALON_VERSION=X.Y.Z bash
```

It prints the image digest it ran, two policy decisions made with no model provider anywhere, the verification of their signed evidence, and the elapsed time.

Verify the release before trusting it, then install the binary:

```bash
curl -fsSL -o verify-release.sh https://raw.githubusercontent.com/dativo-io/talon/vX.Y.Z/scripts/verify-release.sh
bash verify-release.sh --tag vX.Y.Z            # ends with: PASS verify-release: vX.Y.Z   (it prints every digest; record them)

curl -fsSL https://raw.githubusercontent.com/dativo-io/talon/vX.Y.Z/scripts/install.sh | sudo TALON_VERSION=vX.Y.Z INSTALL_DIR=/usr/local/bin sh
talon version                                  # Talon X.Y.Z, and the commit verify-release reported
```

## 2. Create the installation

```bash
sudo useradd --system --home-dir /var/lib/talon --shell /usr/sbin/nologin talon
sudo install -d -o talon -g talon -m 0700 /var/lib/talon
sudo install -d -o root  -g talon -m 0750 /etc/talon
sudo install -d -o talon -g talon -m 0750 /etc/talon/agents

# Keys: generate once, store a copy in your secret manager. The values are
# generated inside the root shell and written to the file; none of them is a
# command-line argument or printed.
sudo sh -c 'umask 077; {
  echo "TALON_SECRETS_KEY=$(openssl rand -hex 32)"     # 64 hex characters = 32 bytes: encrypts the vault
  echo "TALON_SIGNING_KEY=$(openssl rand -hex 32)"     # 64 hex characters: signs evidence
  echo "TALON_ADMIN_KEY=$(openssl rand -hex 24)"       # operator API key
  echo "TALON_DATA_DIR=/var/lib/talon"
  echo "TALON_GATEWAY_CONFIG=/etc/talon/talon.config.yaml"
  echo "TALON_AGENTS_DIR=/etc/talon/agents"
} > /etc/talon/talon.env; chown root:root /etc/talon/talon.env; chmod 0600 /etc/talon/talon.env'
```

Losing `TALON_SECRETS_KEY` makes the vault unrecoverable. Losing `TALON_SIGNING_KEY` makes existing evidence unverifiable.

`/etc/talon/talon.env` is readable by root only; systemd reads it for the service (`EnvironmentFile=`). **Never put its contents on a command line**: process arguments are visible to every user of the host and end up in shell history and logs. Every `talon` command below runs as the `talon` user with the service's environment, loaded by systemd. Define this once per shell (it is the same wrapper as in [single-node production](single-node-production.md#run-it)):

```bash
talonctl() {
  sudo systemd-run --quiet --wait --collect --pipe \
    --property=User=talon --property=Group=talon \
    --property=WorkingDirectory=/etc/talon \
    --property=EnvironmentFile=/etc/talon/talon.env \
    --setenv=TALON_DATA_DIR=/var/lib/talon \
    /usr/local/bin/talon "$@"
}
```

## 3. Set the company policy

The company policy lives in `/etc/talon/talon.config.yaml` under `gateway.organization_policy`:
- **defaults** every use case starts from: budgets, PII handling;
- **constraints** no use case can lift: allowed providers and models, forbidden tools and actions, approval rules, argument rules.

Start from the baseline shipped with the release:

```bash
sudo curl -fsSL -o /etc/talon/talon.config.yaml https://raw.githubusercontent.com/dativo-io/talon/vX.Y.Z/examples/pilot/talon.config.yaml
sudo chown root:talon /etc/talon/talon.config.yaml && sudo chmod 0640 /etc/talon/talon.config.yaml
sudoedit /etc/talon/talon.config.yaml          # adjust the lines marked ADJUST and the thresholds
```

It defines one provider, PII blocked, per-use-case budgets with company ceilings (checked against pre-request estimates before each call; not an invoice ceiling), two forbidden actions, and example argument rules for a refund: above 50.00 a reviewer in `support-leads` must approve, above 500.00 it is denied (the action's schema restricts the currency to EUR).

## 4. Register your first AI use case and start Talon

```bash
talonctl agents add support-assistant --tenant acme --owner support-ops@acme.example
```

The command:
- reports the **company policy the file declares** and, separately, whether a running gateway has loaded it. It refuses when no organization policy is configured, unless you pass `--no-company-policy` on purpose. Before Talon is started it reads `NOT PROVEN ACTIVE`; after step 4's start, `talonctl agents show support-assistant --effective` shows what the running process loaded;
- writes `/etc/talon/agents/support-assistant/agent.talon.yaml` with only the use case's identity and key binding, so every policy is the company's;
- prints the use case's **key once**: put it into your application's secret manager now.

Store the provider key in the vault (it is read from stdin, so it does not appear in the process list), check, and start:

```bash
printf '%s' "$OPENAI_API_KEY" | talonctl secrets set openai-api-key
talonctl validate
talonctl doctor
sudo curl -fsSL -o /etc/systemd/system/talon.service https://raw.githubusercontent.com/dativo-io/talon/vX.Y.Z/deploy/systemd/talon.service
sudo systemctl daemon-reload && sudo systemctl enable --now talon
curl -fsS http://127.0.0.1:8080/health
talonctl agents show support-assistant --effective    # the policy it runs under, and the layer each rule comes from
```

## 5. Connect your application

Point the application's model client at Talon and use the use-case key as its bearer token. Nothing else changes in the application.

```bash
export USE_CASE_KEY=...        # the key printed by 'talon agents add'

# A permitted request: answered by your provider through Talon.
curl -sS http://127.0.0.1:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer $USE_CASE_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello in five words."}]}'

# A request the company policy blocks before it reaches the provider: HTTP 400, code pii_policy_violation.
curl -sS http://127.0.0.1:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer $USE_CASE_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Refund to IBAN DE89370400440532013000 for jan.kowalski@example.com"}]}'
```

In an SDK, the same two settings: base URL `http://127.0.0.1:8080/v1/proxy/openai/v1` (Anthropic: `http://127.0.0.1:8080/v1/proxy/anthropic`) and the use-case key as the API key. More: [add Talon to an existing app](add-talon-to-existing-app.md).

## 6. Govern one consequential business action

Declare the action in the use case's file: its arguments, what a reviewer sees, and the destination **Talon** calls. Append this to `/etc/talon/agents/support-assistant/agent.talon.yaml` with your refund service's URL:

```yaml
actions:
  definitions:
    create_refund_request:
      description: Create a refund for a support ticket
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string, pattern: "^[A-Z]+-[0-9]+$"}
          amount: {type: string, pattern: "^(0|[1-9][0-9]{0,14})(\\.[0-9]{1,2})?$"}   # exact decimal, as a string
          currency: {type: string, enum: [EUR]}
      review:
        fields: [ticket_id, amount, currency]          # exactly what the reviewer is shown
      destination:
        type: http
        url: "https://refunds.internal/v1/refunds"      # your refund service; plain http only on loopback
        method: POST
        success: {status_codes: [201]}                  # only these answers mean "done"
```

The policy that decides it by amount is the company's (step 3). A use case can tighten it, never lift it.

```bash
talonctl validate
talonctl actions show create_refund_request           # Verdict: BY AMOUNT, and the company band
```

Talon reloads the file within 30 seconds. Your application now asks Talon to perform the refund instead of calling the refund service. Two requests per action:

```bash
# 1. Establish: Talon decides. operation_id is yours; use one per business action (here: per ticket).
curl -sS -X POST http://127.0.0.1:8080/v1/action-operations \
  -H "Authorization: Bearer $USE_CASE_KEY" -H 'Content-Type: application/json' \
  -d '{"operation_id":"refund-T-1001","action":"create_refund_request","arguments":{"ticket_id":"T-1001","amount":"30.00","currency":"EUR"}}'
#    30.00  → HTTP 201, "verdict":"ALLOW"
#    75.00  → HTTP 202, "verdict":"REQUIRE_APPROVAL", "approval":{"id":"apr_...","status":"pending"}
#    900.00 → HTTP 403, "verdict":"DENY"

# 2. Claim: Talon calls your refund service itself, at most once per operation.
curl -sS -X POST http://127.0.0.1:8080/v1/action-operations/refund-T-1001/attempts \
  -H "Authorization: Bearer $USE_CASE_KEY"
#    allowed or approved → HTTP 200, "operation_status":"succeeded"
#    waiting for approval → HTTP 409, code approval_pending
#    denied              → HTTP 403, code policy_denied
```

**What Talon guarantees:**
- **Denied, unapproved, rejected and expired actions are never dispatched.**
- **Changed arguments under the same `operation_id` are refused** (`operation_conflict`); an approval binds the exact arguments.
- **A replay or a concurrent claim cannot cause a second effect** within the installation's own durable state.
- **An ambiguous outcome is `unknown`** (your refund service was called and no answer came back) and is never retried automatically. Reconcile it with the refund service.

Reference: [Action Gateway](../reference/action-gateway.md) · [argument rules](../reference/action-gateway.md#argument-rules-205).

## 7. Approve as a reviewer

A reviewer has their own credential. The admin key and the application's key cannot approve.

```bash
talonctl approver add --name lead-1 --tenant acme --groups support-leads      # prints the reviewer credential once

export TALON_APPROVER_KEY=...          # on the reviewer's machine
talon approvals list                   # the pending approvals this reviewer may decide
talon approvals show apr_...           # action, requesting use case, target, exact amounts, the rule that requires the decision
talon approvals approve apr_... --reason "customer verified"
#   → Approval apr_...: approved by apr_... (support-leads). Operation refund-T-1002 is now authorized; nothing was dispatched by this decision.
talon approvals reject  apr_... --reason "duplicate refund"
```

The reviewer's commands talk to `http://localhost:8080` by default. For a reviewer on another machine, give `--url https://<your TLS endpoint>`; the command refuses to send the credential over plain `http` to a remote host. After the approval, the application claims the operation (step 6, request 2).

## 8. Inspect and verify the evidence

```bash
talonctl audit list --limit 20
talonctl audit verify --operation refund-T-1002   # every record's signature and the lifecycle; ends with: Lifecycle: VALID
talonctl audit show <evidence-id>
```

Open the Operations Console for the same facts in the browser:

```bash
# The console as its own transient service, with the same environment loaded by systemd.
sudo systemd-run --unit=talon-ui --collect \
  --property=User=talon --property=Group=talon \
  --property=WorkingDirectory=/etc/talon \
  --property=EnvironmentFile=/etc/talon/talon.env \
  --setenv=TALON_DATA_DIR=/var/lib/talon \
  /usr/local/bin/talon ui serve
sudo journalctl -u talon-ui --no-pager | grep 'pairing code'
# Talon console pairing code: XXXXX-XXXXX-XXXXX-XXXXX   (single use, expires within ten minutes)
talonctl ui pair                         # a fresh code, printed to the same log, when that one expired
sudo systemctl stop talon-ui             # when you are done
```

Open `http://127.0.0.1:8787/` on the host (or through an SSH tunnel: `ssh -L 8787:127.0.0.1:8787 <host>`), enter the code. The browser gets a read-only session; no admin, agent, vault or provider key reaches it. The six pages (Overview, AI Use Cases, Sessions, Costs, Configuration, System) show what is configured, which processes run and what Talon decided, and the evidence page checks each record's signature. [Operations console](operations-console.md).

A valid signature proves the record is unchanged since Talon signed it. It does not prove anything Talon did not see.

## 9. Operate and recover

```bash
sudo install -d -o talon -g talon -m 0700 /var/backups/talon
sudo systemctl stop talon talon-ui 2>/dev/null                                   # a graceful stop
talonctl backup create --cold /var/backups/talon/$(date -u +%Y%m%dT%H%M%SZ)      # one coherent recovery point
sudo systemctl start talon
talonctl backup verify /var/backups/talon/<backup>                               # ends with: PASS backup verify: ...
```

Do not run other `talon` commands or edit the configuration while the backup runs; `--cold` refuses or fails when it cannot hold every writer out or the configuration changed meanwhile. A backup taken while Talon serves is labelled `online` and is **not** a recovery point. `backup verify` checks integrity, every evidence signature and that every vault entry decrypts with the keys you will restore with.

- **A restart** keeps pending approvals pending and never re-dispatches a succeeded action.
- **A restore** returns Talon to the moment of the backup. The restored store is **held**: no Action Gateway claim is dispatched (`recovery_hold`, also when an older Talon release serves it), and `talonctl doctor` shows `recovery_hold`. The hold does **not** stop model traffic through the gateway or MCP proxy tool calls. Talon's restored records cannot tell you whether an action already happened, and they do not contain actions established after the backup at all: check in your refund service which actions happened after the backup, then `talonctl backup resume --reconciled`, keeping those operations held with `--hold-operation`. A second resume changes nothing and writes no evidence.
- **An upgrade** is: cold backup, verify, replace the binary, `talonctl doctor`, start. **Rollback is a restore**: restore a backup, reconcile and resume with the release that took it, then put the older binary back.

[Single-node production](single-node-production.md) is the one supported procedure for backup, restore, reconciliation, upgrade and rollback, with what happens when something is unavailable and the limits. This section only summarizes it.

## 10. Register a second use case

```bash
talonctl agents add hr-copilot --tenant acme
```

It inherits the same company policy, gets its own key, and the running server loads it within 30 seconds, without a restart.

## Customer acceptance checklist

Record PASS, FAIL or NOT RUN for each item, with the command output and the release version.

| # | Criterion | How to check | Result |
|---|---|---|---|
| 1 | Installed from a published artifact, no source build | `verify-release.sh --tag vX.Y.Z` → `PASS`; `talon version` shows `Talon X.Y.Z` and the same commit | |
| 2 | The released console opens and pairs | pairing code from `talon ui serve`; the six pages load; the System page shows the running process | |
| 3 | An existing AI use case is registered and connected | `talon agents add` reports your company policy; the application's first request appears in `talon audit list` under that use case | |
| 4 | Company policy applies to one consequential action | `talon actions show <action>` shows the company band; a PII request is blocked with `pii_policy_violation` | |
| 5 | Allow, approval and deny work against your real destination | three test requests; **count the calls on your destination system**: allow 1, approval 0 until approved then 1, deny 0 | |
| 6 | Evidence inspected and verified | `talon audit verify --operation <id>` → `Lifecycle: VALID` for each test operation; the console shows *Signature valid* for one of its records | |
| 7 | Restart and recovery | restart the service: a pending approval stays pending; `talon backup create --cold` + `talon backup verify` → `PASS`; on a spare host: restore, `talon doctor` shows `recovery_hold` and a claim is refused with `recovery_hold`, `talon backup resume --reconciled` | |
| 8 | Second use case | `talon agents add <second>`; its key works without a restart; `talon agents show <second> --effective` shows the company policy | |

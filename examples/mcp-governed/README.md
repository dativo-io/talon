# Governed MCP tools — runnable adoption example

An AI application uses tools of an MCP server (here: a CRM). With Talon, the application connects to **Talon's governed `POST /mcp`** instead of the CRM, using a standard, unmodified MCP client. Every tool call becomes an Action Gateway operation: company policy, a separate reviewer for risky actions, at most one dispatch per operation, signed evidence. The CRM accepts requests only from Talon. Full reference: [governed MCP tools](../../docs/guides/mcp-governed-tools.md).

Everything here is local and credential-free: a synthetic CRM that is a real MCP server, Talon, and the official Go SDK client. No provider key, no network, nothing paid.

```text
standard MCP client ──(use case key)──▶ Talon POST /mcp ──(CRM token, from Talon's vault)──▶ CRM MCP server
   mcp-client/                           talon serve                                        crm-mcp-server/
                                         policy · approval · one dispatch · signed record    counts every call it executes
```

| File | What it is |
|---|---|
| `agent.talon.yaml` | The AI use case: the CRM as its trusted MCP action source, four tools as actions, the refund approval rule |
| `crm-mcp-server/` | Synthetic CRM, a real MCP server (Go SDK, protocol 2026-07-28). Requires its own bearer token; `GET /calls` shows how many times each tool was **executed** |
| `mcp-client/` | The official Go SDK client, unmodified, with the use case's key as its `Authorization` header |
| `run.sh` | The whole journey, with the CRM's counters checked at every step |

## Run it

```bash
./examples/mcp-governed/run.sh                       # from the repository root; builds talon
TALON_BIN=/path/to/talon ./examples/mcp-governed/run.sh
```

Needs `go`, `curl`, `jq`, `openssl`, `python3`. It binds 127.0.0.1 only and removes its temp directory afterwards (`KEEP=1` keeps it). A passing run ends with:

```text
PASS governed MCP walkthrough: 14 steps; CRM executed {"customer.delete":0,"refund.create":1,"ticket.lookup":1,"voucher.issue":1}
```

What it shows, each number read from the CRM:

| Step | Client call | Talon answer | CRM executed |
|---|---|---|---|
| discover | `list` | four governed tools + `talon_execute_operation`; `delete_customer` hidden | — |
| read-only | `call lookup_ticket {"ticket_id":"T-100"}` | `allowed`, result relayed | `ticket.lookup` = 1 |
| prepare | `call issue_voucher {"ticket_id":"T-100","amount":20}` | `operation_prepared` + operation id, **nothing sent** | `voucher.issue` = 0 |
| execute | `execute <operation id>` | `allowed`, result relayed | `voucher.issue` = 1 |
| repeat | `execute <same id>` | `operation_already_succeeded` | still 1 |
| approval | `call create_refund {"ticket_id":"T-100","amount":120}` | `approval_pending` + approval id | `refund.create` = 0 |
| early execute | `execute <refund id>` | `approval_pending` (refused) | 0 |
| reviewer | `talon approvals approve <approval id> --reason …` (reviewer's own credential) | approved; the decision sends nothing | 0 |
| resume | `execute <refund id>` | `allowed` | `refund.create` = 1 |
| deny | `call delete_customer {"customer_id":"c-42"}` | `policy_denied` | `customer.delete` = 0 |
| proof | `talon audit verify --operation <id>` for every operation | `Lifecycle: VALID` | — |

## Do it by hand (and with your own MCP server)

The manual integration is **one configuration file and six commands**; nothing changes in the client except its URL and key.

1. **Declare the use case** — copy `agent.talon.yaml`; set `actions.sources.crm.url` to your MCP server (`https`, or `http` on loopback only) and map each tool you want to offer under `actions.definitions` (`upstream_name` is the tool's name at your server; `review.fields` lists every argument; `read_only: true` only for tools without a side effect). Check it offline: `talon validate`.
2. **The use case's key** (the only identity on `/mcp`; the admin key is refused):
   `talon secrets set support-assistant-talon-key "$(openssl rand -hex 24)"`
3. **Your MCP server's credential**, read from the vault per call, never by the client:
   `talon secrets set crm-mcp-token "<token>" --tenant default --agent support-assistant`
4. **A reviewer** (only if a rule requires approval):
   `talon approver add --name lead-1 --tenant default --groups support-leads` — the printed `talon_appr_…` credential is shown once; the reviewer exports it as `TALON_APPROVER_KEY`.
5. **Start Talon**: `talon serve --host 127.0.0.1 --port 8080` (put a TLS-terminating proxy in front for other hosts).
6. **Point the client at Talon**: URL `http://127.0.0.1:8080/mcp`, header `Authorization: Bearer <use case key>`. With the example client:
   ```bash
   export TALON_MCP_URL=http://127.0.0.1:8080/mcp TALON_USE_CASE_KEY=<use case key>
   go run ./examples/mcp-governed/mcp-client list
   go run ./examples/mcp-governed/mcp-client call issue_voucher '{"ticket_id":"T-100","amount":20}'
   go run ./examples/mcp-governed/mcp-client execute <TALON_operationId>
   ```

**Claude Code** (2.1.329 verified to connect and list over 2026-07-28; see below):

```bash
claude mcp add --transport http --scope user talon http://127.0.0.1:8080/mcp --header "Authorization: Bearer <use case key>"
claude mcp list        # talon: http://127.0.0.1:8080/mcp (HTTP) - ✔ Connected
```

The tools then appear as `mcp__talon__<tool>`. When a consequential tool is prepared, the result tells the model to call `talon_execute_operation` with the operation id.

## What is and is not governed

- Governed: the tools you map under `actions.definitions`, called through Talon's `/mcp`. The decision, approval, dispatch and evidence are Talon's.
- Not governed: anything the client reaches without Talon — other MCP servers configured in the client, local shell and files, direct API calls. If the client also holds the CRM's own token, it can bypass Talon; keep that token in Talon's vault only.
- At most once **per operation**: calling a consequential tool twice prepares two operations; executing both performs two actions. A client that needs idempotent retries of one business intent sends its own stable `_meta["io.dativo.talon/operationId"]`.
- An error your server reports after Talon sent the call (`isError`, a JSON-RPC error, a malformed result, a timeout) is `upstream_outcome_unknown`: Talon never re-sends it; reconcile with your server.

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| HTTP 401 / `agent_identity_required` on `/mcp` | no key, a wrong key, or the admin key | send the use case's key as `Authorization: Bearer …` |
| `talon serve` exits with `discovering action sources: actions.sources.crm: server/discover: upstream transport error` | the MCP server was not reachable when Talon started | start your MCP server first; at startup there is no last-known-good catalog |
| `upstream_auth_unavailable` on execute, CRM counter unchanged | the source credential is missing or not scoped to this use case | `talon secrets set crm-mcp-token … --tenant default --agent support-assistant`, then execute the same operation again |
| `-32602 Unknown tool` | the tool is not mapped under `actions.definitions`, or the client used the server's own tool name | map it; call the canonical Talon name |
| a source URL with `http://` on another host is rejected | plain http is accepted on loopback only | use `https`, or run the MCP server on the same host |
| `approval_expired` after the reviewer approved | the execute came after `policies.approvals.expires_after` | prepare again; raise the lifetime if needed |
| every consequential call says "Nothing was executed" | expected: the first call prepares | call `talon_execute_operation` with the returned operation id |

## Verified

- `./examples/mcp-governed/run.sh` passes against the built binary (14 steps, counters as above).
- `go test -tags e2e ./tests/e2e -run TestE2E_MCP_StandardSDKClient` — the same SDK client covers concurrency, two identical prepared operations, changed arguments, an expired approval, an unknown outcome and the recovery hold after a real backup restore.
- Claude Code 2.1.329: `claude mcp add` + `claude mcp list` against `/mcp` report **Connected**; a logging proxy records `server/discover` and `tools/list` with `MCP-Protocol-Version: 2026-07-28` and the bearer header. A tool call from Claude Code needs a model turn and was **not run** in Talon's own verification (it uses no paid credentials); try it in your environment, e.g. `claude -p "Look up ticket T-100 with the talon tools, then issue a 20 EUR voucher for it" --allowedTools "mcp__talon__*"`.

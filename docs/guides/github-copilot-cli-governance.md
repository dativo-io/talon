# How to govern GitHub Copilot CLI with Talon

> The narrative companion to this guide — the full experiment, what one signed session record answers, and exactly where the boundary ends — is the [Copilot CLI case study](../explanation/copilot-cli-case-study.md).

This guide explains the verified GitHub Copilot CLI integration implemented in [`dativo-io/talon-full-demo`](https://github.com/dativo-io/talon-full-demo). It shows how a real Copilot CLI session can use Talon for both model traffic and MCP tool calls, while keeping one operational identity, one lifecycle session, attributable spend, data-handling evidence, and signed records.

The tested case is intentionally bounded:

- Copilot calls `release_status` and `release_prepare` through Talon's MCP proxy.
- `release_publish` does not reach the synthetic release service.
- model traffic uses Talon's OpenAI-compatible gateway path;
- personal data detected in prompt traffic is recorded, and configured input redaction is evidenced;
- the resulting gateway and MCP records are exported for one session and cryptographically verified.

Allow about 20 minutes for the first setup and 2–5 minutes for later reruns.

## What this integration proves

The case demonstrates one governed company AI use case across two technical planes:

```text
MODEL PLANE
GitHub Copilot CLI
  → Copilot session shim
  → Talon OpenAI-compatible gateway
  → OpenAI

ACTION PLANE
GitHub Copilot CLI
  → Talon MCP proxy
  → synthetic release MCP server
```

Both planes are attributed to:

```text
Operational identity: coding-assistant
Session:              copilot-<fresh-run-id>
Client:               github-copilot-cli-full-demo
Provenance:           client_asserted
```

The normal Copilot case proves the allowed path and the bounded upstream effect. The separate `make live-check` scenario proves an adversarial `release_publish` call is denied at runtime with Talon enforcement.

## Honest scope boundary

Talon governs only traffic routed through its interception points:

- LLM requests routed through the Talon gateway;
- MCP discovery and tool calls routed through the Talon MCP proxy;
- tool schemas carried in model requests that pass through Talon.

This case does **not** prove Talon controls:

- local shell commands;
- local file edits;
- browser actions;
- direct APIs that bypass Talon;
- the correctness of Copilot's generated answer;
- independent authentication of the Copilot process.

The demo disables shell and write tools using Copilot CLI flags. Those flags are client-side safeguards for the demo, not Talon enforcement.

`client_asserted` is operational attribution, not process attestation. HMAC-signed evidence is tamper-evident and independently verifiable; it is not immutable storage.

## Prerequisites

- Linux or macOS with Bash, Go, Node.js, Python 3, `curl`, `jq`, and Git.
- A checkout of [`dativo-io/talon`](https://github.com/dativo-io/talon).
- A sibling checkout of [`dativo-io/talon-full-demo`](https://github.com/dativo-io/talon-full-demo).
- A real OpenAI API key with billing enabled.
- GitHub Copilot CLI installed. The demo can install the supported official CLI with `make copilot-install`.

The full demo also supports Anthropic for other cases, but the Copilot case itself uses the OpenAI-compatible route.

## 1. Prepare the full demo

```bash
cd ~/talon-full-demo

git pull --ff-only

export OPENAI_API_KEY='sk-...'
# Optional for the other full-demo cases:
export ANTHROPIC_API_KEY='sk-ant-...'

make real-prepare
make real-start
make real-status
```

`make real-prepare` generates the local configuration, stores provider credentials in Talon's encrypted vault, mints one Talon traffic key per use case, and writes `.env`.

For Copilot, the important generated value is:

```text
TALON_CODING_ASSISTANT_KEY
```

Copilot receives this Talon agent key, not the real OpenAI provider key.

The credential flow is:

```text
Copilot presents coding-assistant key
  → Talon resolves agent = coding-assistant
  → Talon computes effective policy
  → Talon retrieves the vaulted OpenAI credential
  → Talon calls OpenAI
```

Do not print `.env` or run `grep KEY .env` in a shared terminal. To inspect only non-secret wiring:

```bash
awk -F= '
  /^(TALON_GATEWAY|TALON_MCP_GATEWAY|COPILOT_MODEL)=/ { print }
' .env
```

## 2. Understand the local services

`make real-start` runs the following local components:

| Component | Default address | Role in this case |
|---|---:|---|
| Talon gateway | `127.0.0.1:8080` | Authenticates `coding-assistant`, applies model/data/cost policy, calls OpenAI, and writes signed gateway evidence. |
| Talon MCP proxy | `127.0.0.1:8081` | Filters MCP discovery, enforces tool policy, forwards allowed calls, and writes signed `proxy_tool_call` evidence. |
| Copilot session shim | `127.0.0.1:8079` | Adds the fresh Talon session and client attribution before forwarding Copilot's OpenAI-compatible requests to the Talon gateway. |
| Release MCP server | `127.0.0.1:8090` | Synthetic upstream with `release_status`, `release_prepare`, and `release_publish`; it records nonce-correlated receipts but performs no external release. |
| Zendesk adapter | `127.0.0.1:8443` | Not used in the Copilot case. |

Verify readiness:

```bash
make real-status
```

Expected checks include the gateway, MCP proxy, Copilot shim, release MCP server, and Copilot CLI.

## 3. Inspect and validate the coding-assistant policy

The demo generates one explicit policy for the `coding-assistant` use case under `config/generated/`.

Locate it without assuming a fixed parent directory:

```bash
AGENT_POLICY="$({
  find config/generated \
    -type f \
    -path '*/coding-assistant/agent.talon.yaml' \
    -print \
    -quit
})"

printf 'Policy: %s\n' "$AGENT_POLICY"
sed -n '1,260p' "$AGENT_POLICY"
```

Validate the single file with the released CLI contract:

```bash
talon validate --file "$AGENT_POLICY"
```

Do not use `talon validate --dir`; released Talon versions used by the demo support single-file validation with `--file` / `-f`.

Inspect these policy domains in the generated YAML:

- agent name and enabled state;
- provider and model allow-lists;
- input scanning and PII action;
- cost limits and session limits;
- tool permissions or constraints used by the MCP boundary;
- evidence and metadata settings inherited from the organization configuration.

The effective policy is the organization baseline from `talon.config.yaml` plus this one explicit `coding-assistant` override.

## 4. Copilot model-path configuration

The runner configures the real Copilot CLI with:

```bash
export COPILOT_PROVIDER_TYPE=openai
export COPILOT_PROVIDER_BASE_URL=http://127.0.0.1:8079/v1/proxy/openai/v1
export COPILOT_PROVIDER_API_KEY="$TALON_CODING_ASSISTANT_KEY"
export COPILOT_MODEL="${COPILOT_MODEL:-gpt-4o-mini}"
export COPILOT_OFFLINE=true
export COPILOT_TASK_WAIT_TIMEOUT_SECONDS=30
```

The base URL points to the session shim, not directly to OpenAI and not directly to the Talon gateway. The shim preserves the real Copilot client while adding the current Talon session and client attribution required for one lifecycle view.

The model path is:

```text
Copilot CLI
  → 127.0.0.1:8079/v1/proxy/openai/v1
  → Talon gateway on 127.0.0.1:8080
  → OpenAI
```

## 5. MCP configuration

The committed template is:

```text
integrations/copilot/copilot-mcp.example.json
```

At run time, `scripts/render-copilot-mcp-config.sh` replaces three placeholders and writes a mode-`0600` file:

```text
.state/copilot-mcp.json
```

The effective shape is:

```json
{
  "mcpServers": {
    "release-gateway": {
      "type": "http",
      "url": "http://127.0.0.1:8081/mcp/proxy",
      "tools": ["release_status", "release_prepare", "release_publish"],
      "headers": {
        "Authorization": "Bearer <coding-assistant Talon key>",
        "X-Talon-Session-ID": "copilot-<fresh-run-id>",
        "X-Talon-Client": "github-copilot-cli-full-demo"
      },
      "timeout": 60000
    }
  }
}
```

The MCP URL must point to Talon's MCP proxy on `:8081`, not directly to the synthetic release server on `:8090`. A direct connection would bypass Talon policy and evidence.

Inspect the generated file with secret-like fields redacted:

```bash
jq '
  walk(
    if type == "object" then
      with_entries(
        if (.key | test("key|token|secret|authorization"; "i")) then
          .value = "<redacted>"
        else
          .
        end
      )
    else
      .
    end
  )
' .state/copilot-mcp.json
```

## 6. Run the real Copilot case

```bash
make real-copilot
```

Every run creates:

- a fresh demo run ID;
- a fresh Copilot session ID;
- a fresh nonce;
- an empty synthetic receipt set;
- a restarted session shim and local integration stack;
- a clean Copilot state directory;
- a new transcript in `.state/`.

The runner gives Copilot a bounded prompt:

```text
1. Call release_status with the exact current run_nonce.
2. Call release_prepare with the same run_nonce.
3. Stop after those two calls.

Do not use release_publish, shell, files, retries, delegation, or subagents.
```

It then invokes Copilot with the relevant flags:

```bash
copilot \
  --prompt "$prompt" \
  --no-ask-user \
  --no-custom-instructions \
  --additional-mcp-config="@.state/copilot-mcp.json" \
  --disable-builtin-mcps \
  --allow-tool='release-gateway(release_status)' \
  --allow-tool='release-gateway(release_prepare)' \
  --deny-tool='shell' \
  --deny-tool='write'
```

The command is bounded by a 90-second hard timeout unless `COPILOT_DEMO_TIMEOUT_SECONDS` is set.

A successful run ends with:

```text
REAL COPILOT CASE PASSED
```

and independently verifies that:

- `release_status` reached the synthetic upstream with the current nonce;
- `release_prepare` reached the synthetic upstream with the current nonce;
- no `release_publish` receipt exists for the current nonce;
- current-run evidence belongs to `coding-assistant`;
- every current-run evidence signature is valid.

## 7. Read the fresh run identity

```bash
source .state/demo-run.env

printf 'Demo run ID:     %s\n' "$TALON_DEMO_RUN_ID"
printf 'Copilot session: %s\n' "$TALON_COPILOT_SESSION_ID"
printf 'Run started:     %s\n' "$TALON_RUN_START_RFC3339"
printf 'Run nonce:       %s\n' "$(cat .state/run-nonce)"
```

The nonce proves the current execution produced the synthetic upstream receipts. It is a demo freshness control, not a substitute for Talon agent authentication.

## 8. Present the verified session

```bash
make present-copilot-all
```

This does not rerun Copilot or call the provider again. It exports, verifies, and projects the latest Copilot session into:

- a concise business receipt;
- a technical Talon session view;
- an evidence timeline;
- MCP boundary results;
- cryptographic verification totals.

The presenter fails closed if records are missing, invalid, from another session, or contain an unexpected MCP action.

## 9. Manual session export and verification

The repository includes a pinned audit-capable Talon CLI profile. Use it for session-filtered signed export so results do not depend on whichever `talon` binary appears first on the shell `PATH`.

```bash
set -a
source .env
source .state/demo-run.env
set +a

SESSION="$TALON_COPILOT_SESSION_ID"
EVIDENCE=".state/${SESSION}.manual.signed.json"

TALON_CLI_PROFILE=audit \
  bash ./scripts/with-talon.sh \
  talon audit list --session "$SESSION"

TALON_CLI_PROFILE=audit \
  bash ./scripts/with-talon.sh \
  talon audit export \
    --format signed-json \
    --session "$SESSION" \
    --output "$EVIDENCE"

TALON_CLI_PROFILE=audit \
  bash ./scripts/with-talon.sh \
  talon audit verify --file "$EVIDENCE"
```

Required verification totals:

```text
Invalid records: 0
Missing signature: 0
Could not parse: 0
Unsupported: 0
```

## 10. Inspect the model and MCP timeline

```bash
jq -r '
  .records
  | sort_by(.timestamp)
  | .[]
  | [
      .timestamp,
      .id,
      .invocation_type,
      .agent_id,
      (.execution.model_used // "-"),
      ((.execution.tools_called // []) | join(",")),
      (if .policy_decision.allowed then "allow" else "deny" end),
      ((.execution.cost // 0) | tostring)
    ]
  | @tsv
' "$EVIDENCE"
```

A normal successful sequence is:

```text
gateway          gpt-4o-mini       allow
proxy_tool_call  release_status    allow
gateway          gpt-4o-mini       allow
proxy_tool_call  release_prepare   allow
gateway          gpt-4o-mini       allow
```

The number of model turns can vary. The pass contract requires exactly the two expected MCP operations.

Inspect only MCP records:

```bash
jq -r '
  .records[]
  | select(.invocation_type == "proxy_tool_call")
  | [
      .id,
      ((.execution.tools_called // []) | join(",")),
      (if .policy_decision.allowed then "allow" else "deny" end),
      (.session_id // "-"),
      (.agent_id // "-")
    ]
  | @tsv
' "$EVIDENCE"
```

Confirm no publish record exists in the selected session:

```bash
jq -e '
  [
    .records[]
    | select(.invocation_type == "proxy_tool_call")
    | .execution.tools_called[]?
    | select(. == "release_publish")
  ]
  | length == 0
' "$EVIDENCE"
```

The stronger upstream-effect assertion is still the nonce-correlated receipt check performed by the demo runner.

## 11. Inspect individual records

```bash
jq -r '.records[].id' "$EVIDENCE"
```

Then use the audit-capable wrapper:

```bash
TALON_CLI_PROFILE=audit \
  bash ./scripts/with-talon.sh \
  talon audit show <record-id>
```

For MCP records, inspect:

- `invocation_type: proxy_tool_call`;
- `agent_id: coding-assistant`;
- the current Copilot session ID;
- `execution.tools_called`;
- policy decision and explanations;
- orchestration client and provenance;
- signature metadata.

## 12. Inspect cost and data handling

Total session cost from evidence:

```bash
jq '[.records[].execution.cost // 0] | add // 0' "$EVIDENCE"
```

Detected personal-data categories and redaction facts:

```bash
jq '
  .records[]
  | {
      id,
      invocation_type,
      detected: .classification.pii_detected,
      redacted: .classification.pii_redacted
    }
' "$EVIDENCE"
```

The tested run recorded email and person data and an input-redaction fact. Treat each future run's evidence as the source of truth; do not hard-code that claim into external reporting.

## 13. Test runtime forbidden-tool enforcement

The normal Copilot run proves the bounded allowed path. Test the separate adversarial enforcement path with:

```bash
make live-check
```

The MCP scene demonstrates two controls:

```text
preventive filtering:
  release_publish absent from discovery

runtime enforcement:
  an adversarial release_publish call is denied
  with TALON_TOOL_FORBIDDEN
```

Do not describe the normal Copilot run as a denied publish attempt. The accurate normal-run statement is: **`release_publish` did not reach the upstream**.

## Pass criteria

The Copilot case passes only when all of the following hold:

- the real GitHub Copilot CLI completes;
- a fresh run ID, session ID, nonce, receipt file, and Copilot state are used;
- model requests reach Talon's gateway as `coding-assistant`;
- `release_status` reaches the synthetic upstream for the current nonce;
- `release_prepare` reaches the synthetic upstream for the current nonce;
- `release_publish` has no current-run upstream receipt;
- the session contains exactly the two expected MCP tool calls;
- all exported records belong to the current Copilot session;
- all signatures verify;
- session cost is derived from evidence, not a hard-coded value.

## What target users gain

For a 250–1,000 person company, the integration turns a developer tool into an explicitly operated AI use case:

- developers keep the real Copilot client;
- platform engineering centralizes provider credentials and a reusable integration boundary;
- security sees data handling and intercepted actions;
- engineering leadership can bound which release operations are available;
- FinOps receives use-case and session-level cost attribution;
- incident responders can reconstruct one model-and-tool lifecycle;
- customer assurance teams can export and verify the controlled activity.

The commercial value is not the small cost of one demo run. It is the repeatable operating model: one identity, one effective policy, one session record, and one proof layer for an existing AI client.

## Cleanup

```bash
make real-stop
```

## Related documentation

- [How to govern coding agents](governing-coding-agents.md)
- [MCP proxy architecture](../ARCHITECTURE_MCP_PROXY.md)
- [Authentication and key scopes](../reference/authentication-and-key-scopes.md)
- [What Talon does to your request](../explanation/what-talon-does-to-your-request.md)
- [Evidence store](../explanation/evidence-store.md)
- [Known coding-agent and orchestration boundaries](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary)

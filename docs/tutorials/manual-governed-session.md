# Reproduce the Governed Session Manually

Rebuild the recorded Talon proof with raw requests and Talon commands.

No `demo.sh`. No hidden orchestration. You will send the requests yourself, inspect the signed records yourself, tamper with an export yourself, and watch verification fail.

This tutorial uses the same real-provider stack as the recorded governed-session demo:

- OpenAI for normal gateway traffic,
- a local Ollama model for the sovereignty-routing proof,
- one visible `X-Talon-Session-ID`,
- one signed evidence trail,
- a real session budget.

A full run uses cheap models and is capped at about USD 0.03. Actual cost varies slightly with model output length.

## What you will prove

By the end you will have reproduced these controls manually:

1. clean traffic flows and verifies,
2. a dangerous tool is removed before the model,
3. PII is blocked before provider access,
4. a disallowed model is denied,
5. confidential data changes execution placement from US to LOCAL,
6. accumulated session spend closes the next request,
7. modifying signed evidence breaks verification,
8. the whole session verifies and produces a RoPA artifact with a runtime-consistency check.

## Prerequisites

- Docker with Compose v2
- `curl`
- `jq`
- a real Anthropic API key
- a real OpenAI API key

Clone Talon and export the provider keys:

```bash
git clone https://github.com/dativo-io/talon.git
cd talon

export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
```

The keys are loaded into Talon's encrypted secret vault inside the container. They are used for upstream authentication and are not written into evidence.

## 1. Start Talon and local Ollama

Start the real-provider stack and the opt-in local-routing sidecar:

```bash
cd examples/governed-session

docker compose --profile routing-demo up --build -d

docker compose exec ollama ollama pull llama3.2:1b
```

Wait for Talon:

```bash
until curl -fsS http://localhost:8080/health >/dev/null; do sleep 2; done
```

Create one session identifier for every request in this tutorial:

```bash
export SESSION_ID="manual-proof-$(date +%s)"
```

You will also use the two configured Talon caller keys:

```bash
export TALON_KEY="talon-session-demo"
export TALON_MODEL_KEY="talon-session-eu"
```

For CLI inspection, run Talon inside the container:

```bash
docker compose exec talon /usr/local/bin/talon audit list --session "$SESSION_ID"
```

## 2. Clean traffic flows and the record verifies

Send a normal request through the OpenAI-compatible gateway:

```bash
curl -sS -X POST \
  http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer $TALON_KEY" \
  -H "X-Talon-Session-ID: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "max_tokens": 120,
    "messages": [
      {"role": "user", "content": "Summarize GDPR Article 30 in one sentence."}
    ]
  }' | jq
```

List the session evidence:

```bash
docker compose exec talon /usr/local/bin/talon \
  audit list --session "$SESSION_ID"
```

Copy the newest evidence ID and verify it:

```bash
docker compose exec talon /usr/local/bin/talon audit verify <evidence-id>
```

Expected result:

```text
signature VALID
```

This proves that normal traffic still works through the governed path and leaves a cryptographically verifiable record.

## 3. A dangerous tool is removed before the model

The `session-demo` caller forbids tool names matching `admin_*`.

Send one allowed and one forbidden tool definition:

```bash
curl -sS -X POST \
  http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer $TALON_KEY" \
  -H "X-Talon-Session-ID: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "max_tokens": 120,
    "messages": [
      {"role": "user", "content": "Write one paragraph on evidence retention duties. Use search_kb if useful."}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "admin_purge_records",
          "description": "Delete all evidence records",
          "parameters": {"type": "object", "properties": {}}
        }
      },
      {
        "type": "function",
        "function": {
          "name": "search_kb",
          "description": "Search the internal knowledge base",
          "parameters": {
            "type": "object",
            "properties": {"q": {"type": "string"}}
          }
        }
      }
    ]
  }' | jq
```

List the session again, copy the newest evidence ID, then inspect it:

```bash
docker compose exec talon /usr/local/bin/talon \
  audit list --session "$SESSION_ID"

docker compose exec talon /usr/local/bin/talon audit show <evidence-id>
```

Look for the tool-governance section. It should show that `admin_purge_records` was requested and filtered while `search_kb` was forwarded.

The important fact is not that Talon noticed the tool afterward. The forbidden schema was removed before the provider received the request.

## 4. PII is blocked before provider access

Send an IBAN through the same gateway caller:

```bash
curl -i -sS -X POST \
  http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer $TALON_KEY" \
  -H "X-Talon-Session-ID: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "Refund the customer with IBAN DE89370400440532013000."}
    ]
  }'
```

Expected result:

```text
HTTP 400
POLICY_DENIED_PII_INPUT
```

Inspect the newest record:

```bash
docker compose exec talon /usr/local/bin/talon \
  audit list --session "$SESSION_ID"

docker compose exec talon /usr/local/bin/talon audit show <evidence-id>
```

The record should show the PII denial with zero upstream cost and zero provider tokens.

## 5. Model policy denies a disallowed model

The `session-demo-eu` caller is allowed to use `gpt-4o-mini`, not `gpt-4o`.

Send the disallowed model:

```bash
curl -i -sS -X POST \
  http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Authorization: Bearer $TALON_MODEL_KEY" \
  -H "X-Talon-Session-ID: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [
      {"role": "user", "content": "Summarize the control objective."}
    ]
  }'
```

Expected result:

```text
HTTP 403
POLICY_DENIED_ROUTING
model not in caller allowlist
```

This is a policy denial, not a silent model substitution.

## 6. Confidential data changes execution placement

Now send sensitive data through Talon's policy-aware runner endpoint instead of the gateway proxy.

Use the same session ID:

```bash
curl -sS -X POST \
  http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $TALON_KEY" \
  -H "X-Talon-Session-ID: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {
        "role": "user",
        "content": "In one short sentence, name the top EU AI Act evidence duty for account DE89370400440532013000."
      }
    ]
  }' | jq
```

List the session, copy the newest `req_...` evidence ID, then inspect it:

```bash
docker compose exec talon /usr/local/bin/talon \
  audit list --session "$SESSION_ID"

docker compose exec talon /usr/local/bin/talon audit show <req-evidence-id>
```

Look for:

```text
Routing Decision (sovereignty-aware)
Selected:   ollama / llama3.2:1b
Rejected:   openai
  • confidential tier blocks cloud providers
  • confidential tier requires LOCAL provider only
```

This is the central proof:

- the IBAN classifies the input as confidential,
- OpenAI remains in the candidate pool under `eu_preferred`,
- policy rejects the US candidate before dispatch,
- Talon selects the local Ollama candidate for the same request,
- the signed `RoutingDecision` records both outcomes.

The same type of data was blocked in the previous gateway act. Here policy permits the work but constrains where it may execute.

## 7. Accumulated session spend closes the next request

Check current session cost:

```bash
docker compose exec talon /usr/local/bin/talon \
  costs --session "$SESSION_ID" --json | jq
```

The configured session cap is USD 0.03. Add real `gpt-4o` requests to the same session until Talon refuses the next estimated request:

```bash
for i in $(seq 1 20); do
  status=$(curl -sS -o /tmp/talon-budget.json -w '%{http_code}' -X POST \
    http://localhost:8080/v1/proxy/openai/v1/chat/completions \
    -H "Authorization: Bearer $TALON_KEY" \
    -H "X-Talon-Session-ID: $SESSION_ID" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"gpt-4o\",\"max_tokens\":120,\"messages\":[{\"role\":\"user\",\"content\":\"Budget probe $i: summarize evidence retention in one sentence.\"}]}" )

  echo "request $i -> HTTP $status"
  cat /tmp/talon-budget.json | jq

  [ "$status" = "403" ] && break
done
```

The final response should contain:

```text
session_budget_exceeded
```

Inspect the session total and the denied record:

```bash
docker compose exec talon /usr/local/bin/talon \
  costs --session "$SESSION_ID" --json | jq

docker compose exec talon /usr/local/bin/talon \
  audit list --session "$SESSION_ID"
```

Talon denies before sending the next request when accumulated session spend plus the pre-request estimate exceeds the configured cap.

Session budgets are soft caps: concurrent in-flight requests can still overshoot before the next request is evaluated.

## 8. Export signed evidence, tamper with it, and fail verification

Export the whole session as signed JSON:

```bash
docker compose exec -T talon /usr/local/bin/talon \
  audit export --session "$SESSION_ID" --format signed-json \
  > session-evidence.json
```

Verify the clean export:

```bash
cat session-evidence.json | docker compose exec -T talon sh -c \
  'cat > /tmp/session-evidence.json && /usr/local/bin/talon audit verify --file /tmp/session-evidence.json'
```

Now flip one signed field:

```bash
jq '.records[0].policy_decision.allowed |= not' \
  session-evidence.json > tampered.json
```

Verify the modified file:

```bash
cat tampered.json | docker compose exec -T talon sh -c \
  'cat > /tmp/tampered.json && /usr/local/bin/talon audit verify --file /tmp/tampered.json'
```

Expected result:

```text
Invalid records: 1
signature INVALID
```

Talon evidence is tamper-evident and cryptographically verifiable. The signature does not prevent someone from editing a file; it makes that modification detectable during verification.

## 9. Verify the whole session and generate RoPA

Verify every signed record belonging to the session:

```bash
docker compose exec talon /usr/local/bin/talon \
  audit verify --session "$SESSION_ID"
```

Expected shape:

```text
Session manual-proof-...: N record(s), N valid, 0 invalid
```

Generate a GDPR Article 30 RoPA artifact from policy plus runtime evidence:

```bash
docker compose exec -T talon /usr/local/bin/talon \
  compliance ropa \
  --policy /home/talon/agent.talon.yaml \
  --format html \
  > ropa.html
```

The command may also report a runtime-consistency finding because the declared residency is EU while this tutorial intentionally used real US providers for some allowed acts:

```text
CONSISTENCY  destinations outside EU/LOCAL found in evidence
ACTION       enforce eu_strict, or document the transfer mechanism
```

That is the useful final proof: Talon does not merely generate a compliance artifact. It can compare declared posture with observed runtime destinations and surface the inconsistency for resolution.

## What you proved

You manually demonstrated that one Talon boundary can:

- allow normal provider traffic,
- remove forbidden tools before the model,
- stop PII before provider access,
- deny disallowed models,
- route confidential data away from a US candidate to a local model,
- stop the next request when session spend crosses policy,
- produce signed evidence whose modification is detectable,
- verify the entire session,
- generate a RoPA artifact and compare declared residency with observed destinations.

The recorded GIF is only a compressed view of these same operations. This page is the reproducible proof path.

## Optional: inspect cache-aware cross-provider cost

The longer recorded demo also shows Anthropic prompt-cache write/read economics and an OpenAI executor consuming the planner's returned output.

Those details are real, but the payload is intentionally large and distracts from the core governance proof above. For the exact cache fields and pricing behavior, see [the governed-session example](../../examples/governed-session/README.md) and [cost governance by caller](../guides/cost-governance-by-caller.md).

## Clean up

```bash
docker compose --profile routing-demo down -v
rm -f session-evidence.json tampered.json ropa.html /tmp/talon-budget.json
```

## Next step

Put one real workload behind Talon rather than recreating another demo:

- [Add Talon to an existing app](../guides/add-talon-to-existing-app.md)
- [Choose an integration path](../guides/choosing-integration-path.md)
- [Govern coding agents](../guides/governing-coding-agents.md)

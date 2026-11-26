# Evidence Integrity: 5-Minute Proof Demo

This walkthrough gives you a fast auditor-ready proof:

1. run a request,
2. verify evidence over the API,
3. export signed evidence,
4. tamper one field,
5. show CLI verification failure.

Core message:

> Signed, verifiable evidence — not just logs. Talon signs every evidence record at creation time. If any signed field changes later, verification fails.

## Prerequisites

- A dedicated local test installation of the released Talon version, with one authenticated use case and a working model route. Follow [connect an existing application](../guides/add-talon-to-existing-app.md) or the optional Compose walkthrough in [try Talon](quickstart-demo.md).
- `curl`, `jq`, and the matching `talon` CLI with access to that same installation's evidence store and signing key. An unrelated host CLI cannot verify the container's records.
- Load the use-case key as `TALON_USE_CASE_KEY` and the operator key as `TALON_ADMIN_KEY` from their approved secret sources. Only for the loopback-only Compose fixture, use `TALON_USE_CASE_KEY=talon-demo-key`; its admin key is unset. Never use that fixture for production.
- Use an otherwise idle synthetic installation so the newest record belongs to this test. Do not export or edit production evidence.

## 1) Run one request

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TALON_USE_CASE_KEY" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Summarize this support ticket and include next actions."}]
  }'
```

Confirm the response succeeds before continuing; HTTP 401 means the use-case key is missing or invalid. A model denial is a different test, not proof of a successful upstream request.

## 2) Verify the latest record over the API

```bash
ID=$(curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" 'http://localhost:8080/v1/evidence?limit=1' | jq -r '.entries[0].id')
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" "http://localhost:8080/v1/evidence/$ID/verify" | jq .
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" "http://localhost:8080/v1/evidence/$ID" | jq '{signature, policy_decision, execution: {model_used: .execution.model_used, cost: .execution.cost, tokens: .execution.tokens}}'
```

- Confirm the verify response reports the signature as valid.
- Confirm the record carries the signature next to the policy decision and the trust/spend details (cost, tokens, model, provider).

## 3) Export signed evidence

Run the CLI commands below in the same installation, with the same configuration and signing key. For the optional Compose fixture, use the release-matched Compose command prefix from the [quickstart](quickstart-demo.md) (`exec talon /usr/local/bin/talon`); the export path is then inside that container. Copy the file out for the tamper exercise and back to a separate test path for verification, or use a local CLI installation instead.

```bash
talon audit export --format signed-json --limit 20 --output signed-evidence.json
```

## 4) Verify the file (expected success)

```bash
talon audit verify --file signed-evidence.json
```

Expected outcome:

- valid records > 0
- invalid/malformed/unsupported = 0
- exit code 0

## 5) Modify one signed field

Copy `signed-evidence.json` to `tampered-evidence.json`, then edit only the copy and change one signed value, for example:

- `policy_decision.allowed`
- `execution.cost`
- `audit_trail.input_hash`
- `timestamp`

Do not update `signature`.

## 6) Verify again (expected failure)

```bash
talon audit verify --file tampered-evidence.json
```

Expected outcome:

- invalid records > 0
- non-zero exit code

This is the proof moment: Talon detects post-creation tampering.

## 7) One-paragraph compliance statement

Use this as a description of integrity verification, not a certification or proof of downstream effects. A signing-key compromise can forge records.

> Talon signs every evidence record at creation time with HMAC-SHA256 and stores the signature with policy decision, hashes, model, and cost metadata. Teams can verify records later over the API (`GET /v1/evidence/{id}/verify`) or the CLI (`talon audit verify` / `talon audit verify --file`). If a signed field is modified after creation, verification fails.

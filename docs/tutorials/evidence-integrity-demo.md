# Evidence Integrity: 5-Minute Proof Demo

This walkthrough gives you a fast auditor-ready proof:

1. run a request,
2. verify evidence in the dashboard,
3. export signed evidence,
4. tamper one field,
5. show CLI verification failure.

Core message:

> Signed, verifiable evidence — not just logs. Talon signs every evidence record at creation time. If any signed field changes later, verification fails.

## Prerequisites

- Talon running locally (for example via `examples/docker-compose`)
- `talon` CLI available in the environment where you run verification

## 1) Run one request

```bash
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Summarize this support ticket and include next actions."}]
  }'
```

## 2) Open dashboard evidence and verify

- Open [http://localhost:8080/dashboard](http://localhost:8080/dashboard).
- Go to the **Evidence** tab.
- Click **Verify** for your latest row (or **Verify visible records**).
- Confirm integrity state shows `✓ Verified`.
- Click **Detail** and confirm the signature block + trust/spend details (cost, tokens, model, provider).

## 3) Export signed evidence

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

Edit `signed-evidence.json` and change one value in a record, for example:

- `policy_decision.allowed`
- `execution.cost`
- `audit_trail.input_hash`
- `timestamp`

Do not update `signature`.

## 6) Verify again (expected failure)

```bash
talon audit verify --file signed-evidence.json
```

Expected outcome:

- invalid records > 0
- non-zero exit code

This is the proof moment: Talon detects post-creation tampering.

## 7) One-paragraph compliance statement

Use this during audits or buyer calls:

> Talon signs every evidence record at creation time with HMAC-SHA256 and stores the signature with policy decision, hashes, model, and cost metadata. Teams can verify records later from dashboard or CLI (`talon audit verify` / `talon audit verify --file`). If a signed field is modified after creation, verification fails.

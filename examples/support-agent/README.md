# Support Agent Example

Policy-enforced eSIM / customer support agent with PII detection (IMSI, ICCID, EID, email, IBAN) and data sovereignty.

## Quick run

```bash
# From repo root or with TALON_DATA_DIR set
export OPENAI_API_KEY=sk-proj-...

talon run --tenant acme --agent support-agent --policy examples/support-agent/agent.talon.yaml \
  "How do I activate an eSIM for ICCID 8943102012345678901?"
```

## Dry run (no LLM call)

```bash
talon run --tenant acme --agent support-agent --policy examples/support-agent/agent.talon.yaml --dry-run \
  "Customer email user@example.at asked about IMSI 232011234567890"
```

Dry-run shows policy decision, PII detected (if any), and input tier.

## Validate

```bash
talon validate -f examples/support-agent/agent.talon.yaml
```

## Notes

- **tier_2** uses `bedrock_only: false` so PII-bearing queries work with only an OpenAI key (no AWS Bedrock).
- Telecom forbidden patterns include `ki_key` and `apn_credential`; adjust per your security policy.
- For project-scoped data: `TALON_DATA_DIR=$(pwd)/.talon talon run ...`

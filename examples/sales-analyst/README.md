# Sales Analyst Example

Financial and sales data analysis agent with PII redaction and cost limits.

## Quick run

```bash
export OPENAI_API_KEY=sk-proj-...

talon run --tenant acme --agent sales-analyst --policy examples/sales-analyst/agent.talon.yaml \
  "Summarize Q4 revenue trends and top 3 products by revenue"
```

## Dry run

```bash
talon run --tenant acme --agent sales-analyst --policy examples/sales-analyst/agent.talon.yaml --dry-run \
  "Revenue was 2300000 EUR in 2025"
```

## Costs and audit

```bash
talon costs --tenant acme --agent sales-analyst
talon audit list --tenant acme --agent sales-analyst
talon report --tenant acme
```

## Validate

```bash
talon validate -f examples/sales-analyst/agent.talon.yaml
```

## Notes

- `redact_pii: true` ensures outputs are scanned for PII leakage.
- For project-scoped data: `TALON_DATA_DIR=$(pwd)/.talon`.

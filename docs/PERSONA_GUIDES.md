# Talon Persona Guides

This guide describes how different roles in your organization use Talon: what they care about, which commands they run, and how policy configuration affects them.

---

## Who Uses Talon?

| Persona | Primary goal | Typical tasks |
|----------|--------------|----------------|
| **DevOps Engineer** | Get agents running and keep them healthy | Install, init, run, validate, serve |
| **Compliance Officer** | Prove processing records and regulatory readiness | Audit trail, exports, verification, reports |
| **CTO / Head of Engineering** | Oversight, costs, and governance posture | Costs, report, memory health, config |
| **SecOps / Security Officer** | Secrets, PII, injection prevention, policy enforcement | Secrets vault, audit, PII tiers, budget denial |
| **FinOps Engineer** | Cost control and budget compliance | Costs, budgets, model routing, export for analysis |

---

## DevOps Engineer

**What they care about:** Getting Talon installed, initializing projects, running agents with policy enforcement, and validating configuration. They need a smooth path from zero to a working governed agent.

### Key commands

Use **`talon run`** (not `talon` alone) to run an agent; flags like `--attach` go after `run`, and the prompt is the last argument: `talon run [flags] "your prompt"`.

```bash
# Install and bootstrap
make build                                    # or: go install .../cmd/talon@latest
talon init --name my-agent --owner dev@co.at  # Create agent.talon.yaml + talon.config.yaml
talon validate                                # Check policy is valid
talon validate --strict                       # Strict compliance check

# Run agents (subcommand is always "run"; prompt is the final quoted argument)
talon run "Summarize EU AI regulation trends"                    # Real run with LLM
talon run --dry-run "What is revenue?"                            # Policy check only, no LLM call
talon run --attach report.pdf "Summarize this document"           # Attachments (injection-scanned)
talon run --tenant acme --agent sales-bot "Your prompt here"       # Multi-tenant

# Serve (triggers, webhooks, cron)
talon serve --port 8080
```

### Workflow example

1. Clone repo, `make build`, then `cd my-project && talon init`.
2. Set LLM key: `export OPENAI_API_KEY=sk-...` or `talon secrets set openai-api-key "sk-..."`.
3. `talon validate` to confirm policy loads.
4. `talon run "First query"` to run with real LLM; check evidence with `talon audit list`.
5. For production: store keys in vault, set `TALON_DATA_DIR` and crypto keys, then `talon serve`. For **project-scoped onboarding** or evaluation (e.g. trying Talon in a repo without touching `~/.talon`), use `TALON_DATA_DIR=$(pwd)/.talon` so vault and evidence DBs live under the project directory.

### Policy configuration that matters

- **`agent.name`**, **`agent.version`** — Identity and versioning. When you run without `--agent`, the runtime agent ID (evidence, memory) is taken from `agent.name` in the loaded policy.
- **`policies.cost_limits`** — Per-request, daily, monthly (DevOps often sets these with FinOps).
- **`policies.model_routing`** — Tier 0/1/2 models; Tier 2 may require Bedrock for EU-only.
- **`triggers`** — Cron and webhooks if using `talon serve`.

---

## Compliance Officer

**What they care about:** GDPR Article 30 processing records, NIS2 incident evidence, EU AI Act transparency, and tamper-evident audit trails. They need to export evidence, verify integrity, and produce reports for auditors or regulators.

### Key commands

```bash
# List and inspect evidence
talon audit list --limit 20                  # Recent evidence records
talon audit list --tenant acme               # Filter by tenant (multi-tenant isolation)
talon audit show <evidence-id>               # Full record: HMAC, PII, tiers, policy reasons
talon audit verify <evidence-id>             # Verify HMAC-SHA256 signature

# Export for regulators
talon audit export --format csv --from 2026-02-01 --to 2026-02-28
talon audit export --format json --limit 1000

# Summary and reporting
talon report                                 # Compliance summary (counts, cost)
talon report --tenant acme                   # Per-tenant summary
```

### Workflow example

1. **Monthly GDPR Art. 30:** Run `talon audit export --format csv --from ... --to ...` and attach to processing records.
2. **Incident review:** Use `talon audit list` to find the time window, then `talon audit show <id>` for full classification, PII detected, and policy decision.
3. **Integrity check:** Run `talon audit verify <id>` on sampled evidence to confirm HMAC-SHA256 intact.
4. **Board/auditor summary:** Use `talon report` and optionally `talon report --tenant <id>` for per-tenant posture.

### Policy configuration that matters

- **`compliance.frameworks`** — Declared frameworks (e.g. gdpr, eu-ai-act, nis2).
- **`compliance.data_residency`** — e.g. `eu`.
- **`audit.retention_days`**, **`audit.log_level`** — How long evidence is kept and how detailed.
- **`policies.data_classification`** — Input/output scan, PII handling; affects what appears in evidence.

---

## CTO / Head of Engineering

**What they care about:** Strategic oversight: cost visibility, multi-tenant isolation, agent health, and governance posture. They want a single view of “how are we doing?” without running low-level audit queries.

### Key commands

```bash
# Cost and posture
talon costs                                   # Cost by tenant/agent (today + month)
talon costs --tenant acme                     # Per-tenant cost breakdown
talon costs --agent sales-bot                 # Per-agent cost
talon report                                  # Compliance summary (evidence count, cost)
talon report --tenant acme

# Agent memory and health
talon memory list --agent sales-analyst       # Memory entries for an agent
talon memory health --agent sales-analyst     # Trust distribution, conflicts
talon memory audit                            # Evidence chain for memory

# Configuration and validation
talon config show                             # Resolved config (data dir, keys, DBs)
talon validate --strict                       # Policy and compliance check
talon version                                 # Binary version and build info
```

### Workflow example

1. **Weekly review:** Run `talon costs` and `talon report` to see spend and evidence volume per tenant.
2. **New agent rollout:** After enabling memory in policy, use `talon memory health --agent <name>` to monitor trust and conflicts.
3. **Pre-audit:** Run `talon validate --strict` and `talon config show` to confirm policy and environment.

### Policy configuration that matters

- **`policies.cost_limits`** — Daily/monthly caps; CTO cares that they align with budget.
- **`agent.model_tier`** — Default tier for the agent.
- **`memory`** — Memory is off by default; enable it in policy (see MEMORY_GOVERNANCE.md) for `memory list` / `memory health` to show data. If enabled, CTO may track `memory health` and rollback when needed.

---

## SecOps / Security Officer

**What they care about:** Secrets management, PII handling, prompt-injection prevention, and policy enforcement (e.g. budget denials). They need to see who accessed which secrets, that PII drives model tiering, and that injections are detected and optionally blocked.

### Key commands

```bash
# Secrets vault
talon secrets set openai-api-key "sk-..."    # Store encrypted (AES-256-GCM)
talon secrets list                           # List secrets (metadata only; values hidden)
talon secrets audit                          # Who accessed which secret, when, allow/deny
talon secrets rotate openai-api-key          # Re-encrypt with fresh nonce

# Evidence and policy enforcement
talon audit list                             # See allowed vs denied requests
talon audit show <evidence-id>               # PII detected, tier, policy reasons, HMAC
talon run --dry-run "..."                    # Policy decision without LLM (no spend)

# Multi-tenant (isolation)
talon run --tenant acme --agent sales-bot "..."  # Scoped run
talon audit list --tenant acme               # Only acme evidence
talon secrets set openai-api-key "..."       # Per-tenant key when using vault
```

### Workflow example

1. **Secrets hygiene:** Rotate keys with `talon secrets rotate <name>`; confirm with `talon secrets audit` that access is logged.
2. **PII and tiering:** Run a query containing email/IBAN; use `talon audit show <id>` to confirm “PII Detected” and higher tier (e.g. tier 2) and correct model.
3. **Budget enforcement:** Set a very low daily budget in `agent.talon.yaml`, run a real request; confirm denial and that `talon audit show` for the denied request shows budget reason.
4. **Attachment injection:** Run with `--attach` on a file containing injection text; verify evidence or logs show injection detection (and block if policy is `block_and_flag`).

### Policy configuration that matters

- **`policies.data_classification`** — `input_scan`, `output_scan`, `redact_pii`; drives PII detection and tiering.
- **`policies.cost_limits`** — Budget denial when exceeded.
- **`attachment_handling`** — Injection detection and action (`block_and_flag`, `warn`, `log`).
- **`secrets.allowed` / `secrets.forbidden`** — Which secrets the agent may use.

---

## FinOps Engineer

**What they care about:** Cost per request, per tenant, and per agent; budget limits; and model routing efficiency (cheaper models for non-sensitive data, pricier for PII). They need numbers for forecasting and to ensure spend stays within policy.

### Key commands

```bash
# Cost visibility
talon costs                                   # Today and month by tenant/agent
talon costs --tenant acme                     # Per-tenant
talon costs --agent sales-bot                 # Per-agent

# Evidence (cost per request)
talon audit list --limit 50                   # Each row shows model, cost, duration
talon audit show <evidence-id>                # Tokens (in/out), cost, model

# Export for analysis
talon audit export --format csv               # Spreadsheet: cost, model_used, duration_ms, etc.
talon audit export --format json --limit 1000 # Programmatic analysis

# Summary
talon report                                  # Cost today and this month
talon report --tenant acme
```

### Workflow example

1. **Daily check:** Run `talon costs` to see today’s and month’s spend per tenant/agent.
2. **Model mix:** Use `talon audit list` and `talon audit show <id>` to confirm tier 0 uses cheaper models (e.g. gpt-4o-mini) and tier 1/2 use higher-cost models when PII is present.
3. **Budget alignment:** Compare `talon costs` output to `policies.cost_limits` in `agent.talon.yaml`; use `talon report` for high-level totals.
4. **Forecasting:** Export with `talon audit export --format csv` and analyze cost, model_used, and duration in a spreadsheet or BI tool.

### Policy configuration that matters

- **`policies.cost_limits`** — `per_request`, `daily`, `monthly`; FinOps defines or tunes these.
- **`policies.model_routing`** — Tier 0/1/2 model choice directly affects cost (tier 0 = cheapest, tier 2 = most expensive when PII is present).

---

## See also

- [QUICKSTART.md](QUICKSTART.md) — Install, init, first run, audit, secrets, memory.
- [ADOPTION_SCENARIOS.md](ADOPTION_SCENARIOS.md) — Greenfield, brownfield custom, brownfield vendor.
- [VENDOR_INTEGRATION_GUIDE.md](VENDOR_INTEGRATION_GUIDE.md) — MCP proxy and vendor compliance.
- [MEMORY_GOVERNANCE.md](MEMORY_GOVERNANCE.md) — Agent memory, categories, and rollback.

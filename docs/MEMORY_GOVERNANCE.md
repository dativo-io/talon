# Agent Memory Governance

Talon's agent memory is a compliance asset. Every learning is governed, audited, and defensible.

## How It Works

- Agents compress each run into ~500-token observations (not raw transcripts)
- Every write passes through a multi-layer governance pipeline before persisting
- Every entry links to an HMAC-signed evidence record
- Memory reads injected into LLM prompts are recorded in evidence for traceability

## Governance Pipeline

Writes pass through these checks in order:

1. **Hardcoded forbidden categories** -- `policy_modifications`, `prompt_injection`, `credential_data` are always rejected (Go-level backstop, independent of OPA)
2. **Max entry size** -- rejects entries exceeding `max_entry_size_kb` (configurable)
3. **OPA policy evaluation** -- unified governance via `EvaluateMemoryWrite()` (degrades gracefully if OPA unavailable)
4. **Category validation** -- allowed/forbidden lists from `.talon.yaml`
5. **PII scanning** -- never persist customer data
6. **Policy override detection** -- agents cannot alter their own rules
7. **Provenance tracking** -- source type + trust score assignment
8. **Conflict detection** -- FTS5 keyword overlap; fail-closed (flags `pending_review` on error)

## Configuration (.talon.yaml)

```yaml
memory:
  enabled: true
  mode: active                  # active | shadow | disabled
  max_entries: 1000             # cap per agent; oldest evicted when exceeded
  max_entry_size_kb: 16         # reject entries larger than this
  max_prompt_tokens: 2000       # cap memory tokens injected into LLM prompts
  retention_days: 90            # auto-purge entries older than this
  review_mode: auto             # auto | human-review | read-only
  allowed_categories:
    - factual_corrections
    - user_preferences
    - domain_knowledge
    - procedure_improvements
  forbidden_categories:
    - credential_data
  prompt_categories:            # which categories to include in LLM prompts (empty = all)
    - domain_knowledge
    - procedure_improvements
  audit: true
  governance:
    conflict_resolution: auto   # auto | flag_for_review | reject
    conflict_similarity_threshold: 0.6
    trust_score_overrides: true
```

### Memory Modes

| Mode | Governance Checks | Persistence | Prompt Injection |
|------|-------------------|-------------|------------------|
| `active` (default) | All checks run | Yes | Memory included in prompts |
| `shadow` | All checks run, results logged | No writes | Memory not included |
| `disabled` | None | No writes | Memory not included |

Shadow mode is designed for evaluation periods: operators see exactly what the agent _would_ learn and which checks pass/fail, without committing any data.

### Conflict Resolution Modes

| Mode | Behavior |
|------|----------|
| `auto` | Higher trust score wins; lower becomes pending_review |
| `flag_for_review` | All conflicts set to pending_review |
| `reject` | Conflicting entries are rejected outright |

### Trust Scores

| Source | Score | Description |
|--------|-------|-------------|
| manual | 100 | Human-entered via CLI |
| user_input | 90 | Direct user instruction |
| agent_run | 70 | Automated agent execution |
| tool_output | 50 | External tool result |
| webhook | 40 | Webhook-triggered run |

### Prompt Injection Controls

- **pending_review filter:** entries with `review_status = "pending_review"` are excluded from LLM prompts
- **prompt_categories:** only listed categories enter the LLM context (empty = all allowed)
- **max_prompt_tokens:** caps total memory tokens injected; oldest/lowest-trust entries evicted first
- **tier re-classification:** memory content is scanned by the classifier before model routing to detect tier upgrades from persisted classified data

### Retention & Expiration

- `retention_days`: entries older than N days are auto-purged
- `max_entries`: hard cap per agent; oldest entries (by version) evicted when exceeded
- Both run automatically via `StartRetentionLoop()` in `talon serve` (daily interval)

## CLI Commands

```bash
# Browse memory index
talon memory list --agent sales-analyst

# Full entry detail
talon memory show mem_a1b2c3d4

# Full-text search
talon memory search "revenue target"

# Rollback to specific version
talon memory rollback --agent sales-analyst --to-version 5 --yes

# Trust distribution and conflict status
talon memory health --agent sales-analyst

# Evidence chain verification
talon memory audit --agent sales-analyst
```

## Privacy Tags

Use privacy tags in shared enterprise context files:

- `<private>...</private>` -- content available for current agent run, never persisted to memory
- `<classified:tier_N>...</classified>` -- propagates data tier to model routing (ensures sensitive data only goes to approved models)

Example context file:

```markdown
# Company Procedures

Our standard process for handling refunds is documented here.

<private>Internal discount code: ACME-2026-REFUND</private>

Revenue targets: <classified:tier_1>Q4 target is EUR 2.5M</classified>
```

## Compliance Mapping

| Requirement | Talon Feature |
|-------------|---------------|
| GDPR Art. 5(1)(c) (data minimization) | Compressed observations, max_entry_size_kb, retention_days |
| GDPR Art. 25 (data protection by design) | `<private>` tag stripping, PII scan |
| GDPR Art. 30 (processing records) | Evidence-linked memory entries, memory read audit |
| EU AI Act Art. 9 (risk management) | Provenance tracking + conflict detection + OPA governance |
| EU AI Act Art. 14 (human oversight) | flag_for_review + memory health + shadow mode |
| ISO 27001 A.8.15 (logging) | Full audit trail with HMAC signatures |
| ISO 27001 A.8.24 (cryptography) | Evidence integrity via HMAC-SHA256 |

## Observability

Memory operations emit OpenTelemetry metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `memory.writes.total` | Counter | Total memory write operations |
| `memory.writes.denied` | Counter | Writes denied by governance |
| `memory.conflicts.detected` | Counter | Conflicts found during validation |
| `memory.reads.total` | Counter | Read operations (list, search) |
| `memory.entries.count` | Gauge | Current number of entries |

All operations emit OTel spans with `tenant_id`, `agent_id`, and relevant attributes.

## Memory Poisoning Defense

Talon implements multiple layers of defense against memory poisoning attacks:

- **Hardcoded forbidden categories:** `policy_modifications`, `prompt_injection`, `credential_data` are always blocked (Go-level, before OPA)
- **OPA policy evaluation:** unified governance; custom Rego rules can enforce additional constraints
- **Max entry size:** rejects oversized payloads that could inflate context
- **Policy override detection:** content containing phrases like "ignore policy" or "bypass policy" is rejected
- **Trust scoring:** entries from lower-trust sources (webhooks, tools) can be flagged for review when conflicting with higher-trust entries
- **Conflict detection:** FTS5-based keyword overlap identifies contradictory information; fail-closed on error
- **Prompt filtering:** `pending_review` entries are excluded from LLM prompts, preventing unvalidated data from influencing decisions
- **Rollback:** `talon memory rollback` restores memory to any previous version if poisoning is detected
- **Health monitoring:** `talon memory health` surfaces trust distribution and pending conflicts

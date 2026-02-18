# Agent Memory Governance

Talon's agent memory is a compliance asset. Every learning is governed, audited, and defensible.

## How It Works

- Agents compress each run into ~500-token observations (not raw transcripts)
- Every write passes 5 governance checks before persisting
- Every entry links to an HMAC-signed evidence record

## Governance Checks

1. **Category validation** -- allowed/forbidden lists in .talon.yaml
2. **PII scanning** -- never persist customer data
3. **Policy override detection** -- agents cannot alter their own rules
4. **Provenance tracking** -- source type + trust score
5. **Conflict detection** -- flag or reject contradictory entries

## Configuration (.talon.yaml)

```yaml
memory:
  enabled: true
  allowed_categories:
    - factual_corrections
    - user_preferences
    - domain_knowledge
    - procedure_improvements
  forbidden_categories:
    - credential_data
  governance:
    conflict_resolution: auto  # auto | flag_for_review | reject
    conflict_similarity_threshold: 0.6
    trust_score_overrides: true
```

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
| GDPR Art. 25 (data protection by design) | `<private>` tag stripping |
| GDPR Art. 30 (processing records) | Evidence-linked memory entries |
| EU AI Act Art. 9 (risk management) | Provenance tracking + conflict detection |
| EU AI Act Art. 14 (human oversight) | flag_for_review + memory health |
| ISO 27001 A.8.15 (logging) | Full audit trail with HMAC signatures |

## Memory Poisoning Defense

Talon implements multiple layers of defense against memory poisoning attacks:

- **Hardcoded forbidden categories:** `policy_modifications`, `prompt_injection`, `credential_data` are always blocked
- **Policy override detection:** content containing phrases like "ignore policy" or "bypass policy" is rejected
- **Trust scoring:** entries from lower-trust sources (webhooks, tools) can be flagged for review when conflicting with higher-trust entries
- **Conflict detection:** FTS5-based keyword overlap identifies contradictory information
- **Rollback:** `talon memory rollback` restores memory to any previous version if poisoning is detected
- **Health monitoring:** `talon memory health` surfaces trust distribution and pending conflicts

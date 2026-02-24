# Agent Memory Governance

Talon's agent memory is a compliance asset. Every learning is governed, audited, and defensible.

## Use cases

| Use case | What happens |
|----------|----------------|
| **Teach & recall** | Agent stores a fact from a run; later runs get that memory injected so the model can answer from context (e.g. "Where is our HQ?" after "Remember: HQ is Berlin."). |
| **Factual corrections** | User corrects a fact; response keywords (e.g. "actually", "updated") cause the run to be stored as `factual_corrections`. |
| **User preferences** | User states a preference (e.g. "I prefer bullet points"); stored as `user_preferences` and available to later runs. |
| **Procedures** | Descriptions of steps or "best practice" are stored as `procedure_improvements` (procedural memory). |
| **Deduplication** | With `dedup_window_minutes`, the same prompt (and attachments) within the window does not create a duplicate entry. |
| **Shadow evaluation** | Use `mode: shadow` to log what would be written and injected without persisting; then switch to `active`. |

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
    dedup_window_minutes: 60    # optional; same prompt+attachments within window → no new memory entry
```

### Memory Modes


| Mode               | Governance Checks              | Persistence | Prompt Injection           |
| ------------------ | ------------------------------ | ----------- | -------------------------- |
| `active` (default) | All checks run                 | Yes         | Memory included in prompts |
| `shadow`           | All checks run, results logged | No writes   | Memory not included        |
| `disabled`         | None                           | No writes   | Memory not included        |


Shadow mode is designed for evaluation periods: operators see exactly what the agent *would* learn and which checks pass/fail, without committing any data.

### Conflict Resolution Modes


| Mode              | Behavior                                              |
| ----------------- | ----------------------------------------------------- |
| `auto`            | Higher trust score wins; lower becomes pending_review |
| `flag_for_review` | All conflicts set to pending_review                   |
| `reject`          | Conflicting entries are rejected outright             |


### Trust Scores


| Source      | Score | Description               |
| ----------- | ----- | ------------------------- |
| manual      | 100   | Human-entered via CLI     |
| user_input  | 90    | Direct user instruction   |
| agent_run   | 70    | Automated agent execution |
| tool_output | 50    | External tool result      |
| webhook     | 40    | Webhook-triggered run     |


### Input-hash deduplication 

- **Dedup window:** When `memory.governance.dedup_window_minutes` is set (e.g. `60`), a second run with the same prompt (and same attachment fingerprint) within that window does **not** create a new memory entry. The evidence record is still created; only the memory write is skipped.
- **Input fingerprint:** The fingerprint is the hash of the user prompt plus attachment content hashes (same prompt + same attachments → same hash). See [reference/configuration.md](reference/configuration.md) for `dedup_window_minutes`.
- **Per-run skip:** Use `talon run --no-memory` (or `RunRequest.SkipMemory: true`) to skip memory write for that run only.
- **Audit:** `talon audit show` with no ID shows the latest evidence record. `talon audit show <evidence-id>` shows a specific record.
- **Retention:** `max_entries` is enforced after each run (oldest evicted when over cap). `retention_days` and purge run in `talon serve` (daily).

### Prompt injection controls

- **Order:** Injected entries are sorted by **trust score (highest first)** so the model sees the most trusted context first.
- **pending_review filter:** Entries with `review_status = "pending_review"` are excluded from LLM prompts.
- **prompt_categories:** Only listed categories enter the LLM context (empty = all allowed).
- **max_prompt_tokens:** Caps total memory tokens injected; when over cap, lower-trust or older entries are excluded.
- **Tier re-classification:** Memory content is scanned before model routing so tier upgrades from persisted data are respected.

### Three-Type Memory and Relevance-Scored Retrieval

Talon uses a **three-type memory model** (semantic, episodic, procedural) for retrieval scoring:


| Type           | Description                                            | Default weight |
| -------------- | ------------------------------------------------------ | -------------- |
| **semantic**   | What the agent knows: facts, preferences, constraints  | 0.6            |
| **episodic**   | What happened: specific interactions, outcomes, events | 0.3            |
| **procedural** | How to do things: learned behaviors, response patterns | 0.1            |


When the run has a non-empty **prompt** and `max_prompt_tokens` is set, memory is retrieved via **relevance-scored retrieval** instead of flat timestamp order. The composite score is:

- **Relevance** (40%): keyword overlap between the current prompt and each entry’s title (governance `keywordSimilarity`)
- **Recency** (30%): decay by age (`1 / (1 + days_since)`)
- **Type weight** (20%): semantic > episodic > procedural
- **Trust** (10%): normalized trust score (0–1)

Retrieval returns entries by score; when building the prompt, Talon then **sorts by trust (highest first)** and applies the **token cap** (`max_prompt_tokens`). When there is no prompt (e.g. scheduled run), retrieval uses **timestamp-ordered** list with the same trust sort and token cap.

### Consolidation and point-in-time

- **Consolidation:** New observations are evaluated against existing entries (ADD / UPDATE / INVALIDATE / NOOP). Invalidated entries are kept for audit but excluded from list and prompt injection.
- **Point-in-time (as-of):** For compliance (e.g. NIS2, EU AI Act), use `talon memory as-of <RFC3339> --agent <name>` to retrieve entries valid at that time.

### Retention & Expiration

- `retention_days`: entries older than N days are auto-purged
- `max_entries`: hard cap per agent; oldest entries (by version) evicted when exceeded
- Both run automatically via `StartRetentionLoop()` in `talon serve` (daily interval)

## Verify memory is used

1. Enable memory in `.talon.yaml` (`memory.enabled: true`, optional `max_prompt_tokens` for relevance retrieval).
2. Run once to teach: `talon run "Remember: our company headquarters is in Berlin."`
3. Run again to recall: `talon run "Where is our company headquarters?"` — the model receives the stored memory in the prompt.
4. Confirm in audit: `talon audit show` shows **Memory Tokens** and **Memory Reads** for the second run.

See [How to verify memory is used](guides/memory-verification.md) for a full CLI walkthrough.

## CLI Commands

```bash
# Browse memory index
talon memory list --agent sales-analyst

# Full entry detail
talon memory show mem_a1b2c3d4

# Full-text search
talon memory search "revenue target"

# Rollback to a specific entry (soft-delete newer entries for audit)
talon memory rollback mem_a1b2c3d4 --yes

# Trust distribution and conflict status
talon memory health --agent sales-analyst

# Evidence chain verification
talon memory audit --agent sales-analyst

# Point-in-time (compliance)
talon memory as-of 2025-06-01T12:00:00Z --agent sales-analyst
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


| Requirement                              | Talon Feature                                              |
| ---------------------------------------- | ---------------------------------------------------------- |
| GDPR Art. 5(1)(c) (data minimization)    | Compressed observations, max_entry_size_kb, retention_days |
| GDPR Art. 25 (data protection by design) | `<private>` tag stripping, PII scan                        |
| GDPR Art. 30 (processing records)        | Evidence-linked memory entries, memory read audit          |
| EU AI Act Art. 9 (risk management)       | Provenance tracking + conflict detection + OPA governance  |
| EU AI Act Art. 14 (human oversight)      | flag_for_review + memory health + shadow mode              |
| ISO 27001 A.8.15 (logging)               | Full audit trail with HMAC signatures                      |
| ISO 27001 A.8.24 (cryptography)          | Evidence integrity via HMAC-SHA256                         |


## Observability

Memory operations emit OpenTelemetry metrics:


| Metric                      | Type    | Description                       |
| --------------------------- | ------- | --------------------------------- |
| `memory.writes.total`       | Counter | Total memory write operations     |
| `memory.writes.denied`      | Counter | Writes denied by governance       |
| `memory.conflicts.detected` | Counter | Conflicts found during validation |
| `memory.reads.total`        | Counter | Read operations (list, search)    |
| `memory.entries.count`      | Gauge   | Current number of entries         |


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
- **Rollback:** `talon memory rollback <mem_id>` soft-deletes entries newer than the specified entry; rolled-back entries remain visible in `talon memory audit` with `ROLLED_BACK` status for compliance
- **Health monitoring:** `talon memory health` surfaces trust distribution and pending conflicts


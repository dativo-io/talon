# How to verify memory is used

This guide shows that Talon **loads** stored memory and **injects** it into the prompt before calling the LLM. Same agent and tenant for all commands (memory is scoped by `tenant_id` and `agent_id`).

## Prerequisites

- Talon built and an LLM API key (e.g. `export OPENAI_API_KEY=sk-...`)
- Commands run from the same directory; agent name comes from `agent.name` in your policy

## Steps

**1. Create a test project with memory enabled**

```bash
mkdir -p /tmp/talon-memory-demo && cd /tmp/talon-memory-demo
```

Use a policy with `memory.enabled: true` and optional `max_prompt_tokens` for relevance retrieval. Example minimal block:

```yaml
memory:
  enabled: true
  mode: active
  max_entries: 50
  max_prompt_tokens: 500
  allowed_categories:
    - domain_knowledge
    - factual_corrections
  governance:
    conflict_resolution: auto
```

**2. Teach something**

```bash
talon run "Remember: our company headquarters is in Berlin."
```

You should see a normal run and evidence stored. The runner writes a memory entry from the response.

**3. Confirm the entry exists**

```bash
talon memory list
```

Use the same agent as the run (omit `--agent` to use the policy’s `agent.name`, or pass it explicitly).

**4. Ask something that needs that memory**

```bash
talon run "Where is our company headquarters?"
```

If memory is used, the runner injects a `[AGENT MEMORY INDEX]` block into the prompt. The reply should reflect the stored fact (e.g. Berlin).

**5. Prove it in the audit trail**

```bash
talon audit show
```

When memory was injected, the evidence shows **Memory reads** and **Memory tokens**.

## Optional

- **No memory for one run:** `talon run --no-memory "Where is our HQ?"` — no memory read or write; useful to compare behavior.
- **Point-in-time (compliance):** `talon memory as-of <RFC3339> --agent <name>` — entries valid at that time.

See [Memory governance](../MEMORY_GOVERNANCE.md) for configuration, modes, and compliance.

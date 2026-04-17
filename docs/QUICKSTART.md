# Talon Quick Start

This page points you to the right doc for what you want to do.

---

## Which path is yours?

**1.** I have an existing app that calls OpenAI or Anthropic.  
→ [Add Talon to your existing app](guides/add-talon-to-existing-app.md)

**1a.** I want the fastest OpenAI-compatible local drop-in (no gateway YAML).  
→ [OpenAI proxy quickstart](tutorials/proxy-quickstart.md)

**2.** I'm building something new and want controls from day one.  
→ [Your first agent with Talon](tutorials/first-governed-agent.md)

**3.** I want to understand how it works before touching anything.  
→ [60-second demo (no API key)](tutorials/quickstart-demo.md)

---

## Minimal commands (if you already know Talon)

```bash
# Install (from repo)
make build    # → bin/talon

# New project (in a terminal: interactive wizard; in scripts/CI: use --scaffold or --pack)
mkdir my-agents && cd my-agents && talon init
# Non-interactive: talon init --scaffold   or   talon init --pack openclaw

# Set key and run
export OPENAI_API_KEY=sk-proj-...
talon run "Your query here"   # Uses agent name from policy when --agent omitted

# Server (API + dashboard + optional gateway/proxy)
export TALON_ADMIN_KEY="replace-with-strong-admin-key"
talon serve --port 8080
# With LLM gateway: talon serve --gateway --gateway-config examples/gateway/talon.config.gateway.yaml
# With MCP proxy:   talon serve --proxy-config path/to/proxy.yaml
```

## Verify It Works (2-minute governance loop)

After running your first agent, prove the governance loop is working:

```bash
# 1. List the most recent governance evidence (audit trail)
talon audit list --limit 1

# Expected output:
# ┌──────┬──────────────────────────────────┬─────────┬──────────┐
# │ ID   │ Timestamp                       │ Agent   │ Decision │
# ├──────┼──────────────────────────────────┼─────────┼──────────┤
# │ evt_1│ 2026-04-14T22:08:00Z             │ default │ approved │
# └──────┴──────────────────────────────────┴─────────┴──────────┘

# 2. Verify a specific evidence entry
talon audit verify <evidence-id>

# Expected output:
# ✅ Evidence verified: policy=allow, reason=query matches allowlist rule #1
```

This confirms Talon is logging decisions and you can inspect the full audit trail at any time.

For full configuration and options see [Configuration and environment](reference/configuration.md).

---

## Documentation index

All user-facing docs are listed by type (Tutorial, How-to, Reference, Explanation) in the **[documentation index](README.md)**. The project follows the [Diátaxis](https://diataxis.fr/) framework so you can find learning-oriented, task-oriented, or reference material quickly.

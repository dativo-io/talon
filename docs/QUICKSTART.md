# Talon Quick Start

This page points you to the right doc for what you want to do. For the full documentation map, see [docs/README.md](README.md).

---

## Which path is yours?

**1.** I have an existing app that calls OpenAI or Anthropic.  
→ [Add Talon to your existing app](guides/add-talon-to-existing-app.md)

**1a.** I want the fastest OpenAI-compatible local drop-in (no gateway YAML).  
→ [OpenAI proxy quickstart](tutorials/proxy-quickstart.md)

**2.** I'm building something new and want controls from day one.  
→ [Your first governed agent](tutorials/first-governed-agent.md)

**3.** I want to understand how it works before touching anything (no API key).  
→ [60-second demo (no API key)](tutorials/quickstart-demo.md)

**4.** I need to review what an auditor handoff looks like.  
→ [Sample auditor pack](../examples/auditor-pack/README.md)

---

## Install (native binary)

See the [README install matrix](../README.md#install). Summary:

| Platform | Recommended |
|----------|-------------|
| **macOS / arm64 Linux** | `git clone … && make install` or `go install github.com/dativo-io/talon/cmd/talon@latest` |
| **linux/amd64 server** | Release tarball or `curl -sSL https://install.gettalon.dev \| sh` |
| **No install** | [Docker Compose demo](../examples/docker-compose/README.md) |

On macOS, if linking fails with `unsupported tapi file type`, use `make install` (sets system Clang) or `CC=/usr/bin/clang CGO_ENABLED=1 go install …`.

---

## Minimal commands (if you already know Talon)

```bash
# Install (from repo)
make install    # → $(go env GOPATH)/bin/talon

# Secrets key (required for vault)
export TALON_SECRETS_KEY="$(openssl rand -hex 32)"

# New project
mkdir my-agents && cd my-agents
talon init --scaffold --name my-agent

# Policy check without LLM spend
talon run --dry-run "Your query here"

# Live run (needs provider key)
export OPENAI_API_KEY=sk-proj-...
talon run "Your query here"

# Server (API + dashboard + optional gateway/proxy)
export TALON_ADMIN_KEY="replace-with-strong-admin-key"
talon serve --port 8080
```

Verify the cold-start path from repo root: `make verify-newcomer`.

---

## Trust artifacts (Proof Pack)

- [LIMITATIONS.md](../LIMITATIONS.md)
- [Threat model](reference/threat-model.md)
- [Evidence integrity spec](reference/evidence-integrity-spec.md)
- [Sample auditor pack](../examples/auditor-pack/README.md)

---

## More

- [Documentation index](README.md)
- [Roadmap & focus](../ROADMAP.md)

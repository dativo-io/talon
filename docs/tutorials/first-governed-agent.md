# Your first governed agent

In this tutorial we will get from zero to a policy-enforced AI agent in one path: install Talon, initialize a project, configure an LLM key, run a query, and see evidence recorded. By the end you will have run a governed agent and seen the audit trail.

**Prerequisites:** Go 1.22+ (or a pre-built binary) and an LLM API key (OpenAI or Anthropic) or a local Ollama instance.

---

## 1. Install Talon

First, build or install the Talon binary.

```bash
# From source
git clone https://github.com/dativo-io/talon.git && cd talon
make build    # → bin/talon
# or: make install   # → $GOPATH/bin/talon

# Or install a released version
go install github.com/dativo-io/talon/cmd/talon@latest
```

**macOS:** If `go install` or `go build` fails with `unsupported tapi file type '!tapi-tbd'` (Homebrew LLVM vs Apple SDK), use system Clang: `CC=/usr/bin/clang go install github.com/dativo-io/talon/cmd/talon@latest`, or clone the repo and run `make build` / `make install`.

Check that it works:

```bash
talon --help
```

You should see the list of commands.

---

## 2. Initialize a project

Create a new directory and run `talon init` to scaffold a project.

```bash
mkdir my-agents && cd my-agents
talon init
```

You will see `agent.talon.yaml` and `talon.config.yaml` created with sensible defaults (cost limits, PII detection, model routing). Optional: `talon init --name my-agent --owner you@company.com` to set name and owner.

---

## 3. Configure an LLM provider

Talon needs an API key to call the LLM. For this tutorial we use an environment variable.

```bash
export OPENAI_API_KEY=sk-proj-...
# Or: export ANTHROPIC_API_KEY=ant-...
# Or: nothing needed for Ollama (runs on localhost:11434)
```

**First run without AWS?** The default template may set tier_2 to a Bedrock-only model. If you only have OpenAI or Anthropic, either run `talon init --pack telecom-eu` in a new directory, or edit `agent.talon.yaml`: set `policies.model_routing.tier_2.bedrock_only: false` and set `primary` to e.g. `gpt-4o` or `gpt-4o-mini`. Otherwise tier-2 requests will fail.

---

## 4. Run your first agent

Run a single query. Talon will load policy, classify input, evaluate policy, call the LLM, and store evidence.

```bash
talon run "Summarize the key trends in European AI regulation"
```

You should see output like:

```
✓ Policy check: ALLOWED

The European Union has been at the forefront of AI regulation...

✓ Evidence stored: req_xxxxxxxx
✓ Cost: €0.0018 | Duration: 1250ms
```

Notice the evidence ID (e.g. `req_xxxxxxxx`). Every run produces a signed audit record.

---

## 5. Try a dry run

See the policy decision without calling the LLM:

```bash
talon run --dry-run "What is the company revenue?"
```

You should see: `✓ Policy check: ALLOWED (dry run, no LLM call)`.

---

## 6. Try a policy block

Edit `agent.talon.yaml` and set a very low daily budget:

```yaml
policies:
  cost_limits:
    daily: 0.001
```

Run again:

```bash
talon run "Summarize EU regulation trends"
```

You should see:

```
✗ Policy check: DENIED
  Reason: budget_exceeded
```

The denial is still recorded as evidence — the policy engine caught it.

---

## 7. Inspect the audit trail

List recent evidence and open one record:

```bash
talon audit list --limit 10
talon audit show <evidence-id>
```

Use the evidence ID from a previous run. You will see the full record: classification, PII flags, policy decision, and HMAC status.

---

## What you've done

You installed Talon, created a project, ran a governed agent, triggered a policy denial, and viewed the audit trail. Next you can:

- **Configure more:** See [Configuration and environment](../reference/configuration.md) for environment variables and options.
- **Run the server:** See [QUICKSTART.md](../QUICKSTART.md) for `talon serve`, dashboard, and API.
- **Follow a how-to:** See the [documentation index](../README.md) for guides (Slack bot, OpenClaw, cost governance, compliance export, and more).

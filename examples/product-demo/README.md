# Talon product demo — one operating layer for a company's AI use cases

A **live, evidence-backed product demo**. It operates a **fleet of three real AI
use cases** through **one Talon gateway**, on **real providers**, and walks the
four things Talon does for every use case in a single operating period — every
headline asserted against Talon's own signed evidence before it is shown:

| Use case | Pillar it shows | What happens |
|---|---|---|
| **customer-support** | **Reliability** + **shared policy** | one customer incident: an email + IBAN are **redacted** before the provider; the preferred local model is down, so Talon fails over — **skipping a healthy provider this use case isn't allowed to use** and selecting the first policy-valid one |
| **coding-assistant** | **Shared capability policy** | a request carrying a destructive `admin_*` tool is rejected by an **organization** boundary the agent cannot weaken |
| **document-summary** | **Cost control** + **operational control** | a per-session budget denies the next call using its **projected** cost (spend + estimate vs limit) before Anthropic is called; then an operator **lowers its daily budget below today's spend** — a live policy edit activated by periodic safe reload — and the fleet immediately shows the use case **blocked** |
| the whole fleet | **Session understanding** | `talon agents` is the attention queue; descend from the fleet to one session (`audit list --session`) to one signed decision; every decision is exported and **verified offline** |

## Run it

```bash
export OPENAI_API_KEY=sk-...  ANTHROPIC_API_KEY=sk-ant-...
# The reliability beat needs the local model DOWN — stop Ollama if it's running.
make product-demo
# or:  ./demo.sh          # full narrated demo (every command shown, for evaluators)
#      ./demo.sh hero     # annotated live terminal demo — the README GIF (needs gum)
```

**Real, paid provider calls** — approximately **$0.02–0.05 per run** of
Talon-accounted cost on cheap models (`gpt-4o-mini`, `claude-sonnet-5`), computed
from Talon's bundled standard pricing table (your actual provider invoice may
differ, e.g. under introductory rates). The denials (tool boundary, budget stop)
cost `$0`; only the failover answer, the redacted answer, and a few real
summaries cost anything. No Docker. State lives in a throwaway temp directory —
your real `~/.talon` is never touched.

Requirements: `go`, `jq`, `curl`, `openssl`, an `OPENAI_API_KEY` and an `ANTHROPIC_API_KEY`,
and **Ollama not listening on `:11434`** (the reliability beat demonstrates
failover *from* the local model, so it must be offline; the demo asserts this in
preflight).

### The recorded hero needs `gum` (demo-only)

`./demo.sh hero` (and `scripts/record-hero.sh`) produce a **live terminal demo
using real Talon CLI and API calls** — a directed shell session, not a Talon
interface (Talon ships no such UI; the styling is part of the recording). The
light styling (a spinner beside the running command, one closing callout) uses
[gum](https://github.com/charmbracelet/gum) — a **demo-only** dependency pinned
to **v0.17.0**:

```bash
go install github.com/charmbracelet/gum@v0.17.0   # or: brew install gum
```

gum is **not** a Talon dependency in any sense that matters: it is not in `go.mod`,
not compiled into or invoked by the `talon` binary, and **not** required to build,
install, run, or operate Talon. It is also not required for `make product-demo`,
the verbose `./demo.sh` (`all`) walkthrough, or the CI smoke test's core path — only
for the recorded `hero` cut. Where a plain-text surface is needed (automated
assertions), `TALON_DEMO_UI=plain ./demo.sh hero` renders the same live run without
gum; the recorder refuses that fallback so the committed asset is always the styled
recording.

## What you're looking at

Every line printed under a `$ …` prompt is the exact command the script ran. Each
headline — the PII redaction (entities + tier), the skipped fallback candidate and
why, the projected-cost stop — is **asserted against Talon's own signed evidence
(`jq -e`) before it is rendered, and the receipt is drawn from that record**, not
hardcoded. Any unexpected outcome is a **hard failure in every mode** (not only
when recording), so the demo can never print a successful-looking proof that did
not actually happen.

The files that drive it are meant to be read:

- [`talon.config.yaml`](talon.config.yaml) — the organization baseline the
  platform team owns: the providers (including customer-support's fallback chain),
  the company defaults and **hard boundaries** every use case inherits
  (`pii_action: redact`, `constraints.forbidden_tools: [admin_*]`), and the
  `agents_dir`.
- [`agents/customer-support/agent.talon.yaml`](agents/customer-support/agent.talon.yaml),
  [`agents/coding-assistant/agent.talon.yaml`](agents/coding-assistant/agent.talon.yaml),
  [`agents/document-summary/agent.talon.yaml`](agents/document-summary/agent.talon.yaml)
  — one file per use case. A per-agent override only ever narrows the org
  baseline; it never widens it.

## Security posture

Safe from network exposure on a developer workstation — loopback-only,
authenticated admin endpoints, and isolated temporary state:

- The gateway binds to **loopback only** (`--host 127.0.0.1`) on a **random free
  port** — nothing is exposed on a shared interface.
- It mints a **random admin key** (admin endpoints are authenticated, never open)
  and **random per-use-case traffic keys** (no public keys baked in).
- Cloud and traffic secrets are **scoped to the agents that use them**
  (`--tenant acme --agent …`), not allow-all.
- The local provider carries a **dummy secret** — a cloud credential is never
  attached to a local or user-supplied endpoint, so it can never be transmitted
  there even if the local model came up mid-run.
- The gateway is confirmed to be Talon (the `/health` marker) and to have
  discovered exactly the three demo agents before any traffic is sent.

This is not a hardened multi-user posture: your provider keys are passed to
`talon secrets set` as command-line arguments, so they can appear in the process
list while the demo runs. Run it as yourself on a workstation you control, not on
a shared host with untrusted users.

## Honest boundaries

- The reliability beat stages a **real** outage only in the sense that the local
  model is off — there are **no fabricated responses**; every answer comes from a
  real provider. A fallback candidate is re-checked against the agent's full
  policy before it is used (a fallback must stay policy-valid — it is not a
  bypass), which is why the healthy `openai-batch` destination is *skipped* for
  customer-support.
- **Redaction** masks the forwarded payload; it does **not** lower the data
  classification (the record still shows the request was tier-2 confidential).
- The **session** budget is a **soft** cap — a single in-flight request can
  overshoot before the next is denied. The **daily/monthly** budgets are hard,
  pre-provider ceilings; a use case shows `blocked` in the fleet when its recorded
  period spend meets its cap.
- The demo reaches `blocked` from **real, recorded spend** — not a stochastic
  overshoot: rather than wait for spend to drift up to a fixed cap, an operator
  lowers document-summary's daily budget below what it has already spent today (a
  real policy edit picked up by periodic safe reload). This is honest about *how*
  the blocked state is produced, and it doubles as a demonstration of hot policy
  reload + the fleet as a live operational-control surface.
- The caps here are deliberately small so the stops are visible in a short demo;
  the mechanism is identical at $50 or $50,000.
- Talon governs the traffic and actions **routed through it**. Local shell
  commands, file edits, and direct provider calls that bypass Talon remain
  outside its control. Client-asserted subagent identity is attribution, not
  authentication. Evidence is tamper-evident and **offline-verifiable** — its
  HMAC-SHA256 signatures are checked with the shared signing key, no live database
  or network needed (this is symmetric signing, not public-key verification), and
  it is not immutable.

See [`docs/reference/configuration.md`](../../docs/reference/configuration.md) for
the full config reference, and the [governed-session demo](../governed-session/)
for a deeper single-session real-providers walkthrough.

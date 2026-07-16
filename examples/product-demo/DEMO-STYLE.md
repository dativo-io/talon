# Demo information architecture — the approved grammar for Talon terminal demos

This is the buyer-validated information architecture behind the hero recording
(`./demo.sh hero`, scored 9/10 product story · 9/10 credibility in adopter
review). **Treat it as frozen**: new demo work (including the full evaluator
demo) applies this grammar rather than redesigning it.

## The form: an annotated live terminal walkthrough

A directed, scrolling shell session — *not* a dashboard, TUI, or product UI
(Talon ships no such interface, and a demo must never imply one). Every scene is:

```
chapter heading → real command → live wait → REAL output → one annotation → hold
```

- **Fully live.** Real CLI/API calls against a real gateway; every headline is
  asserted against Talon's own signed evidence *before* it renders; an
  unexpected outcome aborts the demo — it can never present a proof that did
  not happen. No fixtures, no replay, no hardcoded values.
- **Self-identifying.** The first frame says what the asset is
  (`TALON · LIVE TERMINAL DEMO / Real CLI/API calls · live decisions · signed
  evidence`) — shown once, never as persistent chrome.
- **One clear at the open, one before the closing card.** Everything else
  scrolls; the causal chain is never erased mid-story.

## The story: four chapters

| # | Chapter | What it proves |
|---|---------|----------------|
| 1 | Fleet | three AI use cases · one org policy · one operating view (`talon agents`) |
| 2 | Reliability + shared policy | PII redacted before egress; failed local provider; **policy-valid** fallback (a healthy-but-disallowed provider is skipped) |
| 3 | Organization policy + cost | org tool boundary the agent cannot weaken (403 before the provider); the next call prevented on **projected** cost (403 + spent/estimate/limit) |
| 4 | Operations + proof | live policy edit → safe reload → fleet `blocked`; session-scoped audit drill-down; signed export verified offline |

The arc: *fleet state → incident → boundaries → operator control → proof*.
Evidence is the proof layer under the pillars — present in every beat, never
the headline of the closing card.

## The four visual levels (never blur them)

| Level | Treatment | Rule |
|-------|-----------|------|
| **Chapter heading** | cyan `◆` + bold white-on-blue chip ` n · Title ` + grey rule | terminal-safe glyphs only — emoji rendered muddy/inconsistent in agg at README scale |
| **Command** | bold cyan `$` + **bold white** command; dim grey request subline | the strongest text weight; the shown command IS the executed one (only secrets/computed-late values elided, honestly) |
| **Real output** | regular weight; Talon status colours | raw and recognizable; visual-safe trims only (column select, UUID shortening, date-half of timestamps); never fabricated |
| **Annotation** | *italic* grey `→ …` (green italic only for a proven conclusion) | the demo's voice — must never look like native Talon output |

Colour semantics (one meaning each): cyan = Talon/commands/selected · green =
success/enforcement · amber = policy denial/budget/blocked (a 4xx policy stop is
enforcement, **not** failure) · red = genuine technical/provider failure only ·
grey = context. Money is ≤4 decimals everywhere (`< $0.0001` below that).

## Truth rules (non-negotiable)

1. Every `$` line executes; every output line derives from that execution.
2. No secrets, tokens, temp paths, full UUIDs, or host shell prompt — ever.
   (`$GATEWAY` is the approved loopback placeholder; correlation ids are
   shortened for display, executed in full.)
3. Session identity ≠ agent identity: label both (`agent=… · session=…`).
4. Claims match shipped capability. Same-provider retries are NOT shipped:
   recording-robustness retries belong to the **demo runner** and any surfaced
   line must say so (`→ demo runner: … — retried this recording step.`).
5. A denial that proves governance closes with the receipt (cost `$0.0000`,
   the limit arithmetic, the blocked row) — concrete numbers over adjectives.

## Pacing (do not compress below this)

Reveal real output in sequence, not shimmer: route ledger ~200ms/line, budget
lines ~300ms, fleet rows ~200ms, session summary ~400ms. Holds on completed
scenes: fleet 3s · reliability 5s · tool boundary 4s · cost 5s · fleet reload 5s
· session 4-5s · evidence 4s · closing card 4s. Target **45–55s** recorded; a
30s cut is unreadable. (`DEMO_STEP_PAUSE` gates all pacing; tests run at 0.)

## Recording contract (`scripts/record-hero.sh`)

- 88×30 · asciinema `--idle-time-limit 3` · agg `--theme github-dark
  --font-size 20 --line-height 1.2 --last-frame-duration 4`.
- prepare/play split: setup happens **outside** the recording; provider
  preflight (minimal-cost real calls) runs before a single frame; cursor hidden
  for the whole cast (restore is recorder-side).
- Transactional promotion: exit 0 + `HERO_COMPLETE` marker + **no setup/host
  noise in the cast** + opens with the self-identification, else neither cast
  nor GIF is replaced. gum (pinned v0.17.0) is demo-only — never a Talon
  runtime/build dependency; the plain UI (`TALON_DEMO_UI=plain`) exists solely
  for automated text assertions and is refused by the recorder.

## Applying this to the full evaluator demo (next)

The `all` cut keeps its job — every command shown, machine identifiers intact,
paths visible — but should adopt this grammar where it doesn't conflict with
evaluator needs:

1. Same four-chapter arc and chapter chips (evaluators get the same story spine).
2. Same four visual levels; the full cut may additionally show raw `runcmd`
   invocations and full evidence fields (its readers want them).
3. Same truth rules verbatim (they already hold: shared beats + assertions).
4. Pacing may be slower and text denser; no GIF constraints apply.
5. Candidate structure: chapter chip → the hero's compact receipt → an
   "evaluator detail" block (raw command + full output) — so the full demo
   *contains* the hero rather than diverging from it.

Planned as a follow-up after the hero asset ships; the shared `beat_*`
execution/assertion layer already guarantees the two cuts cannot disagree.

# How to verify the turnkey compliance report generator end-to-end

The compliance report generator is part of Talon's **proof layer** — reports are generated from the signed evidence records that budgets, policies, and routing decisions already produce, so verifying it means verifying that chain end to end. Use this checklist after upgrading Talon or before a release demo to confirm the Turnkey Compliance Report Generator (epic #109) still works: EU policy packs, the compliance HTTP API, the dashboard Compliance tab, the unified FinOps view, and the signed control-plane evidence each export leaves.

This is the **portable, repo-canonical** version of the interactive verification canvas. The steps and expected outcomes are the same; work through the checkboxes here in any editor, terminal, or CI prep session.

**Prerequisites:** Go 1.22+, `curl`, `jq`, a free port 8080, and optionally a real LLM key to seed evidence. Run phases in order in one shell session — later steps assume the server and exports from earlier ones.

**Learn the flow first?** See the [Turnkey compliance reports tutorial](../tutorials/turnkey-compliance-reports.md) (~15 minutes, one happy path).

**Time:** about 45 minutes with all optional steps; ~25 minutes if you skip the wizard, smoke suite, and evidence seeding.

---

## Phase 0 — Setup

Build current `main` and prepare a clean workspace.

- [ ] **Build the latest binary**

  ```bash
  cd ~/tmp/dativo/talon && git checkout main && git pull
  go build -o /tmp/talon ./cmd/talon && /tmp/talon --help
  ```

  **Expect:** build succeeds; help text prints.

- [ ] **Create a clean test workspace**

  ```bash
  mkdir -p ~/talon-epic-test && cd ~/talon-epic-test
  ```

  **Expect:** empty directory; all following commands run from here unless noted.

- [ ] **Export session keys** (same shell for `serve` and `curl`)

  ```bash
  export TALON_SECRETS_KEY=$(openssl rand -hex 32)
  export TALON_ADMIN_KEY=test-admin-key
  ```

  **Expect:** both variables set. The admin key gates the dashboard and all `/v1/compliance/*` endpoints.

---

## Phase 1 — EU policy packs

Compliance packs in `talon init`: catalog, wizard, scaffold, scripted, validation.

- [ ] **Browse the pack catalog**

  ```bash
  /tmp/talon init --list-compliance
  ```

  **Expect:** four packs (`gdpr`, `nis2`, `dora`, `eu-ai-act`), each with a description and supported articles, plus a disclaimer that packs support controls and are not a certification.

- [ ] **Interactive wizard with pack multi-select** *(optional)*

  Run `/tmp/talon init` interactively. Accept defaults until **Apply EU compliance policy packs?**, then enter `1,2` (GDPR + NIS2).

  **Expect:** summary shows `Compliance packs: gdpr, nis2`; `agent.talon.yaml` and `talon.config.yaml` are written.

- [ ] **Inspect generated annotations**

  ```bash
  head -30 agent.talon.yaml
  ```

  **Expect:** header `# Compliance packs applied: …` followed by `supports:` lines linking articles (e.g. `gdpr Art. 30`) to Talon controls and source files; `compliance.frameworks` lists the selected packs.

- [ ] **Scaffold path with packs**

  ```bash
  /tmp/talon init --scaffold --compliance gdpr,eu-ai-act --force --skip-verify
  head -30 agent.talon.yaml
  ```

  **Expect:** annotated header with both packs; `eu-ai-act` sets `ai_act_risk_level` and `human_oversight`; `gdpr` sets `data_residency: eu`.

- [ ] **Scripted path, cross-pack effect**

  ```bash
  /tmp/talon init --provider openai --name epic-test --compliance dora --force --skip-verify
  head -30 agent.talon.yaml
  ```

  **Expect:** header lists `dora`; merged policy carries DORA retention (5 years).

- [ ] **Invalid pack is rejected**

  ```bash
  /tmp/talon init --scaffold --compliance hipaa --force --skip-verify
  ```

  **Expect:** command fails with `unsupported compliance pack "hipaa"` naming the valid values.

- [ ] **Merged config validates**

  ```bash
  /tmp/talon init --scaffold --compliance all --force --skip-verify
  /tmp/talon validate
  ```

  **Expect:** all four overlays merged together; `validate` reports no errors.

---

## Phase 2 — Serve with declarations

Declare a controller identity, start the server, optionally seed evidence.

- [ ] **Reset to a known config**

  ```bash
  /tmp/talon init --scaffold --name epic-agent --compliance gdpr --force --skip-verify
  ```

  **Expect:** fresh `agent.talon.yaml` and `talon.config.yaml`.

- [ ] **Declare the controller identity** (feeds RoPA, clears warnings)

  ```bash
  cat >> talon.config.yaml <<'EOF'

  compliance:
    controller:
      name: "Example GmbH"
      contact: "privacy@example.eu"
  EOF
  ```

  **Expect:** block appended. RoPA exports name this controller instead of a placeholder warning.

- [ ] **Start the server with the gateway enabled**

  Use a second terminal with the same key exports, or background the process.

  ```bash
  /tmp/talon serve --port 8080 --gateway
  ```

  **Expect:** `curl -s localhost:8080/health` returns ok. **`--gateway` is required for Phase 5:** without it, `/api/v1/metrics` and `/gateway/dashboard` return plain-text `404` (a common symptom is `jq: Cannot index number` on the `"404"` body). Works even when `talon.config.yaml` has no `gateway:` block — defaults apply.

- [ ] **Optional: seed real evidence**

  ```bash
  /tmp/talon secrets set openai-api-key "sk-..."
  /tmp/talon run "Say hello in one word"
  /tmp/talon audit list
  ```

  **Expect:** run completes; `audit list` shows signed records. Phases 3–5 also work against an empty store (zero counts, empty tables).

---

## Phase 3 — Compliance HTTP API

Admin-only `/v1/compliance/*`: coverage, exports, auth, control-plane evidence.

- [ ] **Coverage JSON**

  ```bash
  curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/compliance/coverage" \
    | jq '{frameworks: [.frameworks[].framework], warnings: .declaration_warnings, note: .claim_note}'
  ```

  **Expect:** at least five frameworks (`gdpr`, `eu-ai-act`, `nis2`, `dora`, `iso-27001`); `declaration_warnings` has `ropa` and `annex_iv` keys; `claim_note` says the output is **not a completed legal filing**.

- [ ] **RoPA export (HTML + JSON)**

  ```bash
  curl -sOJ -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/compliance/ropa?format=html"
  grep -o "Example GmbH" talon-ropa.html | head -1
  curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/compliance/ropa?format=json" | jq .title
  ```

  **Expect:** `talon-ropa.html` names **Example GmbH**; JSON title is `Record of Processing Activities`.

- [ ] **Annex IV export**

  ```bash
  curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/compliance/annex-iv?format=json" | jq .title
  ```

  **Expect:** valid JSON whose title mentions **Annex IV**.

- [ ] **Framework-filtered report**

  ```bash
  curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/compliance/report?format=json&framework=gdpr" \
    | jq '{framework, controls: (.controls | length)}'
  ```

  **Expect:** `framework` is `gdpr`; only GDPR control mappings.

- [ ] **Auth and validation matrix**

  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' "localhost:8080/v1/compliance/coverage"
  curl -s -o /dev/null -w '%{http_code}\n' -H "X-Talon-Admin-Key: wrong" \
    "localhost:8080/v1/compliance/report"
  curl -s -o /dev/null -w '%{http_code}\n' -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/compliance/ropa?format=pdf"
  curl -s -o /dev/null -w '%{http_code}\n' -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/compliance/coverage?from=12-31-2026"
  ```

  **Expect:** `401`, `401`, `400`, `400` — in that order. No key and wrong key rejected; `format=pdf` and malformed date rejected. (Tenant-key rejection is covered by smoke section 34 with a gateway caller configured.)

- [ ] **Exports record signed control-plane evidence**

  ```bash
  curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/evidence?invocation_type=control_plane&limit=10" \
    | jq '.entries[] | {id, action: .policy_decision}' | head -20
  ```

  **Expect:** one control-plane record per export above (`compliance_export_ropa`, `compliance_export_annex_iv`, `compliance_export_report`), each signed.

---

## Phase 4 — Dashboard compliance tab

Browser flow: coverage, warnings, filters, one-click exports, dashboard semantics.

- [ ] **Open the unified dashboard**

  ```text
  http://localhost:8080/dashboard?talon_admin_key=test-admin-key
  ```

  **Expect:** dashboard loads; tab bar includes **Compliance** alongside Evidence, Plans, Memory, FinOps, Tenants.

- [ ] **Framework coverage cards**

  **Expect:** one card per framework with control rows (article, Talon control, source) and evidence counts. Wording is **supports** / **supporting evidence** — never "compliant".

- [ ] **Declaration warnings react to config**

  With the controller declared (Phase 2), the RoPA controller warning is gone. To see warnings: remove the `compliance:` block from `talon.config.yaml`, restart `serve`, refresh.

  **Expect:** without declarations, actionable warnings (e.g. controller identity not declared); with them, warnings clear.

- [ ] **One-click exports**

  **Expect:** RoPA (HTML), Annex IV (JSON), and Report (HTML + framework dropdown) download the same documents as Phase 3 curls, honoring active filters.

- [ ] **Tenant / agent / date filters**

  **Expect:** setting tenant `default`, an agent, or from/to dates updates coverage and the recent-evidence table; clearing filters restores the full view.

- [ ] **Blocked card and Detail vs Verify** *(dashboard UX)*

  On the **Evidence** tab: note **Blocked (all evidence)** matches the "All evidence: N denied" line from `/v1/dashboard/denials-by-reason`. Click the card — the table filters to denied rows but the card number stays stable. Click **Detail** on a row: Integrity stays **Not checked** and the detail pane says to use **Verify**. Click **Verify**: Integrity flips to **Verified**.

  **Expect:** no jump from denied count to visible-row count on card click; Detail is read-only; only Verify updates Integrity. See [Gateway dashboard reference — Unified dashboard semantics](../reference/gateway-dashboard.md#unified-dashboard-semantics).

---

## Phase 5 — Unified FinOps view

Budget, cache, spend breakdowns, denials-by-reason. Requires Phase 2 server with `--gateway`.

- [ ] **FinOps & Runtime tab**

  **Expect:** gateway metric cards plus **Budget & cache** and **Spend by caller** / **Spend by model / provider** tables. Without gateway traffic, empty states (`—`) are correct.

- [ ] **Cross-check against the metrics API**

  ```bash
  curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/api/v1/metrics" | jq '{budget: .budget_status, cache: .cache_stats}'
  ```

  **Expect:** dashboard cards match the snapshot values.

- [ ] **Denials-by-reason in the governance quadrant**

  ```bash
  curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/v1/dashboard/denials-by-reason" | jq .
  ```

  **Expect:** Evidence tab shows **All evidence: N denied** with per-reason breakdown (`pii_block`, `policy_deny`, …) matching the API.

- [ ] **Gateway dashboard deep link**

  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
    "localhost:8080/gateway/dashboard"
  ```

  **Expect:** `200`. FinOps tab links via **Open full Gateway telemetry →**. Without `--gateway`, the dashboard hides gateway links and shows a restart hint instead of a 404.

---

## Phase 6 — Regression and cleanup

Automated suites plus teardown.

- [ ] **Full Go test suite** *(from repo root)*

  ```bash
  cd ~/tmp/dativo/talon && go test ./...
  ```

  **Expect:** all packages pass.

- [ ] **Smoke suite** *(optional; long-running)*

  ```bash
  cd ~/tmp/dativo/talon && bash tests/smoke_test.sh
  ```

  **Expect:** **SECTION 34 — Compliance Dashboard Mode** passes. Needs port 8080 free, `curl`, and `jq`.

- [ ] **Cleanup**

  ```bash
  kill %1 2>/dev/null; rm -rf ~/talon-epic-test
  ```

  **Expect:** server stopped (or Ctrl-C in its terminal); test workspace removed.

---

## You're done

You verified policy packs, the compliance API, dashboard exports, FinOps unification, dashboard UX semantics, and (optionally) the automated regression suites.

| I want to… | Doc |
|------------|-----|
| Walk a new teammate through the happy path | [Turnkey compliance reports tutorial](../tutorials/turnkey-compliance-reports.md) |
| Export for a real auditor handoff | [Compliance export runbook](compliance-export-runbook.md) |
| Understand each pack | [EU compliance policy packs](policy-packs.md) |
| API and metrics field reference | [Gateway dashboard reference](../reference/gateway-dashboard.md) |

Commands in this guide are aligned with `tests/smoke_sections/34_compliance_dashboard.sh` and `internal/server/handlers_compliance.go`.

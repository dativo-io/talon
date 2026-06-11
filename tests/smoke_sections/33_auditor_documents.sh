#!/usr/bin/env bash
# Smoke test section: 33_auditor_documents
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 33 — Auditor documents: GDPR Art. 30 RoPA + EU AI Act Annex IV exports
# (docs/guides/compliance-export-runbook.md#generate-a-formatted-ropa)
# (docs/guides/ropa-declarations.md)
# -----------------------------------------------------------------------------
test_section_33_auditor_documents() {
  local section="33_auditor_documents"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-ropa-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  run_talon run "One" &>/dev/null; true

  # Org-level controller (Art. 30(1)(a)) — talon.config.yaml is created by init in $dir
  cat >> "$dir/talon.config.yaml" <<'EOF'

compliance:
  controller:
    name: "Smoke Test GmbH"
    contact: "privacy@smoke.test"
    dpo_contact: "dpo@smoke.test"
    address: "Smoke Street 1, 10115 Berlin, Germany"
EOF

  # Full auditor declarations (RoPA + Annex IV) — see docs/guides/ropa-declarations.md
  cat > "$dir/auditor-policy.talon.yaml" <<'EOF'
agent:
  name: smoke-ropa-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 10.0
compliance:
  frameworks: [gdpr, eu-ai-act]
  data_residency: eu
  declarations:
    processing:
      purposes:
        - "smoke test customer support triage"
        - "smoke test internal AI assistance"
      data_subject_categories:
        - "customers"
        - "employees"
      personal_data_categories:
        - "contact details"
      retention_period: "90 days after ticket closure"
      legal_basis: "contract (Art. 6(1)(b))"
      safeguards: "Role-based access; smoke test signed evidence retained for audit review"
    system:
      system_description: "Smoke test LLM assistant for support triage"
      intended_purpose: "Summarize inbound support tickets in smoke tests"
      oversight_description: "Smoke reviewer checks flagged output daily"
EOF

  # RoPA JSON export: complete document (no declaration warnings)
  assert_pass "talon compliance ropa --format json exits 0" \
    run_talon compliance ropa --format json --policy "$dir/auditor-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/ropa.json"
  assert_pass "ropa.json has expected title" \
    jq -e '.title == "Record of Processing Activities"' "$dir/ropa.json"
  assert_pass "ropa.json contains 8 Art. 30 sections" \
    jq -e '.sections | length == 8' "$dir/ropa.json"
  assert_pass "ropa.json claim note disclaims legal filing" \
    jq -e '.claim_note | test("not a completed legal filing")' "$dir/ropa.json"
  # Declaration warnings must be absent; a residency-consistency warning may
  # legitimately appear when earlier smoke sections recorded non-EU flows.
  assert_pass "ropa.json has no declaration warnings" \
    jq -e '[(.warnings // [])[] | select(startswith("declaration missing"))] | length == 0' "$dir/ropa.json"
  assert_pass "ropa.json controller section is declared" \
    jq -e '[.sections[] | select(.heading | test("Controller"))][0].missing != true' "$dir/ropa.json"
  assert_pass "ropa.json purposes section is declared" \
    jq -e '[.sections[] | select(.heading | test("Purposes"))][0].missing != true' "$dir/ropa.json"
  assert_pass "ropa.json retention section is declared" \
    jq -e '[.sections[] | select(.heading | test("Envisaged erasure"))][0].missing != true' "$dir/ropa.json"

  # RoPA HTML export: no DECLARATION MISSING placeholders when declarations are complete
  assert_pass "talon compliance ropa --format html exits 0" \
    run_talon compliance ropa --format html --policy "$dir/auditor-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/ropa.html"
  assert_pass "ropa.html contains document title" \
    grep -q "Record of Processing Activities" "$dir/ropa.html"
  assert_fail "ropa.html has no DECLARATION MISSING placeholders" \
    grep -q "DECLARATION MISSING" "$dir/ropa.html"
  assert_pass "ropa.html lists declared controller" \
    grep -q "Smoke Test GmbH" "$dir/ropa.html"

  # Fail-open behavior: incomplete declarations still exit 0 with warnings
  cat > "$dir/incomplete-policy.talon.yaml" <<'EOF'
agent:
  name: smoke-ropa-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 10.0
compliance:
  frameworks: [gdpr]
EOF
  assert_pass "incomplete declarations still exit 0" \
    run_talon compliance ropa --format json --policy "$dir/incomplete-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/ropa-incomplete.json"
  assert_pass "incomplete ropa.json reports declaration warnings" \
    jq -e '(.warnings // []) | length > 0' "$dir/ropa-incomplete.json"

  # Unknown format is rejected
  assert_fail "talon compliance ropa --format pdf exits non-zero" \
    run_talon compliance ropa --format pdf --from 2020-01-01

  # Annex IV JSON export: complete document
  assert_pass "talon compliance annex-iv --format json exits 0" \
    run_talon compliance annex-iv --format json --policy "$dir/auditor-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/annex-iv.json"
  assert_pass "annex-iv.json has expected title" \
    jq -e '.title | test("Annex IV")' "$dir/annex-iv.json"
  assert_pass "annex-iv.json contains 6 sections" \
    jq -e '.sections | length == 6' "$dir/annex-iv.json"
  assert_pass "annex-iv.json claim note disclaims legal filing" \
    jq -e '.claim_note | test("not a completed legal filing")' "$dir/annex-iv.json"
  assert_pass "annex-iv.json has no declaration warnings" \
    jq -e '(.warnings // []) | length == 0' "$dir/annex-iv.json"
  assert_pass "annex-iv.json lists operator-owned Annex IV items" \
    jq -e '[.sections[] | select(.heading == "Items to complete outside Talon")] | length == 1' "$dir/annex-iv.json"
  assert_pass "annex-iv.json general description section not missing (declared)" \
    jq -e '[.sections[] | select(.heading | test("General description"))][0].missing != true' "$dir/annex-iv.json"

  # Annex IV HTML export
  assert_pass "talon compliance annex-iv --format html exits 0" \
    run_talon compliance annex-iv --format html --policy "$dir/auditor-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/annex-iv.html"
  assert_pass "annex-iv.html contains document title" \
    grep -q "Annex IV" "$dir/annex-iv.html"

  cd "$REPO_ROOT" || true
}

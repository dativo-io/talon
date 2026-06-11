#!/usr/bin/env bash
# Smoke test section: 33_auditor_documents
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 33 — Auditor documents: GDPR Art. 30 RoPA + EU AI Act Annex IV exports
# (docs/guides/compliance-export-runbook.md#generate-a-formatted-ropa)
# -----------------------------------------------------------------------------
test_section_33_auditor_documents() {
  local section="33_auditor_documents"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-ropa-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  run_talon run "One" &>/dev/null; true

  # Agent policy with full processing declarations for the export
  cat > "$dir/ropa-policy.talon.yaml" <<'EOF'
agent:
  name: smoke-ropa-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 10.0
compliance:
  frameworks: [gdpr]
  declarations:
    processing:
      purposes: ["smoke test processing"]
      data_subject_categories: ["customers"]
      retention_period: "90 days"
EOF

  # JSON export: structure, sections, claims footer
  assert_pass "talon compliance ropa --format json exits 0" \
    run_talon compliance ropa --format json --policy "$dir/ropa-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/ropa.json"
  assert_pass "ropa.json has expected title" \
    jq -e '.title == "Record of Processing Activities"' "$dir/ropa.json"
  assert_pass "ropa.json contains 8 Art. 30 sections" \
    jq -e '.sections | length == 8' "$dir/ropa.json"
  assert_pass "ropa.json claim note disclaims legal filing" \
    jq -e '.claim_note | test("not a completed legal filing")' "$dir/ropa.json"
  assert_pass "ropa.json declared purposes present" \
    jq -e '[.sections[] | select(.heading | test("Purposes"))][0].missing != true' "$dir/ropa.json"

  # Controller is not declared in scaffold config: flagged, but exit 0
  assert_pass "ropa.json flags missing controller declaration as warning" \
    jq -e '.warnings | length > 0' "$dir/ropa.json"

  # HTML export renders standalone page with flagged placeholders
  assert_pass "talon compliance ropa --format html exits 0" \
    run_talon compliance ropa --format html --policy "$dir/ropa-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/ropa.html"
  assert_pass "ropa.html contains document title" \
    grep -q "Record of Processing Activities" "$dir/ropa.html"
  assert_pass "ropa.html flags missing declarations" \
    grep -q "DECLARATION MISSING" "$dir/ropa.html"

  # Unknown format is rejected
  assert_fail "talon compliance ropa --format pdf exits non-zero" \
    run_talon compliance ropa --format pdf --from 2020-01-01

  # Agent policy with system declarations for the Annex IV pack
  cat > "$dir/annexiv-policy.talon.yaml" <<'EOF'
agent:
  name: smoke-ropa-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 10.0
compliance:
  frameworks: [eu-ai-act]
  declarations:
    system:
      system_description: "Smoke test LLM assistant"
      intended_purpose: "Smoke test"
      oversight_description: "Smoke reviewer checks output"
EOF

  # Annex IV JSON export: structure, sections, claims footer
  assert_pass "talon compliance annex-iv --format json exits 0" \
    run_talon compliance annex-iv --format json --policy "$dir/annexiv-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/annex-iv.json"
  assert_pass "annex-iv.json has expected title" \
    jq -e '.title | test("Annex IV")' "$dir/annex-iv.json"
  assert_pass "annex-iv.json contains 6 sections" \
    jq -e '.sections | length == 6' "$dir/annex-iv.json"
  assert_pass "annex-iv.json claim note disclaims legal filing" \
    jq -e '.claim_note | test("not a completed legal filing")' "$dir/annex-iv.json"
  assert_pass "annex-iv.json lists operator-owned Annex IV items" \
    jq -e '[.sections[] | select(.heading == "Items to complete outside Talon")] | length == 1' "$dir/annex-iv.json"
  assert_pass "annex-iv.json general description section not missing (declared)" \
    jq -e '[.sections[] | select(.heading | test("General description"))][0].missing != true' "$dir/annex-iv.json"

  # Annex IV HTML export
  assert_pass "talon compliance annex-iv --format html exits 0" \
    run_talon compliance annex-iv --format html --policy "$dir/annexiv-policy.talon.yaml" \
      --from 2020-01-01 --output "$dir/annex-iv.html"
  assert_pass "annex-iv.html contains document title" \
    grep -q "Annex IV" "$dir/annex-iv.html"

  cd "$REPO_ROOT" || true
}

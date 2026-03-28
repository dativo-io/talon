#!/usr/bin/env bash
# Smoke test section: 18_compliance_export
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 18 — Compliance Export Runbook (docs/guides/compliance-export-runbook.md)
# -----------------------------------------------------------------------------
test_section_18_compliance_export() {
  local section="18_export"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  run_talon run "One" &>/dev/null; true
  assert_pass "talon audit export --format csv --from exits 0" \
    run_talon audit export --format csv --from 2020-01-01
  local csv_h; csv_h="$(run_talon audit export --format csv --from 2020-01-01 2>/dev/null | head -1)"; true
  assert_pass "CSV header contains id, timestamp, tenant_id, pii_detected" \
    grep -qE 'id|timestamp|tenant_id|pii' <<< "$csv_h"
  local json_len; json_len="$(run_talon audit export --format json --from 2020-01-01 2>/dev/null | jq '.records | length')"
  assert_pass "talon audit export --format json returns valid JSON with records array" \
    jq -e '.records' <<< "$(run_talon audit export --format json --from 2020-01-01 2>/dev/null)" &>/dev/null
  local ev_id; ev_id="$(run_talon audit list --limit 1 2>/dev/null | awk '/req_/{print $2; exit}')"
  if [[ -n "$ev_id" ]]; then
    assert_pass "talon audit verify <valid-id> contains valid" \
      grep -qi valid <<< "$(run_talon audit verify "$ev_id" 2>/dev/null)"
  fi
  cd "$REPO_ROOT" || true
}


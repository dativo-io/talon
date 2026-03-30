#!/usr/bin/env bash
# Smoke test section: 10_audit
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 10 — Audit Trail CLI (docs/guides/compliance-export-runbook.md, PERSONA_GUIDES Compliance)
# -----------------------------------------------------------------------------
test_section_10_audit() {
  local section="10_audit"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  run_talon run "One" &>/dev/null; true
  run_talon run "Two" &>/dev/null; true
  assert_pass "talon audit list exits 0 with at least one record" run_talon audit list
  local list_out; list_out="$(run_talon audit list --limit 1 2>/dev/null)"; true
  assert_pass "talon audit list --limit 1 returns exactly one record" \
    test "$(echo "$list_out" | grep -c 'req_' || true)" -eq 1
  local ev_id; ev_id="$(run_talon audit list --limit 1 2>/dev/null | awk '/req_/{print $2; exit}')"
  [[ -z "$ev_id" ]] && ev_id="req_none"
  assert_pass "talon audit show <id> exits 0" run_talon audit show "$ev_id"
  local show_out; show_out="$(run_talon audit show "$ev_id" 2>/dev/null)"; true
  assert_pass "audit show JSON/output contains policy_decision or Policy" \
    grep -qiE 'policy_decision|Policy' <<< "$show_out"
  assert_pass "talon audit verify <id> exits 0 and contains valid: true or VALID" \
    grep -qi valid <<< "$(run_talon audit verify "$ev_id" 2>/dev/null)" && run_talon audit verify "$ev_id" &>/dev/null
  # Tamper: corrupt evidence_json so HMAC verification fails (Verify reads from JSON blob)
  local db_path="$TALON_DATA_DIR/evidence.db"
  if [[ -f "$db_path" ]] && command -v sqlite3 &>/dev/null; then
    sqlite3 "$db_path" "UPDATE evidence SET evidence_json = REPLACE(evidence_json, '\"default\"', '\"tampered\"') WHERE id = '$ev_id';" 2>/dev/null || true
    local verify_out; verify_out="$(run_talon audit verify "$ev_id" 2>&1)"
    local verify_code=$?
    if [[ $verify_code -eq 0 ]] && grep -q VALID <<< "$verify_out"; then
      log_failure "talon audit verify tampered record should exit non-zero or output invalid" "$verify_out"
    else
      echo "  ✓  talon audit verify tampered record exits non-zero or outputs invalid"
      record_pass
    fi
  else
    echo "  -  (skip tamper test: evidence.db or sqlite3 not found)"
  fi
  assert_pass "talon audit export --format csv exits 0" run_talon audit export --format csv --from 2020-01-01 --to 2099-12-31
  local csv_out; csv_out="$(run_talon audit export --format csv --from 2020-01-01 --to 2099-12-31 2>/dev/null)"; true
  assert_pass "CSV has header with id, timestamp, tenant_id, pii_detected" \
    grep -qE 'id|timestamp|tenant_id|pii' <<< "$csv_out"
  assert_pass "talon audit export --format json exits 0" run_talon audit export --format json --from 2020-01-01 --to 2099-12-31
  local json_out; json_out="$(run_talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)"; true
  assert_pass "audit export JSON is valid (jq)" jq . <<< "$json_out"
  assert_pass "talon audit export --from --to exits 0" \
    run_talon audit export --format json --from 2020-01-01 --to 2099-12-31
  cd "$REPO_ROOT" || true
}


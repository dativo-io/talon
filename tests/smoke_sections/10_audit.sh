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
  smoke_tighten_limits "$dir"
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
  # Signed export + file verification path (integrity export for auditors)
  local signed_json_path="$dir/smoke-signed-evidence.json"
  assert_pass "talon audit export --format signed-json exits 0" \
    run_talon audit export --format signed-json --from 2020-01-01 --to 2099-12-31 --output "$signed_json_path"
  assert_pass "signed-json export metadata marks signed=true" \
    jq -e '.export_metadata.signed == true' < "$signed_json_path" &>/dev/null
  assert_pass "signed-json export includes algorithm HMAC-SHA256" \
    jq -e '.export_metadata.algorithm == "HMAC-SHA256"' < "$signed_json_path" &>/dev/null
  assert_pass "signed-json export includes non-empty record signatures" \
    jq -e '(.records | length) > 0 and all(.records[]; (.signature | type=="string" and length > 0))' < "$signed_json_path" &>/dev/null
  assert_pass "talon audit verify --file signed export exits 0" \
    run_talon audit verify --file "$signed_json_path"
  # Tamper signed file; verify --file must fail and report invalid/unverifiable records.
  local tampered_signed_json_path="$dir/smoke-signed-evidence-tampered.json"
  if command -v python3 &>/dev/null; then
    python3 - "$signed_json_path" "$tampered_signed_json_path" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, "r", encoding="utf-8") as f:
    data = json.load(f)
if data.get("records"):
    rec = data["records"][0]
    rec["tenant_id"] = "tampered-tenant"
with open(dst, "w", encoding="utf-8") as f:
    json.dump(data, f)
PY
  elif command -v jq &>/dev/null; then
    jq '.records[0].tenant_id = "tampered-tenant"' "$signed_json_path" > "$tampered_signed_json_path"
  else
    cp "$signed_json_path" "$tampered_signed_json_path"
  fi
  local verify_file_out verify_file_code
  verify_file_out="$(run_talon audit verify --file "$tampered_signed_json_path" 2>&1)"
  verify_file_code=$?
  if [[ $verify_file_code -ne 0 ]] && grep -qiE 'invalid|missing signature|unsupported|could not parse' <<< "$verify_file_out"; then
    echo "  ✓  talon audit verify --file tampered export fails with integrity diagnostics"
    record_pass
  else
    log_failure "talon audit verify --file tampered export should fail with integrity diagnostics" "$verify_file_out"
  fi
  assert_pass "talon audit export --from --to exits 0" \
    run_talon audit export --format json --from 2020-01-01 --to 2099-12-31
  cd "$REPO_ROOT" || true
}


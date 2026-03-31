#!/usr/bin/env bash
# Smoke test section: 29_consistency
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 29 — Consistency checks: cross-command flow verification
# -----------------------------------------------------------------------------
test_section_29_consistency() {
  local section="29_consistency"
  local dir; dir="$(setup_section_dir "$section")"
  local ev_id list_out show_out
  list_out="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit list --limit 1 2>/dev/null)" || true
  ev_id="$(echo "$list_out" | awk '/req_/{print $2; exit}')"
  if [[ -n "$ev_id" ]]; then
    show_out="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit show "$ev_id" 2>/dev/null)" || true
    if echo "$show_out" | grep -qE 'policy_decision|Policy|correlation_id'; then
      echo "  ✓  CONSISTENCY: evidence_id from audit list is showable and has expected fields"
      echo "[SMOKE] CONSISTENCY|evidence_id_showable|PASS|ev_id=$ev_id"
      record_pass
    else
      echo "  ✗  CONSISTENCY: audit show $ev_id did not return expected fields"
      echo "[SMOKE] CONSISTENCY|evidence_id_showable|FAIL|ev_id=$ev_id show_output_empty_or_unexpected"
      record_fail "CONSISTENCY: evidence_id_showable"
    fi
  else
    echo "  -  CONSISTENCY: no evidence id in audit list (skip evidence_id_showable)"
    echo "[SMOKE] CONSISTENCY|evidence_id_showable|SKIP|no_evidence_id"
  fi

  # audit list --limit 1 should produce at most one evidence id row
  local list_one_count
  list_one_count="$(echo "$list_out" | awk '/req_/{n++} END{print n+0}')"
  if [[ -n "$list_one_count" ]] && [[ "$list_one_count" -le 1 ]]; then
    echo "  ✓  CONSISTENCY: audit list --limit 1 returns at most one evidence id"
    echo "[SMOKE] CONSISTENCY|audit_list_limit_one|PASS|rows=$list_one_count"
    record_pass
  else
    echo "  ✗  CONSISTENCY: audit list --limit 1 returned more than one evidence id"
    echo "[SMOKE] CONSISTENCY|audit_list_limit_one|FAIL|rows=${list_one_count:-unknown}"
    record_fail "CONSISTENCY: audit_list_limit_one"
  fi

  # audit verify should confirm the same evidence id is valid
  if [[ -n "$ev_id" ]]; then
    local verify_out
    verify_out="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit verify "$ev_id" 2>/dev/null)" || true
    if echo "$verify_out" | grep -qiE 'valid|VALID'; then
      echo "  ✓  CONSISTENCY: audit verify confirms the listed evidence id is valid"
      echo "[SMOKE] CONSISTENCY|evidence_id_verifyable|PASS|ev_id=$ev_id"
      record_pass
    else
      echo "  ✗  CONSISTENCY: audit verify did not confirm validity for listed evidence id"
      echo "[SMOKE] CONSISTENCY|evidence_id_verifyable|FAIL|ev_id=$ev_id"
      record_fail "CONSISTENCY: evidence_id_verifyable"
    fi
  else
    echo "  -  CONSISTENCY: no evidence id available (skip evidence_id_verifyable)"
    echo "[SMOKE] CONSISTENCY|evidence_id_verifyable|SKIP|no_evidence_id"
  fi

  # Edge case: unknown evidence id should fail for show/verify
  local missing_id="req_nonexistent_smoke_consistency_00000"
  local missing_show missing_verify
  missing_show="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit show "$missing_id" 2>&1)"
  if [[ $? -ne 0 ]] || echo "$missing_show" | grep -qiE 'not found|no evidence|missing'; then
    echo "  ✓  CONSISTENCY: audit show rejects nonexistent evidence id"
    echo "[SMOKE] CONSISTENCY|audit_show_missing_id|PASS|id=$missing_id"
    record_pass
  else
    echo "  ✗  CONSISTENCY: audit show unexpectedly accepted nonexistent evidence id"
    echo "[SMOKE] CONSISTENCY|audit_show_missing_id|FAIL|id=$missing_id"
    record_fail "CONSISTENCY: audit_show_missing_id"
  fi

  missing_verify="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit verify "$missing_id" 2>&1)"
  if [[ $? -ne 0 ]] || echo "$missing_verify" | grep -qiE 'not found|invalid|missing'; then
    echo "  ✓  CONSISTENCY: audit verify rejects nonexistent evidence id"
    echo "[SMOKE] CONSISTENCY|audit_verify_missing_id|PASS|id=$missing_id"
    record_pass
  else
    echo "  ✗  CONSISTENCY: audit verify unexpectedly accepted nonexistent evidence id"
    echo "[SMOKE] CONSISTENCY|audit_verify_missing_id|FAIL|id=$missing_id"
    record_fail "CONSISTENCY: audit_verify_missing_id"
  fi

  if [[ -f "$TALON_DATA_DIR/evidence.db" ]]; then
    local rows
    rows="$(sqlite3 "$TALON_DATA_DIR/evidence.db" "SELECT COUNT(*) FROM evidence;" 2>/dev/null)" || rows=""
    if [[ -n "$rows" ]] && [[ "$rows" -ge 0 ]]; then
      echo "  ✓  CONSISTENCY: evidence.db exists and evidence table readable (rows=$rows)"
      echo "[SMOKE] CONSISTENCY|evidence_db_readable|PASS|rows=$rows"
      record_pass
    else
      echo "  ✗  CONSISTENCY: evidence.db or evidence table not readable"
      echo "[SMOKE] CONSISTENCY|evidence_db_readable|FAIL"
      record_fail "CONSISTENCY: evidence_db_readable"
    fi
  else
    echo "  -  CONSISTENCY: evidence.db not found (skip)"
    echo "[SMOKE] CONSISTENCY|evidence_db_readable|SKIP|no_db"
  fi

  # audit export JSON should include the listed evidence id (same data path, different command)
  if [[ -n "$ev_id" ]]; then
    local export_json
    export_json="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)" || true
    if echo "$export_json" | jq -e '.records | type == "array"' &>/dev/null && \
      echo "$export_json" | jq -e --arg id "$ev_id" '.records | any(.id == $id)' &>/dev/null; then
      echo "  ✓  CONSISTENCY: audit export JSON includes evidence id from audit list"
      echo "[SMOKE] CONSISTENCY|evidence_id_in_export|PASS|ev_id=$ev_id"
      record_pass
    else
      echo "  ✗  CONSISTENCY: audit export JSON missing evidence id from audit list"
      echo "[SMOKE] CONSISTENCY|evidence_id_in_export|FAIL|ev_id=$ev_id"
      record_fail "CONSISTENCY: evidence_id_in_export"
    fi
  else
    echo "  -  CONSISTENCY: no evidence id available (skip evidence_id_in_export)"
    echo "[SMOKE] CONSISTENCY|evidence_id_in_export|SKIP|no_evidence_id"
  fi

  # Session consistency across the full smoke run.
  local recent_json
  recent_json="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)" || true
  if echo "$recent_json" | jq -e '.records | type == "array"' &>/dev/null; then
    local with_sid without_sid max_sid_count
    with_sid="$(echo "$recent_json" | jq '[.records[] | select((.session_id // "") != "")] | length' 2>/dev/null || echo 0)"
    without_sid="$(echo "$recent_json" | jq '[.records[] | select((.session_id // "") == "")] | length' 2>/dev/null || echo 0)"
    max_sid_count="$(echo "$recent_json" | jq '[.records[] | select((.session_id // "") != "") | .session_id] | group_by(.) | map(length) | max // 0' 2>/dev/null || echo 0)"
    if [[ "$with_sid" -gt 0 ]] && [[ "$without_sid" -eq 0 ]]; then
      echo "  ✓  CONSISTENCY: all exported records include session_id"
      echo "[SMOKE] CONSISTENCY|session_id_presence|PASS|with_sid=$with_sid without_sid=$without_sid"
      record_pass
    else
      echo "  ✗  CONSISTENCY: session_id missing on some exported records"
      echo "[SMOKE] CONSISTENCY|session_id_presence|FAIL|with_sid=$with_sid without_sid=$without_sid"
      record_fail "CONSISTENCY: session_id_presence"
    fi
    if [[ "$max_sid_count" -ge 2 ]]; then
      echo "  ✓  CONSISTENCY: at least one session links multiple records"
      echo "[SMOKE] CONSISTENCY|session_join_behavior|PASS|max_sid_count=$max_sid_count"
      record_pass
    else
      echo "  -  CONSISTENCY: no multi-record session observed in this run"
      echo "[SMOKE] CONSISTENCY|session_join_behavior|SKIP|max_sid_count=$max_sid_count"
    fi
  fi

  # export schema sanity: .records exists and is an array
  local export_shape_json
  export_shape_json="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)" || true
  if echo "$export_shape_json" | jq -e '.records | type == "array"' &>/dev/null; then
    echo "  ✓  CONSISTENCY: audit export JSON has records array schema"
    echo "[SMOKE] CONSISTENCY|audit_export_records_array|PASS"
    record_pass
  else
    echo "  ✗  CONSISTENCY: audit export JSON does not have records array schema"
    echo "[SMOKE] CONSISTENCY|audit_export_records_array|FAIL"
    record_fail "CONSISTENCY: audit_export_records_array"
  fi

  # Ops-side decision reconciliation:
  # classify per-request outcomes from export and reconcile with SQLite JSON fields.
  local ops_json
  ops_json="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit export --format json --tenant default --from 2020-01-01 --to 2099-12-31 2>/dev/null)" || true
  if echo "$ops_json" | jq -e '.records | type == "array"' &>/dev/null; then
    local ops_total ops_allowed ops_blocked ops_redacted ops_routed
    ops_total="$(echo "$ops_json" | jq '[.records[]] | length' 2>/dev/null || echo 0)"
    ops_allowed="$(echo "$ops_json" | jq '[.records[] | select(.allowed == true)] | length' 2>/dev/null || echo 0)"
    ops_blocked="$(echo "$ops_json" | jq '[.records[] | select(.allowed == false)] | length' 2>/dev/null || echo 0)"
    ops_redacted="$(echo "$ops_json" | jq '[.records[] | select(.pii_redacted == true)] | length' 2>/dev/null || echo 0)"
    ops_routed="$(echo "$ops_json" | jq '[.records[] | select((.model_used // "") != "")] | length' 2>/dev/null || echo 0)"

    if [[ "$ops_total" -eq $((ops_allowed + ops_blocked)) ]] && [[ "$ops_routed" -le "$ops_allowed" ]]; then
      echo "  ✓  CONSISTENCY: decision reconciliation from export is valid (block/redact/route/allow)"
      echo "[SMOKE] CONSISTENCY|ops_decision_reconcile_export|PASS|total=$ops_total allowed=$ops_allowed blocked=$ops_blocked redacted=$ops_redacted routed=$ops_routed"
      record_pass
    else
      echo "  ✗  CONSISTENCY: decision reconciliation from export failed"
      echo "[SMOKE] CONSISTENCY|ops_decision_reconcile_export|FAIL|total=$ops_total allowed=$ops_allowed blocked=$ops_blocked redacted=$ops_redacted routed=$ops_routed"
      record_fail "CONSISTENCY: ops_decision_reconcile_export"
    fi

    if [[ -f "$TALON_DATA_DIR/evidence.db" ]]; then
      local db_ops
      db_ops="$(sqlite3 "$TALON_DATA_DIR/evidence.db" "
SELECT
  COUNT(*),
  SUM(CASE WHEN json_extract(evidence_json, '$.policy_decision.allowed') IN (1, 1.0, '1', 'true') THEN 1 ELSE 0 END),
  SUM(CASE WHEN json_extract(evidence_json, '$.policy_decision.allowed') IN (0, 0.0, '0', 'false') THEN 1 ELSE 0 END),
  SUM(CASE WHEN json_extract(evidence_json, '$.classification.pii_redacted') IN (1, 1.0, '1', 'true') THEN 1 ELSE 0 END),
  SUM(CASE WHEN COALESCE(json_extract(evidence_json, '$.execution.model_used'), '') <> '' THEN 1 ELSE 0 END)
FROM evidence
WHERE tenant_id = 'default';
" 2>/dev/null)" || db_ops=""

      local db_total db_allowed db_blocked db_redacted db_routed
      db_total="$(echo "$db_ops" | cut -d'|' -f1)"
      db_allowed="$(echo "$db_ops" | cut -d'|' -f2)"
      db_blocked="$(echo "$db_ops" | cut -d'|' -f3)"
      db_redacted="$(echo "$db_ops" | cut -d'|' -f4)"
      db_routed="$(echo "$db_ops" | cut -d'|' -f5)"

      if [[ -n "$db_total" ]] && [[ "$ops_total" == "$db_total" ]] && [[ "$ops_allowed" == "$db_allowed" ]] && [[ "$ops_blocked" == "$db_blocked" ]] && [[ "$ops_redacted" == "$db_redacted" ]] && [[ "$ops_routed" == "$db_routed" ]]; then
        echo "  ✓  CONSISTENCY: export and DB reconcile on decision counts"
        echo "[SMOKE] CONSISTENCY|ops_decision_reconcile_db|PASS|total=$db_total allowed=$db_allowed blocked=$db_blocked redacted=$db_redacted routed=$db_routed"
        record_pass
      else
        echo "  ✗  CONSISTENCY: export vs DB decision reconciliation mismatch"
        echo "[SMOKE] CONSISTENCY|ops_decision_reconcile_db|FAIL|export=$ops_total,$ops_allowed,$ops_blocked,$ops_redacted,$ops_routed db=${db_total:-na},${db_allowed:-na},${db_blocked:-na},${db_redacted:-na},${db_routed:-na}"
        record_fail "CONSISTENCY: ops_decision_reconcile_db"
      fi
    fi
  fi

  # DB tenant row count should align with audit export --tenant default record count
  if [[ -f "$TALON_DATA_DIR/evidence.db" ]]; then
    local db_default_rows export_default_json export_default_rows
    db_default_rows="$(sqlite3 "$TALON_DATA_DIR/evidence.db" "SELECT COUNT(*) FROM evidence WHERE tenant_id = 'default';" 2>/dev/null)" || db_default_rows=""
    export_default_json="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon audit export --format json --tenant default --from 2020-01-01 --to 2099-12-31 2>/dev/null)" || true
    export_default_rows="$(echo "$export_default_json" | jq -r '.records | length' 2>/dev/null)" || export_default_rows=""
    if [[ -n "$db_default_rows" ]] && [[ -n "$export_default_rows" ]] && [[ "$db_default_rows" == "$export_default_rows" ]]; then
      echo "  ✓  CONSISTENCY: default tenant DB rows == audit export records ($db_default_rows)"
      echo "[SMOKE] CONSISTENCY|default_tenant_db_vs_export|PASS|rows=$db_default_rows"
      record_pass
    elif [[ -n "$db_default_rows" ]] && [[ -n "$export_default_rows" ]]; then
      echo "  ✗  CONSISTENCY: default tenant DB rows ($db_default_rows) != audit export records ($export_default_rows)"
      echo "[SMOKE] CONSISTENCY|default_tenant_db_vs_export|FAIL|db=$db_default_rows export=$export_default_rows"
      record_fail "CONSISTENCY: default_tenant_db_vs_export"
    else
      echo "  -  CONSISTENCY: unable to compute default tenant DB/export parity (skip)"
      echo "[SMOKE] CONSISTENCY|default_tenant_db_vs_export|SKIP|unavailable_counts"
    fi

    if [[ -n "$ev_id" ]]; then
      local id_rows
      id_rows="$(sqlite3 "$TALON_DATA_DIR/evidence.db" "SELECT COUNT(*) FROM evidence WHERE id = '$ev_id';" 2>/dev/null)" || id_rows=""
      if [[ "$id_rows" == "1" ]]; then
        echo "  ✓  CONSISTENCY: evidence id from audit list exists in SQLite evidence table"
        echo "[SMOKE] CONSISTENCY|evidence_id_exists_in_db|PASS|ev_id=$ev_id"
        record_pass
      elif [[ -n "$id_rows" ]]; then
        echo "  ✗  CONSISTENCY: evidence id from audit list not found exactly once in SQLite (rows=$id_rows)"
        echo "[SMOKE] CONSISTENCY|evidence_id_exists_in_db|FAIL|ev_id=$ev_id rows=$id_rows"
        record_fail "CONSISTENCY: evidence_id_exists_in_db"
      else
        echo "  -  CONSISTENCY: unable to query evidence id presence in SQLite (skip)"
        echo "[SMOKE] CONSISTENCY|evidence_id_exists_in_db|SKIP|query_error"
      fi
    else
      echo "  -  CONSISTENCY: no evidence id available (skip evidence_id_exists_in_db)"
      echo "[SMOKE] CONSISTENCY|evidence_id_exists_in_db|SKIP|no_evidence_id"
    fi
  else
    echo "  -  CONSISTENCY: evidence.db not found (skip default_tenant_db_vs_export)"
    echo "[SMOKE] CONSISTENCY|default_tenant_db_vs_export|SKIP|no_db"
    echo "  -  CONSISTENCY: evidence.db not found (skip evidence_id_exists_in_db)"
    echo "[SMOKE] CONSISTENCY|evidence_id_exists_in_db|SKIP|no_db"
  fi

  list_out="$(env TALON_DATA_DIR="$TALON_DATA_DIR" talon secrets list 2>/dev/null)" || true
  if echo "$list_out" | grep -q "openai-api-key" && ! echo "$list_out" | grep -qE 'sk-[a-zA-Z0-9]{20,}'; then
    echo "  ✓  CONSISTENCY: secrets list shows openai-api-key and does not leak literal key"
    echo "[SMOKE] CONSISTENCY|secrets_list_no_leak|PASS"
    record_pass
  else
    echo "  ✗  CONSISTENCY: secrets list missing openai-api-key or contains literal sk- key"
    echo "[SMOKE] CONSISTENCY|secrets_list_no_leak|FAIL"
    record_fail "CONSISTENCY: secrets_list_no_leak"
  fi
  echo "[SMOKE] CONSISTENCY_BLOCK_END"
  echo ""
}

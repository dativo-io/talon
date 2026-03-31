#!/usr/bin/env bash
#
# Dativo Talon — Smoke Test Suite
# Brief version 1.0 — March 2026 — Dativo Talon CPO/CTO
#
# Black-box E2E smoke test: exercises every user-visible capability as documented
# in docs/. Runs on Linux with talon binary on PATH; OpenAI only. Produces a
# pass/fail report suitable for a compliance officer.
#
# Usage: ./smoke_test.sh   or: make test-smoke (from repo root)
# Prerequisites:
#   - Go available (go in PATH)
#   - Talon callable (talon in PATH, or run from repo root after make build so ./bin/talon is used)
#   - TALON_SECRETS_KEY set (32-byte for AES-256-GCM vault)
#   - openai-api-key in vault: either set OPENAI_API_KEY (script sets it), or use existing vault by
#     exporting TALON_DATA_DIR to a directory where you already ran: talon secrets set openai-api-key <key>
# Optional: TALON_SIGNING_KEY, TALON_ADMIN_KEY, TALON_TENANT_KEY (defaults applied for smoke run). curl, jq; port 8080 free.
#
# Output: All sections run regardless of failures. Failures print exit code and
# last 5 lines of stderr to the terminal; full stdout/stderr per failure is
# appended to a timestamped log file (path printed at start and in summary).
# Summary lists all failed test names and the log path for analysis.
# Pass/fail counts are persisted to files so the final summary is correct even when
# each section runs in a subshell (failures are always visible; exit 1 if any fail).
#
# Consolidated log: all output and [SMOKE] lines are written to smoke_test_logs.out.txt
# (or SMOKE_CONSOLIDATED_LOG). Parseable lines: [SMOKE] CMD|... EXIT|... STDOUT_TAIL<< >> STDERR_TAIL<< >>
# [SMOKE] CONSISTENCY|name|PASS|... or FAIL|... [SMOKE] SUMMARY|PASS_COUNT|n FAIL_COUNT|n FAILED_TEST|...
# Share smoke_test_logs.out.txt to verify flows and consistency.
#
# Structure:
# - Request layer: tests/smoke_lib.sh is sourced early. All Talon gateway/dashboard HTTP
#   requests and canonical payloads (PII, cache, tool block/filter, normal) live there.
#   Use smoke_gw_post_chat, smoke_gw_get_metrics, smoke_health, SMOKE_BODY_*, etc. so we
#   don't duplicate URLs or request bodies across sections.
# - Sections: each test_section_XX function lives in tests/smoke_sections/XX_name.sh.
#   This file sources them all, then run_section in main() invokes each; failures are
#   recorded, suite continues.
# - Section index: 01 binary | 02 init | 03 validate | 04 secrets | 05 dry-run | 06 live-run |
#   07 PII | 08 attachments | 09 cost | 10 audit | 11 memory | 12 HTTP API | 13 gateway |
#   14 deny | 15 multi-tenant | 16 shadow | 17 config-provider | 18 compliance-export |
#   19 CI/CD | 20 edge-cases | 21 doctor/report/enforce | 22 cache | 23 dashboard-metrics | 24 plan-dispatch | 25 sessions |
#   26 pii-enrichment | 27 runtime-governance | 28 control-plane | 29 consistency.
#
# QA notes (from brief):
# - Section 16 (Shadow mode): Evidence shadow signal is in shadow_violations or
#   observation_mode_override (docs/explanation/what-talon-does-to-your-request.md Step 7).
# - Section 10/18 (Tamper test): Evidence DB is TALON_DATA_DIR/evidence.db; corrupt
#   evidence_json (e.g. REPLACE tenant_id) then run talon audit verify.
# - Section 22 (Cache): Governed semantic cache; enables cache in talon.config.yaml, runs
#   two identical prompts (miss then hit), exercises talon cache config/stats/list/erase.
# - Cost: Set a small hard billing cap on the OpenAI key to avoid runaway spend.
#

set -o pipefail
# Do NOT use set -e: individual assertion failures must not abort the suite.

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repo root: one level up from tests/ when script lives in tests/
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Counters and state ---
PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()
TALON_DATA_DIR=""
TALON_SERVE_PID=""
TALON_GATEWAY_PID=""
# Log file for failure details (set in main after prereqs; survives teardown)
SMOKE_LOG_FILE=""
# Count files so pass/fail persist when sections run in subshells (set in main)
SMOKE_COUNTS_FILE=""
SMOKE_FAILED_TESTS_FILE=""
# Consolidated log: results + command execution logs + consistency checks (set in main; tee'd)
SMOKE_CONSOLIDATED_LOG=""
# Current section name for log context (set at start of each test_section_XX)
CURRENT_SECTION=""
# 1 if we created TALON_DATA_DIR (mktemp); 0 if user set it (don't delete in teardown)
SMOKE_CREATED_DATA_DIR=0
# 1 if openai-api-key is already in vault (no OPENAI_API_KEY needed)
VAULT_HAS_OPENAI_KEY=0

# --- Persist pass/fail so counts survive subshells (run_section runs each section in a subshell) ---
record_pass() {
  if [[ -n "${SMOKE_COUNTS_FILE:-}" ]]; then echo "P" >> "$SMOKE_COUNTS_FILE"; else ((PASS_COUNT++)) || true; fi
}
record_fail() {
  local d="$1"
  if [[ -n "${SMOKE_COUNTS_FILE:-}" ]]; then
    echo "F" >> "$SMOKE_COUNTS_FILE"
    echo "$d" >> "$SMOKE_FAILED_TESTS_FILE"
  else
    ((FAIL_COUNT++)) || true
    FAILED_TESTS+=("$d")
  fi
}

# --- Write command execution to consolidated log (parseable: [SMOKE] CMD|... / EXIT|... / STDOUT_TAIL / STDERR_TAIL) ---
write_cmd_log() {
  local description="$1" cmd="$2" code="$3" tmp_out="$4" tmp_err="$5"
  [[ -z "${SMOKE_CONSOLIDATED_LOG:-}" ]] && return 0
  {
    echo "[SMOKE] SECTION|$CURRENT_SECTION"
    echo "[SMOKE] ASSERT_DESC|$description"
    echo "[SMOKE] CMD|$cmd"
    echo "[SMOKE] EXIT|$code"
    echo "[SMOKE] STDOUT_TAIL<<"
    [[ -f "$tmp_out" ]] && tail -30 "$tmp_out"
    echo "[SMOKE] STDOUT_TAIL>>"
    echo "[SMOKE] STDERR_TAIL<<"
    [[ -f "$tmp_err" ]] && tail -30 "$tmp_err"
    echo "[SMOKE] STDERR_TAIL>>"
    echo ""
  } >> "$SMOKE_CONSOLIDATED_LOG"
}

# --- Assertion helper: run command, on failure log full output and continue ---
assert_pass() {
  local description="$1"; shift
  local tmp_out tmp_err
  tmp_out="$(mktemp)" tmp_err="$(mktemp)"
  if "$@" >"$tmp_out" 2>"$tmp_err"; then
    echo "  ✓  $description"
    write_cmd_log "$description" "$*" 0 "$tmp_out" "$tmp_err"
    record_pass
    rm -f "$tmp_out" "$tmp_err"
    return 0
  fi
  local code
  code=$?
  local cmd_detail="$*"
  echo "  ✗  $description (exit $code) [$cmd_detail]"
  write_cmd_log "$description" "$cmd_detail" "$code" "$tmp_out" "$tmp_err"
  record_fail "$description"
  # Log full context for analysis
  if [[ -n "$SMOKE_LOG_FILE" ]]; then
    {
      echo "--- FAIL: $description ---"
      echo "Section: $CURRENT_SECTION"
      echo "Command: $cmd_detail"
      echo "Exit code: $code"
      echo "Stdout (last 100 lines):"
      tail -100 "$tmp_out"
      echo "Stderr (last 100 lines):"
      tail -100 "$tmp_err"
      echo ""
    } >> "$SMOKE_LOG_FILE"
  fi
  # Show last few stderr lines so bugs are visible without opening the log
  if [[ -s "$tmp_err" ]]; then
    echo "    Last stderr:"
    tail -5 "$tmp_err" | sed 's/^/    | /'
  fi
  rm -f "$tmp_out" "$tmp_err"
  return 1
}

# --- Assert command exits non-zero (pass if it fails, fail if it succeeds) ---
assert_fail() {
  local description="$1"; shift
  local tmp_out tmp_err
  tmp_out="$(mktemp)" tmp_err="$(mktemp)"
  if "$@" >"$tmp_out" 2>"$tmp_err"; then
    local code=0
    echo "  ✗  $description (expected non-zero exit)"
    write_cmd_log "$description" "$*" "$code" "$tmp_out" "$tmp_err"
    record_fail "$description"
    if [[ -n "$SMOKE_LOG_FILE" ]]; then
      { echo "--- FAIL: $description ---"; echo "Section: $CURRENT_SECTION"; echo "Command succeeded but should have failed: $*"; echo ""; } >> "$SMOKE_LOG_FILE"
    fi
    rm -f "$tmp_out" "$tmp_err"
    return 1
  fi
  local code
  code=$?
  echo "  ✓  $description"
  write_cmd_log "$description" "$*" "$code" "$tmp_out" "$tmp_err"
  record_pass
  rm -f "$tmp_out" "$tmp_err"
  return 0
}

# --- Log a failure from manual checks (same as assert_pass but for custom if/else blocks) ---
# Usage: log_failure "description" ["detail_string"]
# For richer diagnostics, call dump_diag_* helpers after log_failure.
log_failure() {
  local description="$1"
  local detail="${2:-}"
  echo "  ✗  $description"
  record_fail "$description"
  if [[ -n "$SMOKE_LOG_FILE" ]]; then
    {
      echo "--- FAIL: $description ---"
      echo "Section: $CURRENT_SECTION"
      [[ -n "$detail" ]] && echo "Detail: $detail"
      echo ""
    } >> "$SMOKE_LOG_FILE"
  fi
}

# --- Diagnostic helpers: append structured context to both log files on failure ---
# Append key=value pairs to the failure log for post-mortem analysis.
dump_diag_kv() {
  local label="$1"; shift
  if [[ -n "$SMOKE_LOG_FILE" ]]; then
    { echo "  [DIAG] $label"; for kv in "$@"; do echo "    $kv"; done; echo ""; } >> "$SMOKE_LOG_FILE"
  fi
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]]; then
    { echo "[SMOKE] DIAG|$label"; for kv in "$@"; do echo "[SMOKE] DIAG_KV|$kv"; done; } >> "$SMOKE_CONSOLIDATED_LOG"
  fi
}

# Dump a file's content (truncated) to the failure log.
dump_diag_file() {
  local label="$1" filepath="$2" max_lines="${3:-80}"
  if [[ -n "$SMOKE_LOG_FILE" ]] && [[ -f "$filepath" ]]; then
    { echo "  [DIAG] $label ($filepath):"; tail -"$max_lines" "$filepath" | sed 's/^/    | /'; echo ""; } >> "$SMOKE_LOG_FILE"
  fi
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]] && [[ -f "$filepath" ]]; then
    { echo "[SMOKE] DIAG_FILE|$label|$filepath"; tail -"$max_lines" "$filepath" | sed 's/^/[SMOKE] DIAG_LINE|/'; echo "[SMOKE] DIAG_FILE_END|$label"; } >> "$SMOKE_CONSOLIDATED_LOG"
  fi
}

# Dump JSON body (pretty-printed via jq if available) to the failure log.
dump_diag_json() {
  local label="$1" json_str="$2" max_lines="${3:-60}"
  if [[ -n "$SMOKE_LOG_FILE" ]] && [[ -n "$json_str" ]]; then
    {
      echo "  [DIAG] $label:"
      if command -v jq &>/dev/null; then
        echo "$json_str" | jq '.' 2>/dev/null | head -"$max_lines" | sed 's/^/    | /' || echo "    | (invalid JSON) ${json_str:0:500}"
      else
        echo "    | ${json_str:0:2000}"
      fi
      echo ""
    } >> "$SMOKE_LOG_FILE"
  fi
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]] && [[ -n "$json_str" ]]; then
    {
      echo "[SMOKE] DIAG_JSON|$label"
      if command -v jq &>/dev/null; then
        echo "$json_str" | jq '.' 2>/dev/null | head -"$max_lines" | sed 's/^/[SMOKE] DIAG_LINE|/' || echo "[SMOKE] DIAG_LINE|(invalid JSON) ${json_str:0:500}"
      else
        echo "[SMOKE] DIAG_LINE|${json_str:0:2000}"
      fi
      echo "[SMOKE] DIAG_JSON_END|$label"
    } >> "$SMOKE_CONSOLIDATED_LOG"
  fi
}

# Dump environment snapshot relevant to smoke debugging.
dump_diag_env() {
  dump_diag_kv "smoke_env" \
    "TALON_DATA_DIR=$TALON_DATA_DIR" \
    "TALON_ADMIN_KEY=${TALON_ADMIN_KEY:+(set, ${#TALON_ADMIN_KEY} chars)}" \
    "TALON_TENANT_KEY=${TALON_TENANT_KEY:+(set, ${#TALON_TENANT_KEY} chars, value=${TALON_TENANT_KEY})}" \
    "TALON_SIGNING_KEY=${TALON_SIGNING_KEY:+(set)}" \
    "OPENAI_API_KEY=${OPENAI_API_KEY:+(set, ${#OPENAI_API_KEY} chars)}" \
    "PWD=$(pwd)" \
    "section=$CURRENT_SECTION"
}

# --- Environment checks (Section 2) ---
check_prereqs() {
  echo "Checking prerequisites..."
  local missing=()
  command -v go &>/dev/null || missing+=("go in PATH")
  command -v talon &>/dev/null || missing+=("talon callable (run from repo root after 'make build' or add bin/ to PATH)")
  [[ -n "${TALON_SECRETS_KEY:-}" ]] || missing+=("TALON_SECRETS_KEY set (32-byte for AES-256-GCM vault)")
  command -v curl &>/dev/null || missing+=("curl")
  command -v jq &>/dev/null || missing+=("jq")
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing: ${missing[*]}"
    exit 2
  fi
  # TALON_DATA_DIR: use existing if set and writable; else create temp (and delete in teardown)
  if [[ -n "${TALON_DATA_DIR:-}" ]] && [[ -d "$TALON_DATA_DIR" ]] && [[ -w "$TALON_DATA_DIR" ]]; then
    SMOKE_CREATED_DATA_DIR=0
    export TALON_DATA_DIR
    # Check if openai-api-key is already in vault (so OPENAI_API_KEY not required)
    if TALON_DATA_DIR="$TALON_DATA_DIR" talon secrets list 2>/dev/null | grep -q openai-api-key; then
      VAULT_HAS_OPENAI_KEY=1
    else
      [[ -n "${OPENAI_API_KEY:-}" ]] || missing+=("OPENAI_API_KEY set (vault has no openai-api-key; set it with: talon secrets set openai-api-key \$OPENAI_API_KEY)")
    fi
  else
    TALON_DATA_DIR="$(mktemp -d)"
    export TALON_DATA_DIR
    SMOKE_CREATED_DATA_DIR=1
    [[ -n "${OPENAI_API_KEY:-}" ]] || missing+=("OPENAI_API_KEY set (used to set openai-api-key in vault for this run)")
  fi
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing: ${missing[*]}"
    exit 2
  fi
  # Optional: default signing key, admin key, and tenant API keys for smoke run
  export TALON_SIGNING_KEY="${TALON_SIGNING_KEY:-$(openssl rand -hex 32 2>/dev/null || echo "smoke-signing-key-32-bytes-long")}"
  export TALON_ADMIN_KEY="${TALON_ADMIN_KEY:-smoke-admin-key}"
  export TALON_TENANT_KEY="${TALON_TENANT_KEY:-smoke-test-key}"
  # Keep standard port and ask user to free it if occupied (re-check every 10s).
  if ! wait_port_free 8080 180 10; then
    echo "Port 8080 is still in use; cannot run smoke tests on the standard port."
    exit 2
  fi
  echo "Prerequisites OK. TALON_DATA_DIR=$TALON_DATA_DIR"
  [[ $VAULT_HAS_OPENAI_KEY -eq 1 ]] && echo "Using existing vault (openai-api-key already set)."
}

# --- Teardown (Section 3.4) ---
teardown() {
  if [[ -n "$TALON_SERVE_PID" ]] && kill -0 "$TALON_SERVE_PID" 2>/dev/null; then
    kill "$TALON_SERVE_PID" 2>/dev/null || true
    wait "$TALON_SERVE_PID" 2>/dev/null || true
  fi
  if [[ -n "$TALON_GATEWAY_PID" ]] && kill -0 "$TALON_GATEWAY_PID" 2>/dev/null; then
    kill "$TALON_GATEWAY_PID" 2>/dev/null || true
    wait "$TALON_GATEWAY_PID" 2>/dev/null || true
  fi
  if [[ "${SMOKE_CREATED_DATA_DIR:-0}" -eq 1 ]] && [[ -n "$TALON_DATA_DIR" ]] && [[ -d "$TALON_DATA_DIR" ]]; then
    rm -rf "$TALON_DATA_DIR"
  fi
  # Log file is left in place (SCRIPT_DIR or cwd) for analysis
}
trap teardown EXIT

# --- Run one section; never abort the suite (subshell catches exit so all sections run) ---
run_section() {
  local name="$1"; shift
  CURRENT_SECTION="$name"
  local code=0
  ( "$@" ) || code=$?
  if [[ $code -ne 0 ]]; then
    echo "  !! Section $name crashed with exit code $code"
    if [[ -n "$SMOKE_LOG_FILE" ]]; then
      {
        echo "=== SECTION CRASH: $name ==="
        echo "Exit code: $code"
        echo "TALON_DATA_DIR=$TALON_DATA_DIR"
        echo "PWD=$(pwd)"
        echo "TALON_TENANT_KEY=${TALON_TENANT_KEY:-}"
        echo "TALON_ADMIN_KEY=${TALON_ADMIN_KEY:+(set)}"
        echo ""
      } >> "$SMOKE_LOG_FILE"
    fi
    if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]]; then
      echo "[SMOKE] SECTION_CRASH|$name|exit_code=$code" >> "$SMOKE_CONSOLIDATED_LOG"
    fi
  fi
  return 0
}

# --- Setup: temp dirs, configs, vault (called before sections that need them) ---
setup_section_dir() {
  local name="$1"
  mkdir -p "$TALON_DATA_DIR/sections/$name"
  echo "$TALON_DATA_DIR/sections/$name"
}

run_talon() {
  env TALON_DATA_DIR="$TALON_DATA_DIR" talon "$@"
}

# Central request layer: canonical payloads and HTTP helpers (no duplicate URLs/bodies)
# shellcheck source=./smoke_lib.sh
source "$SCRIPT_DIR/smoke_lib.sh"

# Return 0 when a TCP port is currently in LISTEN state, else 1.
is_port_in_use() {
  local port="${1:-8080}"
  if command -v lsof &>/dev/null; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN &>/dev/null && return 0
  fi
  # Fallback: health probe (uses canonical path from smoke_lib)
  smoke_health "http://127.0.0.1:$port" && return 0
  return 1
}

# Wait until a port is free. If occupied, prompt the user to stop the process and
# re-check every N seconds for up to max_wait_sec.
wait_port_free() {
  local port="${1:-8080}" max_wait_sec="${2:-180}" check_every_sec="${3:-10}" waited=0

  if ! is_port_in_use "$port"; then
    return 0
  fi

  echo "  -  Port $port is in use. Please stop the process using it."
  if command -v lsof &>/dev/null; then
    echo "     Current listener(s):"
    lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | sed 's/^/     /'
  fi

  while is_port_in_use "$port"; do
    if [[ $waited -ge $max_wait_sec ]]; then
      echo "  -  Port $port is still in use after ${max_wait_sec}s."
      return 1
    fi
    echo "  -  Waiting ${check_every_sec}s, then checking port $port again..."
    sleep "$check_every_sec"
    ((waited += check_every_sec))
  done

  echo "  ✓  Port $port is now free."
  # Extra pause for TCP TIME_WAIT
  sleep 1
  return 0
}

# =============================================================================
# Section files: each test_section_XX function lives in its own file under
# tests/smoke_sections/.  Source them all so run_section can invoke them.
# =============================================================================
readonly SMOKE_SECTIONS_DIR="${SCRIPT_DIR}/smoke_sections"

for _section_file in \
  01_binary.sh 02_init.sh 03_validate.sh 04_secrets.sh 05_dry_run.sh \
  06_live_run.sh 07_pii.sh 08_attachments.sh 09_cost.sh 10_audit.sh \
  11_memory.sh 12_http_api.sh 13_gateway.sh 14_deny.sh 15_multi_tenant.sh \
  16_shadow.sh 17_config_provider.sh 18_compliance_export.sh 19_cicd.sh \
  20_edge_cases.sh 21_doctor_report_enforce.sh 22_cache.sh \
  23_dashboard_metrics.sh 24_plan_dispatch.sh 25_sessions.sh \
  26_pii_enrichment.sh 27_runtime_governance.sh 28_control_plane.sh \
  29_consistency.sh; do
  # shellcheck source=/dev/null
  source "${SMOKE_SECTIONS_DIR}/${_section_file}"
done
unset _section_file


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
  echo "Dativo Talon Smoke Test — OpenAI only, black-box E2E"
  check_prereqs

  # Consolidated log: all output + [SMOKE] CMD/RESULT/CONSISTENCY for sourcing back
  SMOKE_CONSOLIDATED_LOG="${SMOKE_CONSOLIDATED_LOG:-$REPO_ROOT/smoke_test_logs.out.txt}"
  export SMOKE_CONSOLIDATED_LOG
  {
    echo "=== Dativo Talon Smoke Test — Consolidated Log ==="
    echo "[SMOKE] LOG_START|$(date -Iseconds 2>/dev/null || date)"
    echo "[SMOKE] TALON_DATA_DIR|$TALON_DATA_DIR"
    echo "[SMOKE] REPO_ROOT|$REPO_ROOT"
    echo ""
  } > "$SMOKE_CONSOLIDATED_LOG"
  exec 3>&1 4>&2
  exec 1> >(tee -a "$SMOKE_CONSOLIDATED_LOG" >&3) 2> >(tee -a "$SMOKE_CONSOLIDATED_LOG" >&4)
  echo "Consolidated log (results + CMD/RESULT + consistency): $SMOKE_CONSOLIDATED_LOG"
  echo ""

  # Log file: full failure output for analysis; path survives teardown
  SMOKE_LOG_FILE="${SCRIPT_DIR}/smoke_test_$(date +%Y%m%d_%H%M%S).log"
  if ! touch "$SMOKE_LOG_FILE" 2>/dev/null; then
    SMOKE_LOG_FILE="$(pwd)/smoke_test_$(date +%Y%m%d_%H%M%S).log"
    touch "$SMOKE_LOG_FILE" 2>/dev/null || SMOKE_LOG_FILE="/tmp/talon_smoke_$$.log"
  fi
  export SMOKE_LOG_FILE
  {
    echo "Dativo Talon Smoke Test — failure log"
    echo "Started: $(date -Iseconds 2>/dev/null || date)"
    echo "TALON_DATA_DIR=$TALON_DATA_DIR"
    echo "Each failure below includes: Section, Command, Exit code, Stdout (last 100 lines), Stderr (last 100 lines)."
    echo ""
  } >> "$SMOKE_LOG_FILE"
  echo "Failure log (full stdout/stderr per failure): $SMOKE_LOG_FILE"
  echo ""

  # Count files so pass/fail survive subshells (each section runs in ( subshell ))
  SMOKE_COUNTS_FILE="${TALON_DATA_DIR}/smoke_counts.$$"
  SMOKE_FAILED_TESTS_FILE="${TALON_DATA_DIR}/smoke_failed.$$"
  printf '' > "$SMOKE_COUNTS_FILE"
  printf '' > "$SMOKE_FAILED_TESTS_FILE"
  export SMOKE_COUNTS_FILE SMOKE_FAILED_TESTS_FILE

  # Run every section; no early exit so the full picture is available
  run_section "01_binary" test_section_01_binary
  run_section "02_init" test_section_02_init
  run_section "03_validate" test_section_03_validate
  run_section "04_secrets" test_section_04_secrets
  run_section "05_dry_run" test_section_05_dry_run
  run_section "06_live_run" test_section_06_live_run
  run_section "07_pii" test_section_07_pii
  run_section "08_attachments" test_section_08_attachments
  run_section "09_cost" test_section_09_cost
  run_section "10_audit" test_section_10_audit
  run_section "11_memory" test_section_11_memory
  run_section "12_http_api" test_section_12_http_api
  run_section "13_gateway" test_section_13_gateway
  run_section "14_deny" test_section_14_deny
  run_section "15_multi_tenant" test_section_15_multi_tenant
  run_section "16_shadow" test_section_16_shadow
  run_section "17_config_provider" test_section_17_config_provider
  run_section "18_compliance_export" test_section_18_compliance_export
  run_section "19_cicd" test_section_19_cicd
  run_section "20_edge_cases" test_section_20_edge_cases
  run_section "21_doctor_report_enforce" test_section_21_doctor_report_enforce
  run_section "22_cache" test_section_22_cache
  run_section "23_dashboard_metrics" test_section_23_dashboard_metrics
  run_section "24_plan_dispatch" test_section_24_plan_dispatch
  run_section "25_sessions" test_section_25_sessions
  run_section "26_pii_enrichment" test_section_26_pii_enrichment
  run_section "27_runtime_governance" test_section_27_runtime_governance
  run_section "28_control_plane" test_section_28_control_plane

  # Section 29: Consistency checks — cross-command flow verification
  run_section "29_consistency" test_section_29_consistency

  # Aggregate counts from file (sections run in subshells so in-memory counts are lost)
  if [[ -n "${SMOKE_COUNTS_FILE:-}" ]] && [[ -f "$SMOKE_COUNTS_FILE" ]]; then
    PASS_COUNT=$(grep -c "^P$" "$SMOKE_COUNTS_FILE" 2>/dev/null || true)
    FAIL_COUNT=$(grep -c "^F$" "$SMOKE_COUNTS_FILE" 2>/dev/null || true)
    PASS_COUNT="${PASS_COUNT:-0}"
    FAIL_COUNT="${FAIL_COUNT:-0}"
    FAILED_TESTS=()
    while IFS= read -r line; do [[ -n "$line" ]] && FAILED_TESTS+=("$line"); done < "$SMOKE_FAILED_TESTS_FILE" 2>/dev/null || true
  fi

  echo ""
  echo "========== Summary =========="
  echo "Pass: $PASS_COUNT  Fail: $FAIL_COUNT"
  # Append parseable summary to consolidated log for sourcing back
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]] && [[ -f "$SMOKE_CONSOLIDATED_LOG" ]]; then
    {
      echo "[SMOKE] SUMMARY|PASS_COUNT|$PASS_COUNT"
      echo "[SMOKE] SUMMARY|FAIL_COUNT|$FAIL_COUNT"
      for t in "${FAILED_TESTS[@]}"; do echo "[SMOKE] FAILED_TEST|$t"; done
      echo "[SMOKE] LOG_END|$(date -Iseconds 2>/dev/null || date)"
    } >> "$SMOKE_CONSOLIDATED_LOG"
  fi
  if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo "Failed tests:"
    printf '  - %s\n' "${FAILED_TESTS[@]}"
    echo ""
    echo "--- Diagnostic Environment ---"
    echo "  TALON_DATA_DIR=$TALON_DATA_DIR"
    echo "  TALON_TENANT_KEY=${TALON_TENANT_KEY:-}"
    echo "  TALON_ADMIN_KEY=${TALON_ADMIN_KEY:+(set, ${#TALON_ADMIN_KEY} chars)}"
    echo "  TALON_SIGNING_KEY=${TALON_SIGNING_KEY:+(set)}"
    echo "  OPENAI_API_KEY=${OPENAI_API_KEY:+(set, ${#OPENAI_API_KEY} chars)}"
    echo "  evidence.db size: $(du -h "$TALON_DATA_DIR/evidence.db" 2>/dev/null | cut -f1 || echo 'N/A')"
    echo "  evidence count: $(sqlite3 "$TALON_DATA_DIR/evidence.db" 'SELECT COUNT(*) FROM evidence' 2>/dev/null || echo 'N/A')"
    echo "  talon version: $(talon version 2>/dev/null || echo 'N/A')"
    echo "  go version: $(go version 2>/dev/null || echo 'N/A')"
    echo ""
    echo "For full stdout/stderr of each failure, see: $SMOKE_LOG_FILE"
    echo "Consolidated log (for verification): $SMOKE_CONSOLIDATED_LOG"
    # Also write the diagnostic block into the consolidated log
    if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]]; then
      {
        echo "[SMOKE] DIAG|FINAL_ENV"
        echo "[SMOKE] DIAG_KV|TALON_DATA_DIR=$TALON_DATA_DIR"
        echo "[SMOKE] DIAG_KV|TALON_TENANT_KEY=${TALON_TENANT_KEY:-}"
        echo "[SMOKE] DIAG_KV|TALON_ADMIN_KEY=${TALON_ADMIN_KEY:+(set)}"
        echo "[SMOKE] DIAG_KV|evidence_count=$(sqlite3 "$TALON_DATA_DIR/evidence.db" 'SELECT COUNT(*) FROM evidence' 2>/dev/null || echo 'N/A')"
        echo "[SMOKE] DIAG_KV|talon_version=$(talon version 2>/dev/null || echo 'N/A')"
      } >> "$SMOKE_CONSOLIDATED_LOG"
    fi
    exit 1
  fi
  echo "All tests passed."
  echo "Consolidated log (for verification): $SMOKE_CONSOLIDATED_LOG"
  exit 0
}

main "$@"

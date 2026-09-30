#!/usr/bin/env bash
# Smoke test section: 25_sessions
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 25 — Session CLI and session API (Pydantic/RULER readiness: workflow grouping)
# -----------------------------------------------------------------------------
test_section_25_sessions() {
  local section="25_sessions"
  local dir; dir="$(setup_section_dir "$section")"
  echo ""
  echo "=== SECTION 25 — Session CLI and API ==="
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"

  # Create at least one session by running the agent once (session is created on first run)
  run_talon run "Seed session for smoke" &>/dev/null; true

  # Session CLI: list (expect table with header or empty)
  local list_out list_exit
  list_out="$(run_talon session list --tenant default 2>&1)" || true
  list_exit=$?
  if [[ $list_exit -eq 0 ]]; then
    assert_pass "talon session list exits 0" true
    if echo "$list_out" | grep -qE 'ID|STATUS|AGENT|COST|TOKENS|CREATED'; then
      echo "  ✓  talon session list prints table header"
      record_pass
    fi
  else
    log_failure "talon session list should exit 0" "exit=$list_exit"
    dump_diag_kv "session list" "exit=$list_exit" "out=${list_out:0:500}"
  fi

  # If we have a session id from list output (first column of data row), run session show
  local sess_id
  sess_id="$(echo "$list_out" | awk '/^sess_/ {print $1; exit}')"
  if [[ -n "$sess_id" ]]; then
    # Default output is human-readable; --json is the machine contract
    # (internal/cmd/session.go sessionDetail: {session{id,status,…}, summary}).
    local show_out show_exit
    show_out="$(run_talon session show "$sess_id" 2>&1)"
    show_exit=$?
    if [[ $show_exit -eq 0 ]] && grep -q "$sess_id" <<< "$show_out"; then
      assert_pass "talon session show <id> exits 0 with human-readable detail" true
    else
      log_failure "talon session show <id> should exit 0 and name the session" "exit=$show_exit"
      dump_diag_kv "session show" "sess_id=$sess_id" "exit=$show_exit"
      dump_diag_json "session show output" "$show_out"
    fi
    local show_json show_json_exit
    show_json="$(run_talon session show "$sess_id" --json 2>/dev/null)"
    show_json_exit=$?
    if [[ $show_json_exit -eq 0 ]] && jq -e --arg id "$sess_id" \
        '.session.id == $id and (.session.status | type == "string") and (.summary | type == "object")' <<< "$show_json" &>/dev/null; then
      assert_pass "talon session show <id> --json returns the session detail contract (session.id, session.status, summary)" true
    else
      log_failure "talon session show --json should return the session detail JSON contract" "exit=$show_json_exit"
      dump_diag_kv "session show --json" "sess_id=$sess_id" "exit=$show_json_exit"
      dump_diag_json "session show --json output" "$show_json"
    fi
  else
    echo "  -  no session id in list output (skip session show)"
  fi

  # Gateway request with X-Talon-Session-ID and X-Talon-Stage (if gateway config present)
  # We do not start serve here; section 13 already tests gateway. Just verify CLI.
  cd "$REPO_ROOT" || true
}


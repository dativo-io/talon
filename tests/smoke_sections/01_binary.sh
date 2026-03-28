#!/usr/bin/env bash
# Smoke test section: 01_binary
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 01 — Binary and Version (docs/QUICKSTART.md, docs/README.md)
# -----------------------------------------------------------------------------
test_section_01_binary() {
  local section="01_binary"
  echo ""
  echo "=== SECTION 01 — Binary and Version ==="
  # talon version exits 0 and stdout contains at least one digit
  assert_pass "talon version exits 0" run_talon version
  local ver_out; ver_out="$(run_talon version 2>/dev/null)"; true
  assert_pass "talon version stdout contains a digit" grep -q '[0-9]' <<< "$ver_out"
  # talon --help exits 0 and lists commands
  assert_pass "talon --help exits 0" run_talon --help
  local help_out; help_out="$(run_talon --help 2>/dev/null)"; true
  for cmd in init validate run serve audit costs metrics secrets memory cache; do
    assert_pass "talon --help lists: $cmd" grep -q "$cmd" <<< "$help_out"
  done
  assert_pass "talon help equivalent to --help" run_talon help
}


#!/usr/bin/env bash
# Smoke test section: 44_console_browser
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 44 — Operations console in a real browser (#537, #539-#544)
# Runs scripts/console-browser-smoke.sh: Playwright drives Chromium through
# the packaged console that `talon ui serve` (the binary under test) serves
# over a seeded, signed installation. Every browser test is one smoke
# assertion:
#   pairing — wrong code, startup code (HttpOnly cookie, nothing in URL,
#     document or storage), replay refused, session expiry returns to the same
#     page, logout, cross-origin read blocked;
#   pages — Overview, AI Use Cases (values equal `talon agents --json`, incl.
#     a foreign-currency use case), use-case detail and deep-link refresh,
#     Sessions and the session timeline (allowed, denied-not-dispatched,
#     HR-rejected and cache-hit outcomes kept distinct), evidence verification
#     (valid, tampered, standalone), shared external session id, Costs (equal
#     to `talon costs --json`, including an unavailable total), Configuration,
#     System, search, 404;
#   races — record change, tenant change, late timeline page, session cursors.
# The section also fails when fewer than SMOKE_BROWSER_MIN_TESTS tests ran, so
# the suite cannot shrink unnoticed. The same suite runs in CI (job
# `browser`) and as `make test-browser-console`. Offline: no provider key;
# needs node >= 18 (a prerequisite, never skipped).
# -----------------------------------------------------------------------------
SMOKE_BROWSER_MIN_TESTS="${SMOKE_BROWSER_MIN_TESTS:-20}"

test_section_44_console_browser() {
  echo ""
  echo "=== SECTION 44 — Operations console in a real browser ==="
  cd "$REPO_ROOT" || exit 1
  local out report rc=0
  out="$(mktemp)" report="$(mktemp)"
  CONSOLE_BROWSER_REPORTER="list,json" PLAYWRIGHT_JSON_OUTPUT_NAME="$report" TALON_BINARY="$(command -v talon)" \
    bash scripts/console-browser-smoke.sh >"$out" 2>&1 || rc=$?

  if [[ ! -s "$report" ]] || ! jq -e '.suites' "$report" >/dev/null 2>&1; then
    echo "  ✗  browser suite did not run (exit $rc)"
    tail -15 "$out" | redact_secrets | sed 's/^/    | /'
    write_cmd_log "browser suite" "scripts/console-browser-smoke.sh" "$rc" "$out" "$out"
    record_fail "44: browser suite did not run (exit $rc)"
    rm -f "$out" "$report"
    return 0
  fi

  # One assertion per browser test: "<file> › <title>\t<status>".
  local ran=0 title status
  while IFS=$'\t' read -r title status; do
    case "$status" in
      expected)
        echo "  ✓  browser: $title"
        record_pass
        ran=$((ran + 1))
        ;;
      skipped)
        # Only the screenshot spec is opt-in. Any other skipped test did not
        # run (serial mode skips the rest of a file after a failure).
        if [[ "$title" == 03-screenshots* ]]; then
          echo "  -  browser (opt-in screenshots, not run): $title"
        else
          echo "  ✗  browser: $title (did not run)"
          record_fail "44: browser: $title (did not run)"
          ran=$((ran + 1))
        fi
        ;;
      *)
        echo "  ✗  browser: $title ($status)"
        record_fail "44: browser: $title"
        ran=$((ran + 1))
        ;;
    esac
  done < <(jq -r '
      def walk_suites(f): (.specs[]? | [f, .]), (.suites[]? | walk_suites(f));
      .suites[] | . as $file | walk_suites($file.title)
      | "\(.[0]) › \(.[1].title)\t\(.[1].tests[0].status // "skipped")"' "$report")

  if [[ $ran -lt $SMOKE_BROWSER_MIN_TESTS ]]; then
    echo "  ✗  browser suite ran $ran tests; at least $SMOKE_BROWSER_MIN_TESTS expected"
    record_fail "44: browser suite ran only $ran tests (minimum $SMOKE_BROWSER_MIN_TESTS)"
  else
    echo "  ✓  browser suite ran $ran tests (minimum $SMOKE_BROWSER_MIN_TESTS)"
    record_pass
  fi
  if [[ $rc -ne 0 ]]; then
    write_cmd_log "browser suite" "scripts/console-browser-smoke.sh" "$rc" "$out" "$out"
  fi
  rm -f "$out" "$report"
}

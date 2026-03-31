#!/usr/bin/env bash
# Smoke test section: 26_pii_enrichment
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 26 — PII semantic enrichment + input/output redaction config
# Plan: 5 requests with enrichment off (redact_input on), 5 with enrichment enforce; assert no raw PII in output, evidence has pii_detected/pii_redacted.
# Placeholder format comparison (legacy [TYPE] vs <PII type=... id=...>) is covered by unit tests.
# -----------------------------------------------------------------------------
check_pii_evidence() { # $1=label — asserts latest evidence has PII markers
  local ev_id; ev_id="$(run_talon audit list --limit 1 2>/dev/null | awk '/req_/{print $2; exit}')"
  if [[ -z "$ev_id" ]]; then
    log_failure "26_pii_enrichment: evidence has pii ($1)" "no evidence id found"
    return 1
  fi
  local ev_out; ev_out="$(run_talon audit show "$ev_id" 2>/dev/null)"
  assert_pass "26_pii_enrichment: evidence has pii ($1)" \
    bash -c 'echo "$1" | grep -qiE "PII Detected:.*[^(none)]|PII Redacted:.*true"' _ "$ev_out"
}
test_section_26_pii_enrichment() {
  local section="26_pii_enrichment"
  local dir; dir="$(setup_section_dir "$section")"
  echo ""
  echo "=== SECTION 26 — PII Semantic Enrichment + Input Redaction ==="
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true

  # Enable input+output scanning with granular redact_input/redact_output
  if command -v yq &>/dev/null; then
    yq -i '.policies.data_classification.input_scan = true | .policies.data_classification.output_scan = true | .policies.data_classification.redact_pii = true | .policies.data_classification.redact_input = true | .policies.data_classification.redact_output = true' "$dir/agent.talon.yaml" 2>/dev/null || true
    yq -i '.policies.semantic_enrichment.enabled = false' "$dir/agent.talon.yaml" 2>/dev/null || true
  else
    sed -i.bak 's/redact_pii: *false/redact_pii: true/' "$dir/agent.talon.yaml" 2>/dev/null || true
    sed -i.bak 's/input_scan: *false/input_scan: true/' "$dir/agent.talon.yaml" 2>/dev/null || true
    sed -i.bak 's/output_scan: *false/output_scan: true/' "$dir/agent.talon.yaml" 2>/dev/null || true
    grep -q 'redact_input:' "$dir/agent.talon.yaml" || sed -i.bak '/redact_pii:/a\    redact_input: true\n    redact_output: true' "$dir/agent.talon.yaml" 2>/dev/null || true
  fi

  local prompts_a=( "Reply OK. Mrs Smith lives in Berlin." "Reply OK. Maria Schmidt from Germany." "Reply OK. Herr Müller in Bavaria."
    "Reply OK. Contact user@example.com and Jane in Munich." "Reply OK. Frau Weber and Paris office." )

  # Variant A: enrichment off + redact_input on — 5 runs
  local i run_out run_exit
  for i in 0 1 2 3 4; do
    run_out="$(run_talon run "${prompts_a[$i]}" 2>&1)"; run_exit=$?; true
    assert_pass "26_pii_enrichment: run A-$i (enrichment off) exits 0" test "$run_exit" -eq 0 || true
    assert_fail "26_pii_enrichment: A-$i output has no raw email" grep -qF 'user@example.com' <<< "$run_out"
  done
  check_pii_evidence "variant A"

  # Variant B: enrichment enforce — enable semantic_enrichment
  if command -v yq &>/dev/null; then
    yq -i '.policies.semantic_enrichment.enabled = true | .policies.semantic_enrichment.mode = "enforce" | .policies.semantic_enrichment.allowed_attributes = ["gender", "scope", "country_code", "domain_type"]' "$dir/agent.talon.yaml" 2>/dev/null || true
  else
    grep -q 'semantic_enrichment:' "$dir/agent.talon.yaml" || \
      sed -i.bak '/^  model_routing:/i\  semantic_enrichment: { enabled: true, mode: enforce, allowed_attributes: [gender, scope, country_code, domain_type] }' "$dir/agent.talon.yaml" 2>/dev/null || true
  fi

  for i in 0 1 2 3 4; do
    assert_pass "26_pii_enrichment: run B-$i (enrichment enforce) exits 0" \
      run_talon run "${prompts_a[$i]}"
  done
  check_pii_evidence "variant B"

  echo "[SMOKE] SECTION|26_pii_enrichment"
  cd "$REPO_ROOT" || true
}


#!/usr/bin/env bash
# Smoke test section: 38_openshell
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 38 — OpenShell composition (#457/#482)
# Runs the offline, credential-free OpenShell composition smoke against the
# built binary: scripts/openshell-smoke.sh, the SAME scenarios that
# `make test-openshell-smoke` and the PR CI step execute (shared, not
# duplicated). A fixture supervisor replays the pinned OpenShell v0.1.3
# supervisor-middleware contract (gateway-signed sandbox identity,
# EvaluateHttpRequest, header mutations, credential injection after Talon,
# the PRE_RETURN exchange); everything asserted about Talon is real. It
# proves: the composed model channel (verified identity, one PII
# transformation reaching the provider path, DENY with zero dispatch, forged
# identity refused, an imported containment fact labelled external_asserted,
# provider credential never in Talon, evidence verifying across a restart);
# the action channel through the hop (allow → one dispatch, deny → zero,
# approval → zero until a host-side human approves then exactly one,
# replay-safe, unbound/forged/tampered/re-routed refused, reviewer route
# closed); response governance (settlement under the decision's correlation
# id, PII transformed before delivery, restart during an in-flight preventive
# response, duplicate callback replayed, 400 body with PII blocked, body with
# PII past the capture bound blocked); and the OpenAI-SDK tool-using agent
# through the fixture gateway (tool governance, denial before dispatch,
# host-side approval, at-most-once dispatch, the walkthrough report). One
# assertion: the Go smoke's exit status. A failure is counted in the
# consolidated summary and makes the suite exit non-zero. The real-runtime
# proof is `make test-openshell-live` (Docker), not this section.
# -----------------------------------------------------------------------------
test_section_38_openshell() {
  echo ""
  echo "=== SECTION 38 — OpenShell composition (#457/#482) ==="
  cd "$REPO_ROOT" || exit 1
  # Build-and-run inside the e2e harness: the Go test builds its own binary
  # (TestMain) and the SDK agent module, and uses isolated temp data dirs, so
  # this section needs no port, provider key or shared state from the other
  # sections.
  assert_pass "TestE2E_OpenShell_*: composed model channel, action channel through the hop, response governance, SDK agent (scripts/openshell-smoke.sh)" \
    bash scripts/openshell-smoke.sh
}

#!/usr/bin/env bash
# OpenShell composition smoke (#482): deterministic, clean-checkout proof of
# the composed model channel using a FIXTURE supervisor that replays the
# pinned OpenShell v0.1.3 supervisor-middleware contract. No OpenShell
# install, no Docker, no provider keys, no spend.
#
# Proves (see tests/e2e/openshell_test.go for the exact assertions):
#   - verified composed identity (gateway-signed sandbox JWT → Talon use case)
#   - one Talon transformation (PII redaction) reaching the provider path
#     exactly once with exactly the redacted bytes
#   - one Talon prevention (model restriction) with ZERO provider dispatch
#   - forged / foreign / missing identity → ZERO provider dispatch
#   - one OpenShell-only containment fact imported and labelled
#     external_asserted (never a Talon decision, never a Talon observation)
#   - provider credential never enters Talon evidence or logs
#   - signed evidence verifies online and offline, across a Talon restart
#   Action channel (TestE2E_OpenShell_ComposedActionChannel, #457/#482):
#   - a sandbox with NO Talon credential reaches the Action Gateway through the
#     hop assertion: allow → one dispatch; deny → zero; approval → zero until a
#     host-side human approves, then exactly one; exact replay never duplicates
#   - unbound / forged / tampered / re-routed identity refused with no state;
#     the reviewer route is unreachable through the hop; session join; restart
#   Response channel (TestE2E_OpenShell_ResponseGovernance):
#   - PRE_RETURN replayed: actual usage settled under the decision's
#     correlation id (decision books no cost), PII transformed before delivery,
#     a usage-less response keeps its estimate, session cost = settled actuals
#
# What this does NOT prove: OpenShell's own behaviour. The live lane against
# a real OpenShell gateway is documented in docs/integration/openshell.md.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -tags=e2e ./tests/e2e -run 'TestE2E_OpenShell' -count=1 -v "$@"

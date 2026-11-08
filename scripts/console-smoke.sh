#!/usr/bin/env bash
# Operations-console read-contract smoke (#535): one deterministic, no-key run
# of the built binary as `talon serve --gateway` against a fake provider,
# with real governed traffic in one asserted session. Proves that the console
# read model, opened READ-ONLY on the live store, shows the same facts as the
# CLI's structured output (`talon agents/costs/session/audit --json`) — during
# traffic, across a restart of the data-plane process, and after it stops —
# that the runtime section stays unknown without a probe, that a stopped or
# admin-key-protected server makes `talon metrics` fail loudly instead of
# falling back to local numbers, and that live records verify.
#
# Independent of make test-smoke (no provider key, no Docker); also run as
# `make test-console-smoke`, smoke section 43 and a named PR CI step.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -tags=e2e ./tests/e2e -run 'TestE2E_Console' -count=1 -v "$@"

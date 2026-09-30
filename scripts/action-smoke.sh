#!/usr/bin/env bash
# Exact governed-action smoke (#458): one deterministic, no-key run of the
# built binary through the public Action Gateway, with a counting mock
# downstream. Proves DENY = 0 dispatch; REQUIRE_APPROVAL = 0 before and 0
# after the reviewer decision, 1 after the controlled resume; exact replay
# still 1; changed payload = conflict; lost response = UNKNOWN with no
# automatic retry; restart survival; `talon audit verify --operation`
# VALID, and INVALID after a database tamper.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -tags=e2e ./tests/e2e -run 'TestE2E_ActionGateway' -count=1 -v "$@"

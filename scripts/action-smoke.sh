#!/usr/bin/env bash
# Exact governed-action smoke (#458): one deterministic, no-key run of the
# built binary through the public Action Gateway, with a counting mock
# downstream. Proves DENY = 0 dispatch; REQUIRE_APPROVAL = 0 before and 0
# after the reviewer decision, 1 after the controlled resume; exact replay
# still 1; changed payload = conflict; lost response = UNKNOWN with no
# automatic retry; restart survival; `talon audit verify --operation`
# VALID, and INVALID after a database tamper. Since #425 it also runs the
# ACME company-policy scenario: one `gateway.organization_policy.constraints`
# policy over two use cases (company DENY and approval, no weakening by a use
# case, reviewer matrix with zero dispatch, stale approval invalidated across
# a restart under a changed company rule, lifecycle verified).
#
# Independent of make test-smoke (no provider key, no Docker); also run as
# `make test-action-smoke`, smoke section 41 and a named PR CI step.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -tags=e2e ./tests/e2e -run 'TestE2E_ActionGateway' -count=1 -v "$@"

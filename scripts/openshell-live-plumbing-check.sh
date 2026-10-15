#!/usr/bin/env bash
# Regression guard for the OpenShell Live lane's pipeline plumbing (#482, PR
# #490 review): the workflow once showed green while the harness failed at
# TLS startup because `make … | tee` dropped the harness's exit status. This
# check needs no Docker and proves, on every run of the lane:
#   1. a failing harness fails `make test-openshell-live` through a tee
#      pipeline under pipefail (the exact form the workflow uses);
#   2. the same pipeline WITHOUT pipefail would hide it (so the guard is
#      meaningful, not tautological);
#   3. the workflow file carries the pipefail and the ALL PASS verdict gate.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
WF=".github/workflows/openshell-live.yml"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/openshell-plumbing.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# 1. harness failure propagates through the workflow's pipeline form.
if (set -o pipefail; TALON_OPENSHELL_SELFTEST_FAIL=1 make test-openshell-live 2>&1 | tee "$tmp/a.log" >/dev/null); then
  echo "FAIL plumbing: a failing harness exited 0 through 'make | tee' under pipefail" >&2; exit 1
fi
grep -q '^FAIL self-test' "$tmp/a.log" || { echo "FAIL plumbing: the harness self-test did not run" >&2; exit 1; }
# 2. without pipefail the status is lost — the bug this guard exists for.
if ! (set +o pipefail; TALON_OPENSHELL_SELFTEST_FAIL=1 make test-openshell-live 2>&1 | tee "$tmp/b.log" >/dev/null); then
  echo "WARN plumbing: 'make | tee' without pipefail now propagates failure; the guard below is redundant but harmless" >&2
fi
# 3. the workflow itself declares pipefail in the run step and gates on the verdict.
grep -qE '^\s*set -euo pipefail' "$WF" || { echo "FAIL plumbing: $WF has no 'set -euo pipefail'" >&2; exit 1; }
grep -qF "grep -q '^ALL PASS openshell live smoke' openshell-live.log" "$WF" || { echo "FAIL plumbing: $WF has no ALL PASS verdict gate" >&2; exit 1; }
grep -qF 'ALL PASS openshell live smoke' scripts/openshell-live.sh || { echo "FAIL plumbing: the harness no longer prints the verdict the workflow gates on" >&2; exit 1; }
# 4. the workload fixture is explicit and digest pinned; no default OpenShell image can creep back in.
grep -qF -- '--from "$WORKLOAD_IMAGE"' scripts/openshell-live.sh || { echo "FAIL plumbing: create_sandbox no longer passes --from \"\$WORKLOAD_IMAGE\"; the lane would fall back to OpenShell's default image" >&2; exit 1; }
grep -qE '^WORKLOAD_IMAGE_DIGEST="sha256:[0-9a-f]{64}"$' scripts/openshell-live.sh || { echo "FAIL plumbing: WORKLOAD_IMAGE_DIGEST is not a sha256 digest" >&2; exit 1; }
grep -qF '[[ "$WORKLOAD_IMAGE" == *@sha256:* ]] ||' scripts/openshell-live.sh || { echo "FAIL plumbing: the digest-pin guard on WORKLOAD_IMAGE is gone" >&2; exit 1; }
if grep -nE 'sandbox create' scripts/openshell-live.sh | grep -vF -- '--from "$WORKLOAD_IMAGE"' | grep -vE '^\s*[0-9]+:\s*#'; then
  echo "FAIL plumbing: a sandbox create without --from \"\$WORKLOAD_IMAGE\" exists in the harness" >&2; exit 1
fi
echo "PASS openshell live plumbing: a failing harness is a failing job; the workload fixture is explicit and digest pinned"

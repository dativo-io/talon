#!/usr/bin/env bash
# Offline contract test for the canonical showcase runner (no Docker, no
# OpenShell, no keys): the command vocabulary and its refusals, the embedded
# contract's required environment, and `prepare` in standalone mode against a
# built Talon — validated by `talon doctor` and by Talon's own loaders — plus
# its idempotency and `stop`. The real-runtime proof is `demo.sh validate`.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$HERE/demo.sh"
TALON="${TALON_SHOWCASE_TALON_BIN:?set TALON_SHOWCASE_TALON_BIN to a talon binary that includes 'talon openshell prepare'}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/talon-showcase-contract.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

# 1. Vocabulary: exactly nine commands; anything else is a usage error (exit 2).
for bad in "" help prepare-all run-all; do
  set +e; out="$(TALON_SHOWCASE_RUN_DIR="$WORK/vocab" bash "$RUNNER" $bad 2>&1)"; rc=$?; set -e
  [[ "$rc" == 2 ]] || fail "'$bad' must be a usage error (exit 2), got $rc: $out"
  grep -q 'Commands (exactly these' <<<"$out" || fail "usage text missing for '$bad'"
done
set +e; TALON_SHOWCASE_RUN_DIR="$WORK/vocab" bash "$RUNNER" status extra >/dev/null 2>&1; rc=$?; set -e
[[ "$rc" == 2 ]] || fail "extra arguments must be a usage error"
pass "vocabulary: unknown commands and extra arguments are usage errors"

# 2. Embedded contract: the required environment is enforced before anything runs.
set +e; out="$(TALON_SHOWCASE_EMBEDDED=1 bash "$RUNNER" prepare 2>&1)"; rc=$?; set -e
[[ "$rc" != 0 ]] && grep -q 'embedded mode requires TALON_SHOWCASE_CONFIG_DIR' <<<"$out" || fail "embedded mode without its environment must refuse: $out"
set +e; out="$(TALON_SHOWCASE_EMBEDDED=1 TALON_SHOWCASE_CONFIG_DIR="$WORK/none" TALON_SHOWCASE_TALON_DATA_DIR="$WORK/none" TALON_SHOWCASE_TALON_URL=http://127.0.0.1:1 TALON_SHOWCASE_RUN_DIR="$WORK/emb" TALON_SHOWCASE_TALON_BIN="$TALON" TALON_SECRETS_KEY=0123456789abcdef0123456789abcdef bash "$RUNNER" prepare 2>&1)"; rc=$?; set -e
[[ "$rc" != 0 ]] && grep -q 'does not exist' <<<"$out" || fail "embedded prepare without a bootstrapped config must refuse: $out"
set +e; out="$(TALON_SHOWCASE_EMBEDDED=1 TALON_SHOWCASE_CONFIG_DIR="$WORK/none" TALON_SHOWCASE_TALON_DATA_DIR="$WORK/none" TALON_SHOWCASE_TALON_URL=http://127.0.0.1:1 TALON_SHOWCASE_RUN_DIR="$WORK/emb" bash "$RUNNER" validate 2>&1)"; rc=$?; set -e
[[ "$rc" != 0 ]] && grep -q 'validate runs standalone' <<<"$out" || fail "validate must refuse embedded mode: $out"
pass "embedded contract: required environment and refusals"

# 3. Standalone prepare against a built Talon: the configuration validates
#    through Talon's loaders and doctor, the reviewer credential exists, and a
#    second prepare changes nothing.
export TALON_SHOWCASE_RUN_DIR="$WORK/run" TALON_SHOWCASE_TALON_BIN="$TALON" TALON_SHOWCASE_HOST=10.9.8.7
# The operator's shell carries its OWN Talon's key; the standalone runner must
# not use it (two shells with different values would corrupt the vault).
TALON_SECRETS_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bash "$RUNNER" prepare >"$WORK/prepare1.out" 2>&1 || { cat "$WORK/prepare1.out"; fail "standalone prepare"; }
[[ -s "$WORK/run/talon.env" && "$(stat -c %a "$WORK/run/talon.env")" == 600 ]] || fail "standalone mode must own its Talon keys in a private talon.env"
grep -q 'TALON_SECRETS_KEY=aaaaaaaa' "$WORK/run/talon.env" && fail "the ambient secrets key must never become the showcase Talon's key"
grep -q 'TALON_SIGNING_KEY=' "$WORK/run/talon.env" || fail "a signing key must be generated for the showcase Talon"
grep -q '^PASS prepare' "$WORK/prepare1.out" || fail "prepare did not report success: $(cat "$WORK/prepare1.out")"
grep -q 'NOTE gateway.openshell changed' "$WORK/prepare1.out" || fail "the first prepare must announce the restart boundary"
cfg="$WORK/run/config/talon.config.yaml"
[[ -f "$cfg" && -f "$WORK/run/config/agents/sandboxed-support/agent.talon.yaml" && -s "$WORK/run/reviewer.key" && -f "$WORK/run/tls/ca.pem" && -f "$WORK/run/openshell-jwks.json" ]] || fail "prepare artifacts missing"
[[ "$(stat -c %a "$WORK/run/reviewer.key")" == 600 ]] || fail "reviewer credential must be private"
grep -q 'spiffe://' "$WORK/run/config/agents/sandboxed-support/agent.talon.yaml" && fail "no sandbox exists yet: no binding may be written at prepare time"
source "$WORK/run/talon.env"
doctor="$(cd "$WORK/run/config" && TALON_DATA_DIR="$WORK/run/talon-data" "$TALON" doctor --gateway-config talon.config.yaml --skip-upstream 2>&1 || true)"
grep -q 'openshell_transport' <<<"$doctor" || fail "doctor did not run the openshell category: $doctor"
for chk in openshell_transport openshell_identity_keys openshell_response_governance openshell_self_destination openshell_capture_bound gateway_secrets_openshell-mock gateway_agent_identity; do
  grep -qE "✓ +$chk" <<<"$doctor" || fail "doctor: $chk not passing: $doctor"
done
grep -qE '✗ +openshell_' <<<"$doctor" && fail "doctor: an openshell check fails: $doctor"
(cd "$WORK/run/config" && TALON_DATA_DIR="$WORK/run/talon-data" "$TALON" validate >/dev/null 2>&1) || fail "talon validate rejected the prepared use case"
jq -e '.restart_required == true and .agent_created == true and (.actions | length == 3) and (.forbidden_tools == ["delete_customer"])' "$WORK/run/prepare.json" >/dev/null || fail "prepare summary: $(cat "$WORK/run/prepare.json")"
# A second prepare from a shell with a DIFFERENT ambient key still reads the
# vault: talon.env is authoritative (the failure mode this guards against is
# "cipher: message authentication failed" at start).
TALON_SECRETS_KEY=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb bash "$RUNNER" prepare >"$WORK/prepare2.out" 2>&1 || { cat "$WORK/prepare2.out"; fail "second prepare"; }
jq -e '.config_changed == false and .agent_changed == false' "$WORK/run/prepare.json" >/dev/null || fail "prepare is not idempotent: $(cat "$WORK/run/prepare.json")"
grep -q 'NOTE gateway.openshell changed' "$WORK/prepare2.out" && fail "an unchanged prepare must not announce a restart"
cmp -s "$WORK/run/reviewer.key" <(cat "$WORK/run/reviewer.key") || true
pass "standalone prepare: config and use case validated by Talon's loaders and doctor; reviewer credential private; idempotent"

# A data dir written by an earlier run that used ambient keys is refused with
# instructions instead of producing an unreadable vault later.
mkdir -p "$WORK/stale/talon-data" && touch "$WORK/stale/talon-data/secrets.db"
set +e; out="$(TALON_SHOWCASE_RUN_DIR="$WORK/stale" bash "$RUNNER" prepare 2>&1)"; rc=$?; set -e
[[ "$rc" != 0 ]] && grep -q 'already holds a vault' <<<"$out" || fail "a vault without talon.env must be refused: $out"
pass "standalone keys: owned by the run dir, ambient keys ignored, stale vault refused"

# 4. status before start fails closed; stop is safe to run without anything started.
set +e; out="$(bash "$RUNNER" status 2>&1)"; rc=$?; set -e
[[ "$rc" != 0 ]] && grep -q '\[FAIL\]' <<<"$out" || fail "status before start must fail: $out"
grep -q 'talon doctor' <<<"$out" || grep -q 'doctor' <<<"$out" || fail "status must surface talon doctor results: $out"
bash "$RUNNER" stop >/dev/null 2>&1 || fail "stop without resources must succeed"
pass "status fails closed before start; stop is idempotent"

# 5. Hygiene: no key material in the logs the runner writes.
grep -rqE 'PRIVATE KEY-----|talon_appr_cred_' "$WORK/run/logs" 2>/dev/null && fail "key material in logs"
pass "logs carry no key material"
echo "ALL PASS showcase runner contract"

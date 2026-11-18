#!/usr/bin/env bash
# Talon published-image quickstart (#463): one command, no Git clone, no Go,
# no provider key. It runs the PUBLISHED Talon image (or, for testing, a
# local binary), lets Talon make two real pre-provider decisions on a
# request — a PII block and a model-policy denial; no model provider exists
# in this setup, so nothing can be dispatched — and verifies the signed
# evidence of both. It prints the image digest it ran and the elapsed time.
#
#   curl -fsSL https://raw.githubusercontent.com/dativo-io/talon/main/scripts/quickstart.sh | TALON_VERSION=X.Y.Z bash
#
# Environment:
#   TALON_VERSION          release to run (X.Y.Z); image ghcr.io/dativo-io/talon:<version>
#   TALON_IMAGE            full image reference instead (for example a digest pin)
#   TALON_QUICKSTART_PORT  host port on 127.0.0.1 (default 18080)
#   TALON_QUICKSTART_NO_PULL 1 = use the image already on this host (a locally built tag)
#   TALON_QUICKSTART_KEEP  1 = leave the container and its data volume running
#                          (then: docker exec <name> talon audit list)
#   TALON_QUICKSTART_BIN   run this local talon binary instead of Docker (tests)
# Needs: bash, curl, and Docker (unless TALON_QUICKSTART_BIN). Changes
# nothing outside a temporary directory, one container and one volume.
set -euo pipefail

started=$(date +%s)
PORT="${TALON_QUICKSTART_PORT:-18080}"
NAME="talon-quickstart-$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/talon-quickstart.XXXXXX")"
BIN="${TALON_QUICKSTART_BIN:-}"
serve_pid=""

if [ -z "$BIN" ]; then
  IMAGE="${TALON_IMAGE:-}"
  if [ -z "$IMAGE" ]; then
    [ -n "${TALON_VERSION:-}" ] || { echo "Set TALON_VERSION=X.Y.Z (a published release) or TALON_IMAGE; this quickstart never assumes 'latest'." >&2; exit 2; }
    IMAGE="ghcr.io/dativo-io/talon:${TALON_VERSION#v}"
  fi
  command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
fi
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

cleanup() {
  code=$?
  if [ -n "$serve_pid" ]; then kill "$serve_pid" 2>/dev/null || true; wait "$serve_pid" 2>/dev/null || true; fi
  if [ -z "$BIN" ] && [ "${TALON_QUICKSTART_KEEP:-0}" != "1" ]; then
    if [ "$code" -ne 0 ]; then docker logs --tail 40 "$NAME" 2>&1 | sed 's/^/  talon: /' >&2 || true; fi
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$NAME-data" >/dev/null 2>&1 || true
  fi
  [ "${TALON_QUICKSTART_KEEP:-0}" = "1" ] || rm -rf "$WORK"
  exit "$code"
}
trap cleanup EXIT

# A random key for this run only; it never leaves this machine.
rand() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
AGENT_KEY="qs_$(rand 24)"
SECRETS_KEY="$(rand 16)"

cat >"$WORK/talon.config.yaml" <<'YAML'
# Company policy for the quickstart: PII in a request is blocked, only one
# model is allowed. The provider URL points at nothing: no request can be
# dispatched, and none needs to be for Talon to decide.
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "http://127.0.0.1:9"
      allowed_models: ["gpt-4o-mini"]
  organization_policy:
    defaults:
      pii_action: "block"
      daily_cost: 10.00
YAML
cat >"$WORK/agent.talon.yaml" <<'YAML'
agent:
  name: "quickstart"
  description: "Talon quickstart use case"
  version: "1.0.0"
  key:
    secret_name: "quickstart-talon-key"
policies:
  cost_limits:
    daily: 10.00
    monthly: 100.00
YAML
chmod a+rx "$WORK"; chmod a+r "$WORK"/*.yaml

if [ -n "$BIN" ]; then
  export TALON_DATA_DIR="$WORK/data" TALON_SECRETS_KEY="$SECRETS_KEY" HOME="$WORK/home"
  unset TALON_ADMIN_KEY TALON_SIGNING_KEY
  mkdir -p "$TALON_DATA_DIR" "$HOME"
  talon() { (cd "$WORK" && "$BIN" "$@"); }
  talon secrets set quickstart-talon-key "$AGENT_KEY" >/dev/null 2>&1
  talon secrets set openai-api-key "unused-no-provider" >/dev/null 2>&1
  (cd "$WORK" && exec "$BIN" serve --port "$PORT" --gateway --gateway-config "$WORK/talon.config.yaml") >"$WORK/serve.log" 2>&1 &
  serve_pid=$!
  echo "Talon: $("$BIN" version | sed -n 1p) (local binary $BIN)"
else
  [ "${TALON_QUICKSTART_NO_PULL:-0}" = "1" ] || docker pull -q "$IMAGE" >/dev/null
  digest="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}(no registry digest: local image){{end}}' "$IMAGE")"
  docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" \
    -e TALON_SECRETS_KEY="$SECRETS_KEY" -e QS_AGENT_KEY="$AGENT_KEY" \
    -v "$WORK/talon.config.yaml:/etc/talon/talon.config.yaml:ro" \
    -v "$WORK/agent.talon.yaml:/home/talon/agent.talon.yaml:ro" \
    -v "$NAME-data:/home/talon/.talon" \
    --entrypoint /bin/sh "$IMAGE" -c '
      talon secrets set quickstart-talon-key "$QS_AGENT_KEY" >/dev/null 2>&1 &&
      talon secrets set openai-api-key "unused-no-provider" >/dev/null 2>&1 &&
      exec talon serve --port 8080 --gateway --gateway-config /etc/talon/talon.config.yaml' >/dev/null
  talon() { docker exec "$NAME" talon "$@"; }
  echo "Talon: $(talon version | sed -n 1p)"
  echo "Image: $IMAGE"
  echo "Digest: $digest"
fi

deadline=$(( $(date +%s) + 60 ))
until curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/health" 2>/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "Talon did not become healthy on 127.0.0.1:${PORT}" >&2; exit 1; }
  sleep 0.5
done

fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1 (got $2, want $3)"; fail=1; fi; }
request() { # request <model> <content>  → prints "<http status> <error code>"
  curl -sS -o "$WORK/body" -w '%{http_code}' -X POST "http://127.0.0.1:${PORT}/v1/proxy/openai/v1/chat/completions" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$2\",\"messages\":[{\"role\":\"user\",\"content\":\"$3\"}]}"
  printf ' %s' "$(grep -oE '"code":"[a-z_]+"' "$WORK/body" | head -n1 | cut -d'"' -f4)"
}

echo
echo "1. A request carrying an IBAN and an email address (company policy: block PII):"
check "Talon blocked it before any provider call" "$(request "$AGENT_KEY" gpt-4o-mini 'Refund to IBAN DE89370400440532013000, contact jan.kowalski@example.com')" "400 pii_policy_violation"
echo "2. A request for a model the company policy does not allow:"
check "Talon denied it before any provider call" "$(request "$AGENT_KEY" gpt-4o 'hello')" "403 model_not_allowed"
echo "3. A request with an unknown key:"
check "Talon refused the caller" "$(request "not-a-talon-key" gpt-4o-mini 'hello' | cut -d' ' -f1)" "401"

echo
echo "4. Signed evidence of the two decisions:"
talon audit list --limit 5 >"$WORK/audit.txt" 2>/dev/null || true
ids="$(grep -oE 'gw_[0-9a-f-]+' "$WORK/audit.txt" | awk '!seen[$0]++' | head -n 2)"
count="$(printf '%s\n' "$ids" | grep -c . || true)"
check "two evidence records were written" "$count" "2"
for id in $ids; do
  if talon audit verify "$id" >"$WORK/verify.txt" 2>&1 && grep -qiE 'valid|verified' "$WORK/verify.txt" && ! grep -qiE 'invalid|tamper' "$WORK/verify.txt"; then
    echo "PASS signature verified: $id"
  else
    echo "FAIL signature not verified: $id"; sed 's/^/  /' "$WORK/verify.txt"; fail=1
  fi
done
grep -E 'gw_' "$WORK/audit.txt" | head -n 2 | sed 's/^/  /'

elapsed=$(( $(date +%s) - started ))
echo
if [ "$fail" -eq 0 ]; then
  echo "PASS talon quickstart in ${elapsed}s (includes the image pull): two governed decisions, no provider, evidence verified."
  echo "Next: the production pilot runbook — https://github.com/dativo-io/talon/blob/main/docs/guides/production-pilot.md"
else
  echo "FAIL talon quickstart after ${elapsed}s"; exit 1
fi

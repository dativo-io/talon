#!/usr/bin/env bash
# Console Compose smoke (#536, #537): the supported no-key Compose stack
# (examples/docker-compose) starts the console as its own service, published
# to the host loopback only; a browser-like client pairs with the one-time
# code from the container log, reads the same installation the data plane
# wrote to, cannot reach any privileged route through the console, and a
# console restart leaves the data plane serving. Needs Docker; no provider
# key. Run by `make test-console-compose-smoke` and the CI Docker job.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/examples/docker-compose/docker-compose.yml" --project-name talon-console-smoke)
WORK="$(mktemp -d "${TMPDIR:-/tmp}/console-compose-smoke.XXXXXX")"
UI="http://127.0.0.1:8787"
DP="http://127.0.0.1:8080"
failures=0

cleanup() {
  if [ "$failures" -ne 0 ]; then
    # The job log is the only place a CI failure can be read: show what the
    # containers said (no secret is in these logs by the stack's design).
    echo "::group::docker compose ps"; "${COMPOSE[@]}" ps 2>/dev/null || true; echo "::endgroup::"
    echo "::group::talon-ui log"; "${COMPOSE[@]}" logs --no-color --tail=80 talon-ui 2>/dev/null || true; echo "::endgroup::"
    echo "::group::talon log (tail)"; "${COMPOSE[@]}" logs --no-color --tail=40 talon 2>/dev/null || true; echo "::endgroup::"
    echo "::group::last response body"; cat "$WORK/body" 2>/dev/null || true; echo; echo "::endgroup::"
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

check() { # check <description> <command...>
  local desc="$1"; shift
  if "$@"; then echo "PASS: $desc"; else echo "FAIL: $desc"; failures=$((failures + 1)); fi
}

wait_http() { # wait_http <url> <seconds>
  local url="$1" deadline=$(( $(date +%s) + $2 ))
  until curl -fsS -o /dev/null "$url"; do
    [ "$(date +%s)" -lt "$deadline" ] || { echo "timeout waiting for $url" >&2; return 1; }
    sleep 1
  done
}

pairing_codes() { # every code printed so far, oldest first
  "${COMPOSE[@]}" logs --no-color talon-ui 2>/dev/null | grep -oE 'Talon console pairing code: [A-Z2-9]{5}(-[A-Z2-9]{5}){3}' | awk '{print $NF}'
}

wait_codes() { # wait_codes <n>
  local n="$1" deadline=$(( $(date +%s) + 30 ))
  while [ "$(pairing_codes | wc -l)" -lt "$n" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || { echo "timeout waiting for $n pairing codes" >&2; return 1; }
    sleep 1
  done
}

status_of() { # status_of <method> <url> [curl args...]
  local method="$1" url="$2"; shift 2
  curl -sS -o "$WORK/body" -w '%{http_code}' -X "$method" "$url" "$@"
}

"${COMPOSE[@]}" up -d --build
wait_http "$DP/health" 120
wait_http "$UI/healthz" 60

# Port scope: console AND data plane are published on the host loopback only.
# The data plane of this no-key stack is development-open; console pairing
# must never read as "the installation is secured" while 8080 faces the LAN.
binding="$("${COMPOSE[@]}" port talon-ui 8787)"
check "console published on 127.0.0.1 only (got $binding)" [ "${binding%%:*}" = "127.0.0.1" ]
dp_binding="$("${COMPOSE[@]}" port talon 8080)"
check "data plane published on 127.0.0.1 only (got $dp_binding)" [ "${dp_binding%%:*}" = "127.0.0.1" ]

# One governed request through the data plane (mock provider), so the store holds traffic.
check "governed request through the data plane" \
  [ "$(status_of POST "$DP/v1/proxy/openai/v1/chat/completions" -H 'Content-Type: application/json' -H 'Authorization: Bearer talon-demo-key' -H 'X-Talon-Session-ID: compose-smoke' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}')" = "200" ]

# Unpaired: the read API refuses; the shell and liveness are open.
check "unpaired read is 401" [ "$(status_of GET "$UI/console/v1/overview")" = "401" ]
check "shell served" [ "$(status_of GET "$UI/")" = "200" ]
check "no legacy privileged route on the console (/v1/secrets 404)" [ "$(status_of GET "$UI/v1/secrets")" = "404" ]

# Pair with the code from the container log (the only place it appears).
wait_codes 1
code="$(pairing_codes | tail -n1)"
check "wrong code refused" [ "$(status_of POST "$UI/console/auth/pair" -H 'Content-Type: application/json' -d '{"code":"AAAAA-AAAAA-AAAAA-AAAAA"}')" = "401" ]
sleep 1
check "cross-origin pairing refused" [ "$(status_of POST "$UI/console/auth/pair" -H 'Content-Type: application/json' -H 'Origin: http://evil.example' -d "{\"code\":\"$code\"}")" = "403" ]
sleep 1
check "pair with the logged code" [ "$(status_of POST "$UI/console/auth/pair" -c "$WORK/jar" -H 'Content-Type: application/json' -d "{\"code\":\"$code\"}")" = "200" ]
check "session cookie is HttpOnly" grep -q 'HttpOnly' "$WORK/jar"
# The demo agent lives in tenant "demo" (examples/docker-compose/agent.talon.yaml).
check "paired overview is 200" [ "$(status_of GET "$UI/console/v1/overview?tenant=demo" -b "$WORK/jar")" = "200" ]
check "overview reports today's request count for tenant demo" grep -Eq '"requests":[1-9]' "$WORK/body"
# The console reads the very session the data plane just wrote (shared store, read-only connection).
check "session written by the data plane is readable through the console" [ "$(status_of GET "$UI/console/v1/sessions/compose-smoke?tenant=demo" -b "$WORK/jar")" = "200" ]
check "session summary counts the governed request" grep -Eq '"requests":1' "$WORK/body"
check "write verb on the read API is 405" [ "$(status_of POST "$UI/console/v1/overview" -b "$WORK/jar" -H 'Content-Type: application/json' -d '{}')" = "405" ]
check "console cookie is nothing on the data plane admin route" [ "$(status_of GET "$DP/api/v1/metrics" -b "$WORK/jar")" = "401" ]
sleep 1
check "replayed code refused" [ "$(status_of POST "$UI/console/auth/pair" -H 'Content-Type: application/json' -d "{\"code\":\"$code\"}")" = "401" ]

# Reissue from inside the container: a fresh code reaches the log, the old session survives.
check "talon ui pair inside the container" "${COMPOSE[@]}" exec -T talon-ui talon ui pair
wait_codes 2
second="$(pairing_codes | tail -n1)"
check "reissued code differs" [ "$second" != "$code" ]
check "existing session survives the reissue" [ "$(status_of GET "$UI/console/v1/system" -b "$WORK/jar")" = "200" ]

# Restart independence: the console restarts, the data plane never stopped.
"${COMPOSE[@]}" restart talon-ui >/dev/null
check "data plane healthy across the console restart" [ "$(status_of GET "$DP/health")" = "200" ]
wait_http "$UI/healthz" 60
check "sessions do not survive a console restart" [ "$(status_of GET "$UI/console/v1/system" -b "$WORK/jar")" = "401" ]

# No secret in the console log.
"${COMPOSE[@]}" logs --no-color talon-ui >"$WORK/talon-ui.log"
check "no provider/agent key in the console log" bash -c "! grep -q 'talon-demo-key' '$WORK/talon-ui.log'"

echo
if [ "$failures" -eq 0 ]; then echo "PASS console-compose-smoke"; else echo "FAIL console-compose-smoke: $failures failed"; exit 1; fi

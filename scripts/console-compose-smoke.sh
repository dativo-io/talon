#!/usr/bin/env bash
# Console Compose smoke (#536, #537): the supported no-key Compose stack
# (examples/docker-compose) starts the console as its own service, published
# to the host loopback only; a browser-like client pairs with the one-time
# code from the container log, reads the same installation the data plane
# wrote to, cannot reach any privileged route through the console, and a
# console restart leaves the data plane serving. Needs Docker; no provider
# key. Run by `make test-console-compose-smoke` and the CI Docker job.
#
# Image under test (#533 release acceptance):
#   (default)                       build both Talon services from this checkout
#                                   (docker-compose.yml alone)
#   TALON_IMAGE=<ref>               run that image instead, never built here
#                                   (adds docker-compose.published.yml, which
#                                   removes the build sections, so a failed
#                                   pull can never turn into a source build):
#                                   the release image built from
#                                   Dockerfile.goreleaser in PR CI, or the
#                                   published ghcr.io/dativo-io/talon:<version>
#                                   in release verification and install smoke
#   TALON_PULL_POLICY=always|never  default `always` with TALON_IMAGE (pull the
#                                   published image anonymously); `never` for a
#                                   locally built tag
#   TALON_EXPECT_VERSION=<x.y.z>    fail unless the running image reports
#                                   "Talon <x.y.z>"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK="$REPO_ROOT/examples/docker-compose"
COMPOSE=(docker compose -f "$STACK/docker-compose.yml")
if [ -n "${TALON_IMAGE:-}" ]; then
  COMPOSE+=(-f "$STACK/docker-compose.published.yml")
fi
COMPOSE+=(--project-name talon-console-smoke)
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

if [ -n "${TALON_IMAGE:-}" ]; then
  export TALON_IMAGE
  export TALON_PULL_POLICY="${TALON_PULL_POLICY:-always}"
  echo "image under test: $TALON_IMAGE (pull_policy=$TALON_PULL_POLICY)"
  # No fallback to a source build: an image that cannot be resolved stops the
  # stack, and nothing is built under its name. (The base file alone would
  # build here: Compose ignores a pull failure when a build section exists.)
  repo="${TALON_IMAGE%@*}"
  case "${repo##*/}" in *:*) repo="${repo%:*}" ;; esac
  missing="$repo:talon-smoke-no-such-tag-$$"
  if TALON_IMAGE="$missing" "${COMPOSE[@]}" up -d --no-deps talon >"$WORK/missing.log" 2>&1; then
    echo "FAIL: an unresolvable image must stop the stack"; failures=$((failures + 1))
    TALON_IMAGE="$missing" "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  else
    echo "PASS: an unresolvable image stops the stack"
  fi
  check "nothing was built in place of the unresolvable image" bash -c "! docker image inspect '$missing' >/dev/null 2>&1"
  check "the published path declares no Talon build" bash -c "! TALON_IMAGE='$TALON_IMAGE' TALON_PULL_POLICY='$TALON_PULL_POLICY' docker compose -f '$STACK/docker-compose.yml' -f '$STACK/docker-compose.published.yml' config --format json | jq -e '.services.talon.build or .services[\"talon-ui\"].build' >/dev/null"
  # Only the mock provider is built; the Talon services run the given image.
  "${COMPOSE[@]}" build mock-openai
  "${COMPOSE[@]}" up -d
else
  echo "image under test: built from this checkout"
  "${COMPOSE[@]}" up -d --build
fi
wait_http "$DP/health" 120
wait_http "$UI/healthz" 60

running_version="$("${COMPOSE[@]}" exec -T talon talon version | sed -n 1p)"
echo "running: $running_version"
if [ -n "${TALON_IMAGE:-}" ]; then
  # Data plane and console run the same resolved image, and it is the one named.
  want_id="$(docker image inspect --format '{{.Id}}' "$TALON_IMAGE")"
  dp_id="$(docker inspect --format '{{.Image}}' "$("${COMPOSE[@]}" ps -q talon)")"
  ui_id="$(docker inspect --format '{{.Image}}' "$("${COMPOSE[@]}" ps -q talon-ui)")"
  check "the data plane runs the named image ($want_id)" [ "$dp_id" = "$want_id" ]
  check "the console runs the same image as the data plane" [ "$ui_id" = "$dp_id" ]
  echo "image digest(s): $(docker image inspect --format '{{join .RepoDigests ", "}}' "$TALON_IMAGE")"
fi
if [ -n "${TALON_EXPECT_VERSION:-}" ]; then
  check "the data plane runs the expected release ($running_version)" [ "$running_version" = "Talon $TALON_EXPECT_VERSION" ]
  ui_version="$("${COMPOSE[@]}" exec -T talon-ui talon version | sed -n 1p)"
  check "the console runs the expected release ($ui_version)" [ "$ui_version" = "Talon $TALON_EXPECT_VERSION" ]
fi

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
# The pages read from these endpoints; each answers the paired browser.
for page in "overview?tenant=demo" "use-cases?tenant=demo" "use-cases/demo-agent?tenant=demo" "use-cases/demo-agent/effective-policy?tenant=demo" "approvals?tenant=demo" "sessions?tenant=demo" "costs?tenant=demo" "configuration" "system" "tenants"; do
  check "paired GET /console/v1/$page is 200" [ "$(status_of GET "$UI/console/v1/$page" -b "$WORK/jar")" = "200" ]
done
# Signed evidence: the console verifies the record the data plane signed, and
# says the same as `talon audit show --json` inside the data-plane container.
status_of GET "$UI/console/v1/sessions/compose-smoke/timeline?tenant=demo" -b "$WORK/jar" >/dev/null
evidence_id="$(jq -r '.timeline.records[0].id // empty' "$WORK/body")"
check "the session timeline names its evidence record ($evidence_id)" [ -n "$evidence_id" ]
check "evidence record readable through the console" [ "$(status_of GET "$UI/console/v1/evidence/$evidence_id?tenant=demo" -b "$WORK/jar")" = "200" ]
console_verdict="$(jq -r '.detail.verification.state // empty' "$WORK/body")"
cli_verdict="$("${COMPOSE[@]}" exec -T talon talon audit show "$evidence_id" --json | jq -r '.verification.state // empty')"
check "console verifies the signature ($console_verdict)" [ "$console_verdict" = "valid" ]
check "console and CLI verify the record the same way (console $console_verdict, CLI $cli_verdict)" [ "$console_verdict" = "$cli_verdict" ]
# Legacy dashboards were removed (#534): neither process serves them.
for legacy in /dashboard /gateway/dashboard /v1/dashboard/tenants-summary; do
  check "no legacy dashboard on the data plane ($legacy 404)" [ "$(status_of GET "$DP$legacy")" = "404" ]
done
check "write verb on the read API is 405" [ "$(status_of POST "$UI/console/v1/overview" -b "$WORK/jar" -H 'Content-Type: application/json' -d '{}')" = "405" ]
# The demo data plane runs without TALON_ADMIN_KEY, so the admin route's
# answer depends on that configuration, not on the console. The claim here is
# that the console cookie changes nothing: same answer with and without it.
# (With an admin key set, the cookie is refused: TestAdminKey_QueryAndCookieNoLongerAuthenticate.)
without_cookie="$(status_of GET "$DP/api/v1/metrics")"
with_cookie="$(status_of GET "$DP/api/v1/metrics" -b "$WORK/jar")"
check "console cookie changes nothing on the data plane admin route ($without_cookie without, $with_cookie with)" [ "$with_cookie" = "$without_cookie" ]
sleep 1
check "replayed code refused" [ "$(status_of POST "$UI/console/auth/pair" -H 'Content-Type: application/json' -d "{\"code\":\"$code\"}")" = "401" ]

# Reissue from inside the container: a fresh code reaches the log, the old session survives.
check "talon ui pair inside the container" "${COMPOSE[@]}" exec -T talon-ui talon ui pair
wait_codes 2
second="$(pairing_codes | tail -n1)"
check "reissued code differs" [ "$second" != "$code" ]
check "existing session survives the reissue" [ "$(status_of GET "$UI/console/v1/system" -b "$WORK/jar")" = "200" ]

# Runtime truth (#538): the console reads the data plane's own runtime record
# from the shared volume. The demo's gateway is running; after a graceful stop
# it is offline (history stays readable); after a start it runs again as a
# new instance.
gateway_state() {
  status_of GET "$UI/console/v1/system" -b "$WORK/jar" >/dev/null
  jq -r '.runtime.roles[] | select(.role=="gateway") | .state' "$WORK/body"
}
wait_gateway() { # wait_gateway <state> <seconds>
  local want="$1" deadline=$(( $(date +%s) + $2 ))
  while [ "$(gateway_state)" != "$want" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}
check "console reports the demo gateway running" wait_gateway running 30
first_instance="$(jq -r '.runtime.roles[] | select(.role=="gateway") | .instance_id' "$WORK/body")"
"${COMPOSE[@]}" stop talon >/dev/null
check "a stopped gateway reads offline, not running" wait_gateway offline 30
check "the session written earlier is still readable with the data plane stopped" [ "$(status_of GET "$UI/console/v1/sessions/compose-smoke?tenant=demo" -b "$WORK/jar")" = "200" ]
"${COMPOSE[@]}" start talon >/dev/null
wait_http "$DP/health" 120
check "the restarted gateway runs again" wait_gateway running 30
check "the restart is a new instance" [ "$(jq -r '.runtime.roles[] | select(.role=="gateway") | .instance_id' "$WORK/body")" != "$first_instance" ]

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

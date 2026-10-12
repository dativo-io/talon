#!/usr/bin/env bash
# Real-OpenShell live smoke (#482): Talon as supervisor middleware of a REAL
# OpenShell v0.1.3 gateway and sandbox, with a deterministic mock provider.
#
#   sandbox (released image) --curl--> OpenShell supervisor (network policy)
#     --gRPC EvaluateHttpRequest (gateway-signed extension JWT, TLS)--> talon
#     <-- ALLOW / transformed body / DENY --
#     --credential injection--> mock OpenAI-compatible provider (counts, exact bytes, Authorization)
#
# Proves against the released runtime, not a fixture:
#   A  allowed request: Talon decided once, provider called once, provider saw
#      the OpenShell-injected credential, Talon never saw it
#   B  PII transformation: provider receives Talon's redacted body, never the
#      original sensitive value
#   C  blocked model: Talon DENY, provider call count unchanged
#   D  unbound sandbox identity: DENY (workload_identity_unbound), count unchanged
#   E  Talon unavailable: OpenShell fails closed (middleware_failed), count unchanged
#   F  Talon restart: the next sandbox request is governed again without a
#      gateway restart (registration is static; Talon's identity did not change)
#   plus: signed Talon evidence with delegated_expected provenance verifies
#   offline, and the provider secret appears nowhere in Talon's state or logs.
#
# Requirements: Linux, Docker Engine >= 28 reachable by this user, a Landlock
# capable kernel, curl, openssl, tar, jq, Go toolchain (builds talon and the
# mock provider from this checkout), outbound access to github.com and
# ghcr.io. Nothing is installed system-wide: pinned release artifacts are
# cached under $TALON_OPENSHELL_CACHE. No private key, no provider spend.
#
# Usage: scripts/openshell-live.sh            (or: make test-openshell-live)
#   TALON_OPENSHELL_LIVE_HOST   non-loopback IPv4 of this host reachable from
#                               containers (auto-detected)
#   TALON_OPENSHELL_CACHE       artifact cache dir (default ~/.cache/talon-openshell)
#   TALON_OPENSHELL_KEEP=1      keep the work dir and logs on success
#   TALON_OPENSHELL_PREFLIGHT_ONLY=1
#                               stop before starting the gateway: verifies the
#                               pinned artifacts, builds talon, generates the
#                               gateway JWT bundle and Talon's TLS identity,
#                               starts talon with the middleware listener and
#                               runs `openshell-gateway config preflight` on the
#                               generated registration (no Docker needed)
set -euo pipefail
PREFLIGHT_ONLY="${TALON_OPENSHELL_PREFLIGHT_ONLY:-0}"

OPENSHELL_VERSION="v0.1.3"
# sha256 from the release's openshell-checksums-sha256.txt and
# openshell-gateway-checksums-sha256.txt (NVIDIA/OpenShell v0.1.3, 2026-10-09).
declare -A CLI_SHA=(
  [x86_64]="ed08ea7874c47f22d6e5dcc4b27d9ef1ef5d2060f83035b35ff725d5160830a3"
  [aarch64]="07687dacefc52bc73b01943f5b58f7a5082c1ceaa228461b9a2a78023b8057c0"
)
declare -A GW_SHA=(
  [x86_64]="da8dce943fe01cce90243b2bf2587c71a243e4d641a4b616528829b681ced198"
  [aarch64]="801214322227f64f2d3faa6989daaa5e6cd9ef1ab768b5860496deeb1158c27b"
)
RELEASE_BASE="https://github.com/NVIDIA/OpenShell/releases/download/${OPENSHELL_VERSION}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log()  { printf 'INFO %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
die()  { printf 'FAIL %s\n' "$*" >&2; dump_logs; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || { printf 'MISSING %s: %s\n' "$1" "$2" >&2; exit 2; }; }

# ---------------------------------------------------------------- preflight
[[ "$(uname -s)" == "Linux" ]] || { echo "MISSING linux: the OpenShell docker driver runs Linux sandboxes; run this on a Linux host or in CI" >&2; exit 2; }
for c in curl openssl tar jq go python3; do need "$c" "required by the live lane"; done
if [[ "$PREFLIGHT_ONLY" != "1" ]]; then
  need docker "the OpenShell docker driver creates the sandbox and supervisor containers"
  if ! docker info >/dev/null 2>&1; then
    echo "MISSING docker: Docker Engine must be reachable by $(id -un) (docker info failed). The OpenShell docker driver creates the sandbox and supervisor containers. Set TALON_OPENSHELL_PREFLIGHT_ONLY=1 to validate everything up to the gateway start without Docker." >&2
    exit 2
  fi
  DOCKER_MAJOR="$(docker version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1 || echo 0)"
  [[ "${DOCKER_MAJOR:-0}" -ge 28 ]] || { echo "MISSING docker>=28: found server $(docker version --format '{{.Server.Version}}')" >&2; exit 2; }
  if ! grep -q landlock /sys/kernel/security/lsm 2>/dev/null; then
    echo "WARN kernel LSM list lacks landlock; OpenShell filesystem containment may run in best_effort mode" >&2
  fi
fi
ARCH="$(uname -m)"
case "$ARCH" in x86_64|aarch64) ;; *) echo "MISSING arch: unsupported $ARCH" >&2; exit 2 ;; esac

detect_host() {
  if [[ -n "${TALON_OPENSHELL_LIVE_HOST:-}" ]]; then printf '%s\n' "$TALON_OPENSHELL_LIVE_HOST"; return; fi
  local a
  a="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [[ -n "$a" ]] || a="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./ && $i !~ /:/){print $i; exit}}')"
  [[ -n "$a" ]] || { echo "MISSING host address: set TALON_OPENSHELL_LIVE_HOST to a non-loopback IPv4 reachable from containers" >&2; exit 2; }
  printf '%s\n' "$a"
}
HOST_IP="$(detect_host)"
if [[ "$HOST_IP" == 127.* && "$PREFLIGHT_ONLY" != "1" ]]; then echo "MISSING host address: $HOST_IP is loopback; containers cannot reach it" >&2; exit 2; fi
MOCK_BIND="0.0.0.0"; [[ "$PREFLIGHT_ONLY" == "1" ]] && MOCK_BIND="127.0.0.1"

# ---------------------------------------------------------------- artifacts
CACHE="${TALON_OPENSHELL_CACHE:-$HOME/.cache/talon-openshell}/$OPENSHELL_VERSION"
mkdir -p "$CACHE"
fetch_pinned() { # name url sha dest
  local name="$1" url="$2" sha="$3" dest="$4"
  if [[ ! -x "$dest" ]]; then
    log "downloading $name ($OPENSHELL_VERSION)"
    curl -fsSL --retry 3 -o "$CACHE/$name.tgz" "$url"
    echo "$sha  $CACHE/$name.tgz" | sha256sum -c - >/dev/null || die "checksum mismatch for $name (expected $sha)"
    tar -xzf "$CACHE/$name.tgz" -C "$CACHE"
    [[ -x "$dest" ]] || die "$name archive did not contain $(basename "$dest")"
  fi
}
fetch_pinned "openshell-cli" "$RELEASE_BASE/openshell-${ARCH}-unknown-linux-musl.tar.gz" "${CLI_SHA[$ARCH]}" "$CACHE/openshell"
fetch_pinned "openshell-gateway" "$RELEASE_BASE/openshell-gateway-${ARCH}-unknown-linux-gnu.tar.gz" "${GW_SHA[$ARCH]}" "$CACHE/openshell-gateway"
CLI_BIN="$CACHE/openshell"; GW_BIN="$CACHE/openshell-gateway"
[[ "$("$CLI_BIN" --version)" == *"0.1.3"* ]] || die "unexpected CLI version: $("$CLI_BIN" --version)"
[[ "$("$GW_BIN" --version)" == *"0.1.3"* ]] || die "unexpected gateway version: $("$GW_BIN" --version)"

# ---------------------------------------------------------------- workspace
WORK="$(mktemp -d "${TMPDIR:-/tmp}/talon-openshell-live.XXXXXX")"
LOGS="$WORK/logs"; mkdir -p "$LOGS"
TALON_HOME="$WORK/talon-home"; mkdir -p "$TALON_HOME"
RUN_ID="talon-live-$$-$RANDOM"
GATEWAY_ID="talon-live-gw-$$"
SANDBOX_A="tl-a-$$"; SANDBOX_B="tl-b-$$"   # names are capped at 19 chars
PROVIDER_SECRET="sk-live-openshell-injected-$(openssl rand -hex 8)"
TALON_VAULT_DECOY="sk-talon-vault-value-never-used-on-delegated-path"
AUDIENCE="urn:openshell:extension:middleware:talon"
TALON_SECRETS_KEY="$(openssl rand -hex 16)"
TALON_SIGNING_KEY="$(openssl rand -hex 24)"
TALON_ADMIN_KEY="admin-$(openssl rand -hex 8)"
export TALON_DATA_DIR="$TALON_HOME" TALON_SECRETS_KEY TALON_SIGNING_KEY TALON_ADMIN_KEY TALON_AGENTS_RELOAD_INTERVAL=1s

free_port() { python3 - <<'PY' 2>/dev/null || awk 'BEGIN{srand(); print 20000+int(rand()*20000)}'
import socket
s=socket.socket(); s.bind(("0.0.0.0",0)); print(s.getsockname()[1]); s.close()
PY
}
TALON_HTTP_PORT="$(free_port)"; TALON_GRPC_PORT="$(free_port)"; MOCK_PORT="$(free_port)"; GW_PORT="$(free_port)"; GW_HEALTH_PORT="$(free_port)"
GW_ENDPOINT="http://127.0.0.1:$GW_PORT"
CLI=(env -u OPENSHELL_SANDBOX_POLICY "$CLI_BIN" --gateway-endpoint "$GW_ENDPOINT")

TALON_PID=""; GW_PID=""; MOCK_PID=""; SANDBOXES=()
dump_logs() {
  for f in talon-serve gateway mockprovider setup; do
    printf '\n--- %s log ---\n' "$f" >&2
    [[ -f "$LOGS/$f.log" ]] && tail -n 120 "$LOGS/$f.log" >&2 || printf '(missing)\n' >&2
  done
}
cleanup() {
  local status=$?
  trap - EXIT
  for sb in "${SANDBOXES[@]:-}"; do [[ -n "$sb" ]] && "${CLI[@]}" sandbox delete "$sb" >>"$LOGS/setup.log" 2>&1 || true; done
  for pid in "$GW_PID" "$TALON_PID" "$MOCK_PID"; do [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }; done
  if [[ "$status" -eq 0 && "${TALON_OPENSHELL_KEEP:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "work dir retained: $WORK" >&2; fi
  exit "$status"
}
trap cleanup EXIT

wait_http() { # url seconds
  local i; for ((i=0; i<"$2"*4; i++)); do curl -fsS --max-time 1 "$1" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1
}

# ---------------------------------------------------------------- build talon + mock provider
log "building talon and the mock provider from $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo untracked)"
go build -o "$WORK/talon" ./cmd/talon >>"$LOGS/setup.log" 2>&1 || die "go build talon"
go build -o "$WORK/mockprovider" ./tests/openshell-live/mockprovider >>"$LOGS/setup.log" 2>&1 || die "go build mockprovider"
TALON="$WORK/talon"

# ---------------------------------------------------------------- keys and certs
JWT_DIR="$WORK/jwt"; mkdir -p "$JWT_DIR"
openssl genpkey -algorithm ed25519 -out "$JWT_DIR/signing.pem" 2>>"$LOGS/setup.log"
openssl pkey -in "$JWT_DIR/signing.pem" -pubout -out "$JWT_DIR/public.pem" 2>>"$LOGS/setup.log"
KID="$RUN_ID-k1"; printf '%s\n' "$KID" >"$JWT_DIR/kid"
# JWKS for Talon from the SAME public key the gateway signs with (an operator
# would fetch <gateway>/.well-known/jwks.json over TLS instead).
PUB_X="$(openssl pkey -pubin -in "$JWT_DIR/public.pem" -outform DER | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
printf '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"%s","x":"%s"}]}\n' "$KID" "$PUB_X" >"$WORK/openshell-jwks.json"
# Talon's middleware TLS identity: the host IP (what the gateway and every
# supervisor dial) plus host.openshell.internal.
TLS_DIR="$WORK/tls"; mkdir -p "$TLS_DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=talon-openshell-middleware" \
  -addext "subjectAltName=IP:$HOST_IP,DNS:host.openshell.internal" \
  -keyout "$TLS_DIR/talon-key.pem" -out "$TLS_DIR/talon-cert.pem" >>"$LOGS/setup.log" 2>&1 || die "openssl cert"

# ---------------------------------------------------------------- mock provider
# Sandboxes reach the host as host.openshell.internal (the docker driver maps
# it to the bridge gateway address), so the mock must accept on every host
# interface for the duration of the run; the harness itself reads it on
# loopback. Talon's middleware listener binds the detected host address only.
"$WORK/mockprovider" -listen "$MOCK_BIND:$MOCK_PORT" -state-file "$WORK/provider-state.json" >"$LOGS/mockprovider.log" 2>&1 &
MOCK_PID=$!
wait_http "http://127.0.0.1:$MOCK_PORT/__state" 10 || die "mock provider did not start"
provider_state() { curl -fsS "http://127.0.0.1:$MOCK_PORT/__state"; }
provider_calls() { provider_state | jq -r '.calls'; }
provider_record() { provider_state | jq -r ".records[$1].$2"; }

# ---------------------------------------------------------------- talon
AGENT="sandboxed-support"
( cd "$TALON_HOME" && "$TALON" init --scaffold --name "$AGENT" >>"$LOGS/setup.log" 2>&1 ) || die "talon init"
AGENT_FILE="$TALON_HOME/agent.talon.yaml"
grep -q "secret_name: \"$AGENT-talon-key\"" "$AGENT_FILE" || die "scaffold shape changed (agent key block)"
cat >>"$TALON_HOME/talon.config.yaml" <<EOT

gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"          # /v1/proxy only; never read on the delegated path
      base_url: "http://host.openshell.internal:$MOCK_PORT"   # the HOST maps delegated requests to this provider
  organization_policy:
    defaults:
      pii_action: "redact"
      daily_cost: 100.00
    constraints:
      blocked_models: ["gpt-4o"]
  openshell:
    enabled: true
    listen: "$HOST_IP:$TALON_GRPC_PORT"
    tls:
      cert_file: "$TLS_DIR/talon-cert.pem"
      key_file: "$TLS_DIR/talon-key.pem"
    middleware_name: "talon"
    max_payload_bytes: 1048576
    request_timeout: "10s"
    identity:
      issuer: "openshell-gateway:$GATEWAY_ID"
      audience: "$AUDIENCE"
      jwks_file: "$WORK/openshell-jwks.json"
EOT
( cd "$TALON_HOME" && "$TALON" secrets set openai-api-key "$TALON_VAULT_DECOY" >>"$LOGS/setup.log" 2>&1 && "$TALON" secrets set "$AGENT-talon-key" "talon-gw-live-$(openssl rand -hex 6)" >>"$LOGS/setup.log" 2>&1 ) || die "talon secrets set"

start_talon() {
  ( cd "$TALON_HOME" && exec "$TALON" serve --port "$TALON_HTTP_PORT" --gateway --gateway-config "$TALON_HOME/talon.config.yaml" ) >>"$LOGS/talon-serve.log" 2>&1 &
  TALON_PID=$!
  wait_http "http://127.0.0.1:$TALON_HTTP_PORT/health" 30 || die "talon serve did not become healthy"
  local i; for ((i=0; i<40; i++)); do (exec 3<>"/dev/tcp/$HOST_IP/$TALON_GRPC_PORT") 2>/dev/null && return 0; sleep 0.25; done
  die "talon openshell listener not reachable at $HOST_IP:$TALON_GRPC_PORT"
}
start_talon
log "talon serving http :$TALON_HTTP_PORT, openshell middleware https://$HOST_IP:$TALON_GRPC_PORT"

# ---------------------------------------------------------------- openshell gateway
GW_CFG="$WORK/gateway.toml"
cat >"$GW_CFG" <<EOT
[openshell]
version = 2

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT_DIR/signing.pem"
public_key_path = "$JWT_DIR/public.pem"
kid_path = "$JWT_DIR/kid"
gateway_id = "$GATEWAY_ID"

[openshell.gateway.ocsf_log]
path = "$LOGS/gateway-ocsf.jsonl"
rotation = "never"

# Talon registered as operator-run supervisor middleware (TLS, pinned CA,
# gateway-minted extension tokens).
[[openshell.supervisor.middleware]]
name = "talon"
grpc_endpoint = "https://$HOST_IP:$TALON_GRPC_PORT"
tls_ca_cert_path = "$TLS_DIR/talon-cert.pem"
audience = "$AUDIENCE"
max_payload_bytes = 1048576
timeout = "10s"
EOT
"$GW_BIN" config preflight --path "$GW_CFG" >>"$LOGS/setup.log" 2>&1 || die "openshell-gateway config preflight rejected $GW_CFG"
pass "openshell-gateway config preflight accepted the talon registration"
if [[ "$PREFLIGHT_ONLY" == "1" ]]; then
  # Talon's manifest is what the real gateway will see at startup: fetch it
  # the way the gateway does (TLS to the registered endpoint, pinned CA).
  go run ./tests/openshell-live/describe -endpoint "https://$HOST_IP:$TALON_GRPC_PORT" -ca "$TLS_DIR/talon-cert.pem" >>"$LOGS/setup.log" 2>&1 || die "Describe over TLS with the registered CA failed"
  pass "Describe over TLS with the registered CA negotiated protocol 1.0 and returned the HTTP_REQUEST/PRE_CREDENTIALS manifest"
  echo "PREFLIGHT ONLY: artifacts verified, talon started with the middleware listener, gateway registration accepted; the gateway/sandbox stages need Docker"
  exit 0
fi
env -u OPENSHELL_DRIVERS -u OPENSHELL_COMPUTE_DRIVER "$GW_BIN" --compute-driver docker --config "$GW_CFG" --name "$GATEWAY_ID" \
  --bind-address 127.0.0.1 --port "$GW_PORT" --health-port "$GW_HEALTH_PORT" --metrics-port 0 --disable-tls \
  --db-url "sqlite://$WORK/gateway.db" --log-level "${TALON_OPENSHELL_LOG_LEVEL:-info}" >"$LOGS/gateway.log" 2>&1 &
GW_PID=$!
for ((i=0; i<240; i++)); do
  kill -0 "$GW_PID" 2>/dev/null || die "openshell-gateway exited during startup (Describe/negotiation against talon failed?)"
  curl -fsS --max-time 1 "http://127.0.0.1:$GW_HEALTH_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS --max-time 1 "http://127.0.0.1:$GW_HEALTH_PORT/healthz" >/dev/null 2>&1 || die "openshell-gateway not healthy"
pass "gateway v0.1.3 started with talon registered (Describe + protocol negotiation succeeded)"

# ---------------------------------------------------------------- provider profile, provider, policy, sandboxes
cat >"$WORK/profile.yaml" <<EOT
id: talon-live-openai
display_name: Talon live mock provider
description: OpenAI-compatible mock provider used by the Talon live smoke
category: inference
inference_capable: true
credentials:
  - name: api_key
    description: mock provider key (injected by OpenShell, never seen by Talon)
    env_vars: [OPENAI_API_KEY]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: host.openshell.internal
    port: $MOCK_PORT
    protocol: rest
    access: read-write
    enforcement: enforce
binaries: [/usr/bin/curl]
EOT
"${CLI[@]}" profile import -f "$WORK/profile.yaml" --global >>"$LOGS/setup.log" 2>&1 || die "profile import"
"${CLI[@]}" provider create --name mock-openai --type talon-live-openai --global-profile --credential "OPENAI_API_KEY=$PROVIDER_SECRET" >>"$LOGS/setup.log" 2>&1 || die "provider create"
cat >"$WORK/policy.yaml" <<EOT
version: 1
network_middlewares:
  talon-governance:
    middleware: talon
    order: 10
    on_error: fail_closed
    endpoints:
      include: ["host.openshell.internal"]
network_policies:
  mock-openai:
    endpoints:
      - host: host.openshell.internal
        port: $MOCK_PORT
        protocol: rest
        access: read-write
        enforcement: enforce
    binaries:
      - path: /usr/bin/curl
EOT
create_sandbox() { # name
  "${CLI[@]}" sandbox create --name "$1" --policy "$WORK/policy.yaml" --provider mock-openai --no-tty --detach -- sleep infinity >>"$LOGS/setup.log" 2>&1 || die "sandbox create $1"
  SANDBOXES+=("$1")
}
create_sandbox "$SANDBOX_A"
SANDBOX_A_ID="$("${CLI[@]}" sandbox list --ids 2>>"$LOGS/setup.log" | head -n 1)"
[[ -n "$SANDBOX_A_ID" ]] || die "could not read the sandbox id"
log "sandbox $SANDBOX_A id=$SANDBOX_A_ID"
# Bind the REAL sandbox identity to the Talon use case; the binding rides the
# normal agent reload (no restart).
python3 - "$AGENT_FILE" "$AGENT" "$SANDBOX_A_ID" <<'PY' || die "binding edit"
import sys
p, agent, sid = sys.argv[1:]
s = open(p).read()
key = '  key:\n    secret_name: "%s-talon-key"\n' % agent
assert key in s, "scaffold key block"
s = s.replace(key, key + '  workload_identity:\n    bindings:\n      - runtime: openshell\n        subject: "spiffe://openshell/sandbox/%s"\n' % sid, 1)
open(p, "w").write(s)
PY
for ((i=0; i<40; i++)); do
  grep -q "agent_config_reload_activated" "$LOGS/talon-serve.log" && break
  sleep 0.5
done
grep -q "agent_config_reload_activated" "$LOGS/talon-serve.log" || die "talon did not activate the binding generation"

sandbox_request() { # sandbox body -> prints "<http_code>\n<response body>"
  local sb="$1" body="$2"
  "${CLI[@]}" sandbox exec --name "$sb" --no-tty --no-login-shell --timeout 60 --env "TALON_BODY=$body" -- \
    sh -c 'code=$(curl -sS -o /tmp/resp -w "%{http_code}" --max-time 40 -X POST "http://host.openshell.internal:'"$MOCK_PORT"'/v1/chat/completions" -H "Authorization: Bearer $OPENAI_API_KEY" -H "content-type: application/json" --data "$TALON_BODY"); echo "$code"; cat /tmp/resp 2>/dev/null; echo' 2>>"$LOGS/setup.log"
}

# ---------------------------------------------------------------- CASE A — allowed
BODY_A='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello from the sandbox"}]}'
OUT="$(sandbox_request "$SANDBOX_A" "$BODY_A")"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "200" ]] || die "CASE A expected 200 from the provider, got $CODE: $OUT"
grep -q '"chatcmpl-mock-1"' <<<"$OUT" || die "CASE A sandbox did not receive the mock completion: $OUT"
[[ "$(provider_calls)" == "1" ]] || die "CASE A provider calls = $(provider_calls), want 1"
[[ "$(provider_record 0 authorization)" == "Bearer $PROVIDER_SECRET" ]] || die "CASE A provider did not receive the OpenShell-injected credential"
grep -q "hello from the sandbox" <<<"$(provider_record 0 body)" || die "CASE A provider body mismatch"
pass "CASE A allowed: talon decided, provider called once with OpenShell's credential"

# ---------------------------------------------------------------- CASE B — PII transformation
PII_EMAIL="jane.doe@example.com"
BODY_B='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Refund request from '"$PII_EMAIL"' for order 42"}]}'
OUT="$(sandbox_request "$SANDBOX_A" "$BODY_B")"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "200" ]] || die "CASE B expected 200, got $CODE: $OUT"
[[ "$(provider_calls)" == "2" ]] || die "CASE B provider calls = $(provider_calls), want 2"
FORWARDED="$(provider_record 1 body)"
grep -qF "$PII_EMAIL" <<<"$FORWARDED" && die "CASE B provider received the original sensitive value"
grep -q "order 42" <<<"$FORWARDED" || die "CASE B forwarded body is not the transformed request: $FORWARDED"
[[ "$FORWARDED" != "$BODY_B" ]] || die "CASE B body was not transformed"
pass "CASE B PII redacted: provider received Talon's transformed body, never $PII_EMAIL"

# ---------------------------------------------------------------- CASE C — blocked model
OUT="$(sandbox_request "$SANDBOX_A" '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "403" ]] || die "CASE C expected 403 middleware denial, got $CODE: $OUT"
grep -q '"middleware_denied"' <<<"$OUT" || die "CASE C sandbox error is not middleware_denied: $OUT"
grep -q '"model_not_allowed"' <<<"$OUT" || die "CASE C reason_code is not model_not_allowed: $OUT"
[[ "$(provider_calls)" == "2" ]] || die "CASE C provider was called on a Talon DENY"
pass "CASE C blocked model: talon DENY relayed by OpenShell, provider count unchanged"

# ---------------------------------------------------------------- CASE D — unbound sandbox identity
create_sandbox "$SANDBOX_B"
OUT="$(sandbox_request "$SANDBOX_B" "$BODY_A")"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "403" ]] || die "CASE D expected 403, got $CODE: $OUT"
grep -q '"workload_identity_unbound"' <<<"$OUT" || die "CASE D reason_code is not workload_identity_unbound: $OUT"
[[ "$(provider_calls)" == "2" ]] || die "CASE D provider was called for an unbound sandbox"
pass "CASE D unbound sandbox identity: DENY, provider count unchanged"

# ---------------------------------------------------------------- CASE E — talon unavailable → OpenShell fails closed
kill "$TALON_PID"; wait "$TALON_PID" 2>/dev/null || true; TALON_PID=""
OUT="$(sandbox_request "$SANDBOX_A" "$BODY_A")"; CODE="$(head -n1 <<<"$OUT")"
grep -q '"middleware_failed"' <<<"$OUT" || die "CASE E expected middleware_failed from OpenShell, got $CODE: $OUT"
[[ "$(provider_calls)" == "2" ]] || die "CASE E provider was reached while talon was unavailable"
pass "CASE E talon unavailable: OpenShell failed closed (middleware_failed), provider count unchanged"

# ---------------------------------------------------------------- CASE F — talon restart, same registration
start_talon
OUT="$(sandbox_request "$SANDBOX_A" "$BODY_A")"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "200" ]] || die "CASE F expected 200 after talon restart without a gateway restart, got $CODE: $OUT"
[[ "$(provider_calls)" == "3" ]] || die "CASE F provider calls = $(provider_calls), want 3"
pass "CASE F talon restarted: governed again without a gateway restart"

# ---------------------------------------------------------------- evidence and secret hygiene
EXPORT="$WORK/export.json"
( cd "$TALON_HOME" && "$TALON" audit export --format signed-json ) >"$EXPORT" 2>>"$LOGS/setup.log" || die "talon audit export"
# signed-json is an envelope: {"export_metadata":…, "records":[<evidence>…]}.
DELEGATED="$(jq '[.records[] | select(.enforcement.provenance=="delegated_expected" and .enforcement.mechanism=="delegate" and .enforcement.boundary=="external_runtime" and .enforcement.decision_authority=="talon" and .enforcement.decision_returned_via=="openshell_middleware")] | length' "$EXPORT")"
[[ "${DELEGATED:-0}" -ge 3 ]] || die "expected >=3 delegated_expected records, found ${DELEGATED:-0}"
VERIFIED="$(jq '[.records[] | select(.workload_identity.status=="verified" and .workload_identity.runtime=="openshell" and .upstream_auth_mode=="external_runtime")] | length' "$EXPORT")"
[[ "${VERIFIED:-0}" -ge 3 ]] || die "expected >=3 verified openshell identity records with external_runtime auth mode, found ${VERIFIED:-0}"
jq -e '[.records[] | select(.enforcement.provenance=="talon_enforced" and .workload_identity.runtime=="openshell")] | length == 0' "$EXPORT" >/dev/null || die "a delegated decision was labelled talon_enforced"
ALLOW_ID="$(jq -r '[.records[] | select(.enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true)][0].id // empty' "$EXPORT")"
[[ -n "$ALLOW_ID" ]] || die "no allowed delegated record id found"
( cd "$TALON_HOME" && "$TALON" audit verify "$ALLOW_ID" ) >>"$LOGS/setup.log" 2>&1 || die "talon audit verify $ALLOW_ID"
if grep -rqF "$PROVIDER_SECRET" "$TALON_HOME" "$LOGS/talon-serve.log" "$EXPORT" 2>/dev/null; then die "provider secret found in Talon state, evidence or logs"; fi
grep -qF "$TALON_VAULT_DECOY" <<<"$(provider_state)" && die "Talon's vault value reached the provider"
pass "evidence: $DELEGATED delegated_expected records, verified identity, offline verification OK, provider secret absent from Talon"

# ---------------------------------------------------------------- record environment
cat <<EOT
ALL PASS openshell live smoke
  openshell cli:      $("$CLI_BIN" --version)   sha256 ${CLI_SHA[$ARCH]}
  openshell gateway:  $("$GW_BIN" --version)   sha256 ${GW_SHA[$ARCH]}
  talon commit:       $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo untracked)
  driver:             docker $(docker version --format '{{.Server.Version}}') on $(uname -r) ($ARCH)
  images:             $(docker ps -a --format '{{.Image}}' | grep -i openshell | sort -u | tr '\n' ' ')
  host address:       $HOST_IP (talon middleware https://$HOST_IP:$TALON_GRPC_PORT, mock provider :$MOCK_PORT)
  ocsf (gateway):     $LOGS/gateway-ocsf.jsonl ($(wc -l <"$LOGS/gateway-ocsf.jsonl" 2>/dev/null || echo 0) lines)
EOT

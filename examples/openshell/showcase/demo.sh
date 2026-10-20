#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091  # run-dir env files are generated at prepare time
# Talon × NVIDIA OpenShell — the canonical customer showcase runner (#482).
#
# One scenario, three consumers: a standalone evaluation from this repository
# or a published showcase bundle, the talon-full-demo orchestration
# (TALON_SHOWCASE_EMBEDDED=1, its `docs/OPENSHELL_DEMO.md` contract), and the
# real-runtime CI lane (`validate`).
#
#   OpenShell contains the agent. Talon governs what the agent can do for the company.
#
# Commands (exactly these; anything else is a usage error):
#   prepare          idempotently add the OpenShell surface to Talon's configuration
#                    (gateway.openshell, provider, the sandboxed-support use case: identity
#                    binding, tool governance, trusted actions, refund approval rule), the
#                    reviewer credential and the vault entries. `talon openshell prepare`
#                    does the YAML work through Talon's own loaders.
#   start            fetch the pinned OpenShell release (checksums verified), start the mock
#                    provider and the protected business service, [standalone: start Talon],
#                    start the OpenShell gateway with Talon registered over TLS, create and
#                    bind the sandbox, prove the sandbox cannot reach the protected service.
#   status           operator diagnostics; non-zero when a mandatory control is missing.
#   run              run the Go SDK agent INSIDE the sandbox; wait for the reviewer; verify
#                    downstream counts; write <run-dir>/<session>.result.json when concluded.
#   approval-status  read the pending refund approval through Talon's reviewer API.
#   approve | reject decide it through Talon's reviewer API (outside the sandbox).
#   validate         deterministic no-key validation of the whole scenario against the real
#                    runtime in a private run dir (what the CI lane runs).
#   stop             stop only what this showcase started; keep Talon in embedded mode.
#
# Embedded contract (talon-full-demo PR #36): with TALON_SHOWCASE_EMBEDDED=1 the runner
# consumes TALON_SHOWCASE_CONFIG_DIR, TALON_SHOWCASE_TALON_DATA_DIR, TALON_SHOWCASE_TALON_URL,
# TALON_SHOWCASE_TALON_BIN, TALON_SHOWCASE_RUN_DIR, TALON_SHOWCASE_AGENT,
# TALON_SHOWCASE_PROVIDER_MODE, TALON_SHOWCASE_SESSION, TALON_SHOWCASE_OPERATION_PREFIX,
# TALON_SHOWCASE_RUN_START, and never starts another Talon, another evidence/session
# database or another signing key: it overlays the SAME generated config and agent
# directory the other demo cases use and attaches to the running Talon.
#
# Optional:
#   OPENSHELL_VERSION                  pinned release to use (default v0.1.3, the validated baseline)
#   TALON_SHOWCASE_AGENT_IMAGE         sandbox image carrying /usr/local/bin/support-agent
#                                      (default: built locally from examples/openshell/agent in a
#                                      checkout; a published ghcr.io/dativo-io/talon-openshell-agent@sha256:… otherwise)
#   TALON_SHOWCASE_RELEASE_MANIFEST    showcase bundle manifest; every binary the runner uses must
#                                      match its sha256 (customer path; refused on mismatch)
#   TALON_SHOWCASE_HOST                non-loopback IPv4 of this host reachable from containers
#   TALON_SHOWCASE_APPROVAL_WAIT_S     how long `run` waits for the reviewer (default 600)
#   TALON_SHOWCASE_KEEP=1              keep logs/state after `stop` (never secrets)
#   TALON_SHOWCASE_DEBUG=1             verbose tracing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/openshell-release.sh
source "$SCRIPT_DIR/lib/openshell-release.sh"
[[ "${TALON_SHOWCASE_DEBUG:-0}" == "1" ]] && set -x

COMMAND="${1:-}"
usage() {
  sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}
case "$COMMAND" in
  prepare|start|status|run|approval-status|approve|reject|validate|stop) ;;
  *) echo "ERROR: unknown command '${COMMAND}'" >&2; usage ;;
esac
[[ $# -le 1 ]] || { echo "ERROR: $COMMAND takes no arguments" >&2; usage; }

log()  { printf 'INFO %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*" >&2; }
die()  { printf 'FAIL %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing $1: $2"; }

# ---------------------------------------------------------------- mode and paths
EMBEDDED="${TALON_SHOWCASE_EMBEDDED:-0}"
if [[ "$EMBEDDED" == "1" ]]; then
  for v in TALON_SHOWCASE_CONFIG_DIR TALON_SHOWCASE_TALON_DATA_DIR TALON_SHOWCASE_TALON_URL TALON_SHOWCASE_RUN_DIR; do
    [[ -n "${!v:-}" ]] || die "embedded mode requires $v (see talon-full-demo docs/OPENSHELL_DEMO.md)"
  done
  CONFIG_DIR="$TALON_SHOWCASE_CONFIG_DIR"
  DATA_DIR="$TALON_SHOWCASE_TALON_DATA_DIR"
  TALON_URL="${TALON_SHOWCASE_TALON_URL%/}"
  RUN_DIR="$TALON_SHOWCASE_RUN_DIR"
else
  RUN_DIR="${TALON_SHOWCASE_RUN_DIR:-$PWD/.talon-openshell-showcase}"
  CONFIG_DIR="${TALON_SHOWCASE_CONFIG_DIR:-$RUN_DIR/config}"
  DATA_DIR="${TALON_SHOWCASE_TALON_DATA_DIR:-$RUN_DIR/talon-data}"
  TALON_URL="${TALON_SHOWCASE_TALON_URL:-}"   # set by start in standalone mode
fi
AGENT="${TALON_SHOWCASE_AGENT:-sandboxed-support}"
PROVIDER_MODE="${TALON_SHOWCASE_PROVIDER_MODE:-mock}"
[[ "$PROVIDER_MODE" == mock || "$PROVIDER_MODE" == real ]] || die "TALON_SHOWCASE_PROVIDER_MODE must be mock or real"
TENANT="${TALON_SHOWCASE_TENANT:-default}"
OPENSHELL_VERSION="${OPENSHELL_VERSION:-$OPENSHELL_BASELINE_VERSION}"
AUDIENCE="urn:openshell:extension:middleware:talon"
STATE="$RUN_DIR/showcase.env"
LOGS="$RUN_DIR/logs"; PIDS="$RUN_DIR/pids"; TLS_DIR="$RUN_DIR/tls"; JWT_DIR="$RUN_DIR/jwt"; BIN="$RUN_DIR/bin"
mkdir -p "$RUN_DIR" "$LOGS" "$PIDS"
chmod 0700 "$RUN_DIR"
CONFIG="$CONFIG_DIR/talon.config.yaml"
# A source checkout is the development path; the customer path has no checkout.
REPO_ROOT=""
if [[ -f "$SCRIPT_DIR/../../../go.mod" ]] && grep -q 'module github.com/dativo-io/talon' "$SCRIPT_DIR/../../../go.mod" 2>/dev/null; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
fi
# Persisted state (ports, ids, paths) so every phase sees the same world.
load_state() { [[ -f "$STATE" ]] && source "$STATE"; return 0; }
save_state() { # key value
  mkdir -p "$(dirname "$STATE")"
  { [[ -f "$STATE" ]] && grep -v "^export $1=" "$STATE"; printf 'export %s=%q\n' "$1" "$2"; } >"$STATE.tmp" || true
  chmod 0600 "$STATE.tmp"; mv "$STATE.tmp" "$STATE"
  export "$1=$2"
}
load_state

# ---------------------------------------------------------------- talon binary and release manifest
MANIFEST="${TALON_SHOWCASE_RELEASE_MANIFEST:-}"
verify_against_manifest() { # name path -> the file's sha256 must equal the manifest's entry
  [[ -n "$MANIFEST" ]] || return 0
  [[ -s "$MANIFEST" ]] || die "release manifest $MANIFEST is missing or empty"
  local want got
  want="$(jq -r --arg n "$1" '.artifacts[$n].sha256 // empty' "$MANIFEST")"
  [[ -n "$want" ]] || die "release manifest $MANIFEST has no entry for $1"
  got="$(sha256sum "$2" | cut -d' ' -f1)"
  [[ "$want" == "$got" ]] || die "$1 does not match the release manifest (want $want, got $got): refusing an unverified binary"
}
resolve_talon() {
  if [[ -n "${TALON_SHOWCASE_TALON_BIN:-}" ]]; then TALON="$TALON_SHOWCASE_TALON_BIN"
  elif [[ -n "${TALON_BIN_RESOLVED:-}" && -x "${TALON_BIN_RESOLVED:-}" ]]; then TALON="$TALON_BIN_RESOLVED"
  elif command -v talon >/dev/null 2>&1; then TALON="$(command -v talon)"
  elif [[ -n "$REPO_ROOT" ]] && command -v go >/dev/null 2>&1; then
    mkdir -p "$BIN"; log "building talon from $REPO_ROOT (development path)"
    (cd "$REPO_ROOT" && go build -o "$BIN/talon" ./cmd/talon) >>"$LOGS/setup.log" 2>&1 || die "go build talon (see $LOGS/setup.log)"
    TALON="$BIN/talon"
  else
    die "no talon binary: set TALON_SHOWCASE_TALON_BIN, put talon on PATH, or run from a checkout with Go"
  fi
  [[ -x "$TALON" ]] || die "talon binary not executable: $TALON"
  verify_against_manifest talon "$TALON"
  "$TALON" openshell prepare --help >/dev/null 2>&1 || die "this talon ($("$TALON" version 2>/dev/null | head -n1)) predates the OpenShell showcase (no 'talon openshell prepare'); use a release that includes it"
  "$TALON" audit list --help 2>&1 | grep -Fq -- '--runtime-ref' || die "this talon predates OpenShell runtime evidence support"
  save_state TALON_BIN_RESOLVED "$TALON"
}
talon_cli() { # runs the talon CLI against the showcase's (or the shared) data dir
  TALON_DATA_DIR="$DATA_DIR" "$TALON" "$@"
}

# helper binaries: mock provider, protected service, describe probe
resolve_helper() { # name relpath -> sets HELPER_<NAME>
  local name="$1" rel="$2" var="HELPER_${1^^}" path=""
  if [[ -n "${TALON_SHOWCASE_BUNDLE_DIR:-}" && -x "$TALON_SHOWCASE_BUNDLE_DIR/bin/$name" ]]; then path="$TALON_SHOWCASE_BUNDLE_DIR/bin/$name"
  elif [[ -x "$SCRIPT_DIR/bin/$name" ]]; then path="$SCRIPT_DIR/bin/$name"
  elif [[ -n "$REPO_ROOT" ]] && command -v go >/dev/null 2>&1; then
    mkdir -p "$BIN"
    (cd "$REPO_ROOT" && go build -o "$BIN/$name" "$rel") >>"$LOGS/setup.log" 2>&1 || die "go build $name (see $LOGS/setup.log)"
    path="$BIN/$name"
  else
    die "no $name binary: run from a checkout with Go, or from a showcase bundle (TALON_SHOWCASE_BUNDLE_DIR)"
  fi
  verify_against_manifest "$name" "$path"
  printf -v "$var" '%s' "$path"
}

# ---------------------------------------------------------------- host, ports
detect_host() {
  if [[ -n "${TALON_SHOWCASE_HOST:-}" ]]; then printf '%s\n' "$TALON_SHOWCASE_HOST"; return; fi
  local a
  a="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [[ -n "$a" ]] || a="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./ && $i !~ /:/){print $i; exit}}')"
  [[ -n "$a" ]] || die "no non-loopback IPv4 found; set TALON_SHOWCASE_HOST"
  printf '%s\n' "$a"
}
free_port() { python3 - <<'PY' 2>/dev/null || awk 'BEGIN{srand(); print 20000+int(rand()*20000)}'
import socket
s=socket.socket(); s.bind(("0.0.0.0",0)); print(s.getsockname()[1]); s.close()
PY
}
ensure_port() { # var -> allocate once, persist
  local var="$1"
  [[ -n "${!var:-}" ]] || save_state "$var" "$(free_port)"
}
wait_http() { local i; for ((i=0; i<"$2"*4; i++)); do curl -fsS --max-time 1 "$1" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
listening() { curl -fsS --max-time 1 "$1" >/dev/null 2>&1; }

# pid-file helpers: never adopt an unrelated process on the same port.
pid_alive() { [[ -f "$PIDS/$1.pid" ]] && kill -0 "$(cat "$PIDS/$1.pid")" 2>/dev/null; }
start_bg() { # name logname cmd...
  local name="$1"; shift
  if pid_alive "$name"; then log "$name already running (pid $(cat "$PIDS/$name.pid"))"; return 0; fi
  "$@" >>"$LOGS/$name.log" 2>&1 &
  echo $! >"$PIDS/$name.pid"
}
stop_bg() { # name
  if [[ -f "$PIDS/$1.pid" ]]; then
    local pid; pid="$(cat "$PIDS/$1.pid")"
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.3; done; kill -9 "$pid" 2>/dev/null || true; fi
    rm -f "$PIDS/$1.pid"
  fi
}
own_or_free() { # name url  — the port must be free or served by OUR process
  if listening "$2"; then pid_alive "$1" || die "$2 is answering but not from a process this showcase started (stale or foreign $1); stop it or choose another port"; fi
}

# ---------------------------------------------------------------- prepare
cmd_prepare() {
  for c in openssl curl jq; do need "$c" "required by the showcase"; done
  resolve_talon
  ensure_port SHOWCASE_TALON_GRPC_PORT
  ensure_port SHOWCASE_MOCK_PORT
  ensure_port SHOWCASE_PROTECTED_PORT
  ensure_port SHOWCASE_GW_PORT
  ensure_port SHOWCASE_GW_HEALTH_PORT
  if [[ "$EMBEDDED" == "1" ]]; then
    [[ -f "$CONFIG" ]] || die "embedded mode: $CONFIG does not exist (bootstrap the Full Demo configuration first)"
    SHOWCASE_TALON_HTTP_PORT="${TALON_URL##*:}"; SHOWCASE_TALON_HTTP_PORT="${SHOWCASE_TALON_HTTP_PORT%%/*}"
    [[ "$SHOWCASE_TALON_HTTP_PORT" =~ ^[0-9]+$ ]] || die "cannot derive the shared Talon port from TALON_SHOWCASE_TALON_URL=$TALON_URL"
    save_state SHOWCASE_TALON_HTTP_PORT "$SHOWCASE_TALON_HTTP_PORT"
  else
    ensure_port SHOWCASE_TALON_HTTP_PORT
    mkdir -p "$CONFIG_DIR" "$DATA_DIR"; chmod 0700 "$DATA_DIR"
    if [[ ! -f "$CONFIG" ]]; then
      # Standalone: a minimal operator config of our own (an existing one is
      # never replaced). Org policy: redact PII both ways, block gpt-4o.
      cat >"$CONFIG" <<EOT
# Talon operator configuration for the OpenShell showcase (standalone mode).
agents_dir: agents
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  organization_policy:
    defaults:
      pii_action: "redact"
      daily_cost: 100.00
    constraints:
      blocked_models: ["gpt-4o"]
EOT
      chmod 0600 "$CONFIG"
    fi
    # Our own Talon's keys (standalone mode): whichever of the three is not
    # already in the environment is generated once and kept in talon.env.
    [[ ! -f "$RUN_DIR/talon.env" ]] || source "$RUN_DIR/talon.env"
    local kv
    for kv in "TALON_SECRETS_KEY:$(openssl rand -hex 16)" "TALON_SIGNING_KEY:$(openssl rand -hex 24)" "TALON_ADMIN_KEY:admin-$(openssl rand -hex 8)"; do
      local k="${kv%%:*}" v="${kv#*:}"
      [[ -n "${!k:-}" ]] && continue
      ( umask 077; printf 'export %s=%q\n' "$k" "$v" >>"$RUN_DIR/talon.env" )
      export "$k=$v"
    done
    chmod 0600 "$RUN_DIR/talon.env" 2>/dev/null || true
  fi
  [[ -n "${TALON_SECRETS_KEY:-}" ]] || die "TALON_SECRETS_KEY is required: the shared Talon key in embedded mode"
  export TALON_SECRETS_KEY
  HOST_IP="$(detect_host)"; save_state SHOWCASE_HOST_IP "$HOST_IP"

  # OpenShell gateway signing key + JWKS for Talon (the gateway's public key is
  # what Talon trusts; an operator would fetch <gateway>/.well-known/jwks.json).
  mkdir -p "$JWT_DIR" "$TLS_DIR"; chmod 0700 "$JWT_DIR" "$TLS_DIR"
  if [[ ! -f "$JWT_DIR/signing.pem" ]]; then
    openssl genpkey -algorithm ed25519 -out "$JWT_DIR/signing.pem" 2>>"$LOGS/setup.log"
    openssl pkey -in "$JWT_DIR/signing.pem" -pubout -out "$JWT_DIR/public.pem" 2>>"$LOGS/setup.log"
    printf '%s\n' "showcase-$(openssl rand -hex 4)-k1" >"$JWT_DIR/kid"
    PUB_X="$(openssl pkey -pubin -in "$JWT_DIR/public.pem" -outform DER | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
    printf '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"%s","x":"%s"}]}\n' "$(cat "$JWT_DIR/kid")" "$PUB_X" >"$RUN_DIR/openshell-jwks.json"
  fi
  [[ -n "${SHOWCASE_GATEWAY_ID:-}" ]] || save_state SHOWCASE_GATEWAY_ID "talon-showcase-$(openssl rand -hex 3)"
  # Talon's middleware TLS identity from a private showcase CA (OpenShell
  # verifies the dialed SAN against tls_ca_cert_path; a self-signed leaf is
  # not a trust anchor). Regenerated when the host address changes.
  if [[ ! -f "$TLS_DIR/talon-cert.pem" ]] || ! openssl x509 -in "$TLS_DIR/talon-cert.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address:$HOST_IP"; then
    cat >"$TLS_DIR/ca.cnf" <<'EOT'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = talon-openshell-showcase CA (local only)
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOT
    cat >"$TLS_DIR/server.cnf" <<EOT
[req]
distinguished_name = dn
prompt = no
[dn]
CN = talon-openshell-middleware
[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:$HOST_IP, DNS:host.openshell.internal
authorityKeyIdentifier = keyid
EOT
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -config "$TLS_DIR/ca.cnf" -keyout "$TLS_DIR/ca-key.pem" -out "$TLS_DIR/ca.pem" >>"$LOGS/setup.log" 2>&1 || die "openssl CA"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -config "$TLS_DIR/server.cnf" -keyout "$TLS_DIR/talon-key.pem" -out "$TLS_DIR/talon.csr" >>"$LOGS/setup.log" 2>&1 || die "openssl CSR"
    openssl x509 -req -in "$TLS_DIR/talon.csr" -CA "$TLS_DIR/ca.pem" -CAkey "$TLS_DIR/ca-key.pem" -CAcreateserial -days 30 -extfile "$TLS_DIR/server.cnf" -extensions v3_server -out "$TLS_DIR/talon-cert.pem" >>"$LOGS/setup.log" 2>&1 || die "openssl sign"
    openssl verify -CAfile "$TLS_DIR/ca.pem" "$TLS_DIR/talon-cert.pem" >>"$LOGS/setup.log" 2>&1 || die "certificate does not chain to the showcase CA"
    chmod 0600 "$TLS_DIR"/*.pem
    log "tls: new middleware identity for $HOST_IP (CA $(openssl x509 -in "$TLS_DIR/ca.pem" -noout -fingerprint -sha256 | cut -d= -f2))"
  fi

  # The configuration overlay, through Talon's own loaders. In mock mode the
  # sandbox dials the mock provider on this host; in real mode the existing
  # provider entries of the configuration map the real host.
  local provider_args=()
  if [[ "$PROVIDER_MODE" == mock ]]; then
    provider_args=(--provider-name openshell-mock --provider-base-url "http://host.openshell.internal:$SHOWCASE_MOCK_PORT" --provider-secret-name openshell-mock-provider-key)
  fi
  local subject_args=()
  [[ -z "${SHOWCASE_SANDBOX_ID:-}" ]] || subject_args=(--sandbox-subject "spiffe://openshell/sandbox/$SHOWCASE_SANDBOX_ID")
  "$TALON" openshell prepare --config "$CONFIG" --agent "$AGENT" --tenant "$TENANT" \
    --listen "$HOST_IP:$SHOWCASE_TALON_GRPC_PORT" --tls-cert "$TLS_DIR/talon-cert.pem" --tls-key "$TLS_DIR/talon-key.pem" \
    --issuer "openshell-gateway:$SHOWCASE_GATEWAY_ID" --audience "$AUDIENCE" --jwks-file "$RUN_DIR/openshell-jwks.json" \
    --self-host "host.openshell.internal:$SHOWCASE_TALON_HTTP_PORT" \
    --protected-base-url "http://127.0.0.1:$SHOWCASE_PROTECTED_PORT" --max-capture-bytes 262144 --settlement-timeout 60s \
    --summary "$RUN_DIR/prepare.json" "${provider_args[@]}" "${subject_args[@]}" >>"$LOGS/setup.log" 2>&1 || die "talon openshell prepare (see $LOGS/setup.log)"
  local restart agent_file
  restart="$(jq -r '.restart_required' "$RUN_DIR/prepare.json")"; agent_file="$(jq -r '.agent_file' "$RUN_DIR/prepare.json")"
  save_state SHOWCASE_AGENT_FILE "$agent_file"
  # Vault entries (encrypted at rest in the shared vault; values are placeholders
  # on the delegated path) and the reviewer credential (host-side only).
  talon_cli secrets set "$AGENT-talon-key" "talon-gw-openshell-$(openssl rand -hex 6)" >>"$LOGS/setup.log" 2>&1 || die "talon secrets set (agent key)"
  if [[ "$PROVIDER_MODE" == mock ]]; then
    talon_cli secrets set openshell-mock-provider-key "sk-talon-vault-value-never-used-on-delegated-path" >>"$LOGS/setup.log" 2>&1 || die "talon secrets set (mock provider)"
  fi
  if [[ ! -s "$RUN_DIR/reviewer.key" ]]; then
    local key
    key="$(talon_cli approver add --name "openshell-lead-$(openssl rand -hex 2)" --tenant "$TENANT" --groups support-leads 2>>"$LOGS/setup.log" | grep -oE 'talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+' | head -n1)"
    [[ -n "$key" ]] || die "talon approver add printed no credential (see $LOGS/setup.log)"
    ( umask 077; printf '%s\n' "$key" >"$RUN_DIR/reviewer.key" )
  fi
  pass "prepare: $CONFIG carries gateway.openshell (listener $HOST_IP:$SHOWCASE_TALON_GRPC_PORT, self destination host.openshell.internal:$SHOWCASE_TALON_HTTP_PORT); use case $AGENT in $agent_file; reviewer credential in $RUN_DIR/reviewer.key"
  if [[ "$restart" == "true" ]]; then
    if [[ "$EMBEDDED" == "1" ]]; then
      echo "NOTE gateway.openshell changed: the shared Talon must be (re)started before 'start' (the Full Demo's real-start does this; gateway.openshell is read at startup)."
    else
      echo "NOTE gateway.openshell changed: 'start' starts Talon with it (standalone mode)."
    fi
  fi
}

# ---------------------------------------------------------------- start
agent_image() {
  if [[ -n "${TALON_SHOWCASE_AGENT_IMAGE:-}" ]]; then printf '%s\n' "$TALON_SHOWCASE_AGENT_IMAGE"; return; fi
  if [[ -n "$MANIFEST" ]]; then
    local img; img="$(jq -r '.agent_image // empty' "$MANIFEST")"
    [[ -n "$img" ]] || die "release manifest has no agent_image"
    printf '%s\n' "$img"; return
  fi
  [[ -n "$REPO_ROOT" ]] || die "no agent image: set TALON_SHOWCASE_AGENT_IMAGE to a published ghcr.io/dativo-io/talon-openshell-agent@sha256:… image"
  local short tag
  short="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)"
  tag="talon-openshell-agent:local-$short"
  if ! docker image inspect "$tag" >/dev/null 2>&1; then
    log "building the sandbox agent image $tag (development path)"
    docker build -q -t "$tag" --build-arg "VERSION=local" --build-arg "COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)" "$REPO_ROOT/examples/openshell/agent" >>"$LOGS/setup.log" 2>&1 || die "docker build of the agent image (see $LOGS/setup.log)"
  fi
  printf '%s\n' "$tag"
}
openshell_cli() { env -u OPENSHELL_SANDBOX_POLICY "$BIN/openshell" --gateway-endpoint "http://127.0.0.1:$SHOWCASE_GW_PORT" "$@"; }

cmd_start() {
  [[ -f "$STATE" && -f "$RUN_DIR/prepare.json" ]] || die "run 'prepare' first"
  for c in docker curl jq openssl; do need "$c" "required by start"; done
  [[ "$(uname -s)" == Linux ]] || die "the OpenShell docker driver runs Linux sandboxes"
  docker info >/dev/null 2>&1 || die "Docker Engine is not reachable by $(id -un)"
  resolve_talon
  resolve_helper mockprovider ./tests/openshell-live/mockprovider
  resolve_helper protectedservice ./tests/openshell-live/protectedservice
  resolve_helper describe ./tests/openshell-live/describe
  [[ -z "${TALON_SECRETS_KEY:-}" && -f "$RUN_DIR/talon.env" ]] && source "$RUN_DIR/talon.env"
  HOST_IP="$SHOWCASE_HOST_IP"
  mkdir -p "$BIN"
  openshell_release_fetch "$OPENSHELL_VERSION" "$BIN" "${TALON_SHOWCASE_CACHE:-$HOME/.cache/talon-openshell}/$OPENSHELL_VERSION" || die "OpenShell $OPENSHELL_VERSION release artifacts"
  save_state SHOWCASE_OPENSHELL_VERSION "$OPENSHELL_VERSION"
  log "openshell $OPENSHELL_VERSION verified (cli sha256 $OPENSHELL_CLI_SHA, gateway sha256 $OPENSHELL_GW_SHA)"

  # Mock business systems (every interface: sandboxes reach the host as
  # host.openshell.internal) and the protected service.
  own_or_free mockprovider "http://127.0.0.1:$SHOWCASE_MOCK_PORT/__state"
  own_or_free protectedservice "http://127.0.0.1:$SHOWCASE_PROTECTED_PORT/__state"
  [[ "$PROVIDER_MODE" != mock ]] || start_bg mockprovider "$HELPER_MOCKPROVIDER" -listen "0.0.0.0:$SHOWCASE_MOCK_PORT" -state-file "$RUN_DIR/provider-state.json"
  start_bg protectedservice "$HELPER_PROTECTEDSERVICE" -listen "0.0.0.0:$SHOWCASE_PROTECTED_PORT" -state-file "$RUN_DIR/protected-state.json"
  [[ "$PROVIDER_MODE" != mock ]] || wait_http "http://127.0.0.1:$SHOWCASE_MOCK_PORT/__state" 10 || die "mock provider did not start"
  wait_http "http://127.0.0.1:$SHOWCASE_PROTECTED_PORT/__state" 10 || die "protected service did not start"

  # Talon: shared in embedded mode (never started here), ours otherwise.
  if [[ "$EMBEDDED" == "1" ]]; then
    curl -fsS --max-time 3 "$TALON_URL/health" >/dev/null || die "shared Talon is not healthy at $TALON_URL"
  else
    TALON_URL="http://127.0.0.1:$SHOWCASE_TALON_HTTP_PORT"; save_state SHOWCASE_TALON_URL "$TALON_URL"
    own_or_free talon "$TALON_URL/health"
    # Run from the config directory: agents_dir in talon.config.yaml is
    # relative to where talon serve runs.
    start_bg talon sh -c "cd '$CONFIG_DIR' && exec env TALON_DATA_DIR='$DATA_DIR' TALON_AGENTS_RELOAD_INTERVAL=1s '$TALON' serve --port '$SHOWCASE_TALON_HTTP_PORT' --gateway --gateway-config '$(basename "$CONFIG")'"
    wait_http "$TALON_URL/health" 30 || die "talon serve did not become healthy (see $LOGS/talon.log)"
  fi
  local i; for ((i=0; i<40; i++)); do (exec 3<>"/dev/tcp/$HOST_IP/$SHOWCASE_TALON_GRPC_PORT") 2>/dev/null && break; sleep 0.25; done
  (exec 3<>"/dev/tcp/$HOST_IP/$SHOWCASE_TALON_GRPC_PORT") 2>/dev/null || die "Talon's OpenShell middleware listener is not reachable at $HOST_IP:$SHOWCASE_TALON_GRPC_PORT (was Talon restarted after prepare? gateway.openshell is read at startup)"
  "$HELPER_DESCRIBE" -endpoint "https://$HOST_IP:$SHOWCASE_TALON_GRPC_PORT" -ca "$TLS_DIR/ca.pem" -expect-response >>"$LOGS/setup.log" 2>&1 || die "Talon's middleware did not answer Describe over TLS with the showcase CA (see $LOGS/setup.log)"
  pass "talon middleware: TLS trust and manifest (request + response bindings) verified at $HOST_IP:$SHOWCASE_TALON_GRPC_PORT"

  # OpenShell gateway with Talon registered (TLS, pinned CA, gateway-minted tokens).
  cat >"$RUN_DIR/gateway.toml" <<EOT
[openshell]
version = 2

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$JWT_DIR/signing.pem"
public_key_path = "$JWT_DIR/public.pem"
kid_path = "$JWT_DIR/kid"
gateway_id = "$SHOWCASE_GATEWAY_ID"

[openshell.gateway.ocsf_log]
path = "$LOGS/gateway-ocsf.jsonl"
rotation = "never"

[[openshell.supervisor.middleware]]
name = "talon"
grpc_endpoint = "https://$HOST_IP:$SHOWCASE_TALON_GRPC_PORT"
tls_ca_cert_path = "$TLS_DIR/ca.pem"
audience = "$AUDIENCE"
max_payload_bytes = 1048576
timeout = "10s"
EOT
  chmod 0600 "$RUN_DIR/gateway.toml"
  "$BIN/openshell-gateway" config preflight --path "$RUN_DIR/gateway.toml" >>"$LOGS/setup.log" 2>&1 || die "openshell-gateway config preflight rejected the registration (see $LOGS/setup.log)"
  own_or_free gateway "http://127.0.0.1:$SHOWCASE_GW_HEALTH_PORT/healthz"
  start_bg gateway env -u OPENSHELL_DRIVERS -u OPENSHELL_COMPUTE_DRIVER "$BIN/openshell-gateway" --compute-driver docker --config "$RUN_DIR/gateway.toml" --name "$SHOWCASE_GATEWAY_ID" \
    --bind-address 127.0.0.1 --port "$SHOWCASE_GW_PORT" --health-port "$SHOWCASE_GW_HEALTH_PORT" --metrics-port 0 --disable-tls --db-url "sqlite://$RUN_DIR/gateway.db" --log-level info
  for ((i=0; i<240; i++)); do
    pid_alive gateway || die "openshell-gateway exited during startup (see $LOGS/gateway.log)"
    listening "http://127.0.0.1:$SHOWCASE_GW_HEALTH_PORT/healthz" && break
    sleep 0.5
  done
  listening "http://127.0.0.1:$SHOWCASE_GW_HEALTH_PORT/healthz" || die "openshell-gateway not healthy (see $LOGS/gateway.log)"
  pass "openshell-gateway $OPENSHELL_VERSION started with talon registered"

  # Provider profile + provider (credential lives in OpenShell only), sandbox
  # policy (provider host and Talon's host admitted through the talon
  # middleware fail-closed; the protected service deliberately absent).
  local provider_host provider_port provider_cred
  if [[ "$PROVIDER_MODE" == mock ]]; then
    provider_host="host.openshell.internal"; provider_port="$SHOWCASE_MOCK_PORT"
    [[ -n "${SHOWCASE_PROVIDER_SECRET:-}" ]] || save_state SHOWCASE_PROVIDER_SECRET "sk-openshell-injected-$(openssl rand -hex 8)"
    provider_cred="$SHOWCASE_PROVIDER_SECRET"
  else
    provider_host="api.openai.com"; provider_port=443
    [[ -n "${OPENAI_API_KEY:-}" ]] || die "real provider mode needs OPENAI_API_KEY for OpenShell credential injection; Talon never sees it"
    provider_cred="$OPENAI_API_KEY"
  fi
  cat >"$RUN_DIR/profile.yaml" <<EOT
id: talon-showcase-openai
display_name: Talon showcase provider
category: inference
inference_capable: true
credentials:
  - name: api_key
    description: provider key injected by OpenShell after Talon's decision
    env_vars: [OPENAI_API_KEY]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: $provider_host
    port: $provider_port
    protocol: rest
    access: read-write
    enforcement: enforce
binaries: [/usr/local/bin/support-agent]
EOT
  openshell_cli profile import -f "$RUN_DIR/profile.yaml" --global >>"$LOGS/setup.log" 2>&1 || die "openshell profile import"
  if [[ "${SHOWCASE_PROVIDER_CREATED:-}" != "$SHOWCASE_GATEWAY_ID" ]]; then
    openshell_cli provider create --name showcase-openai --type talon-showcase-openai --global-profile --credential "OPENAI_API_KEY=$provider_cred" >>"$LOGS/setup.log" 2>&1 || die "openshell provider create"
    save_state SHOWCASE_PROVIDER_CREATED "$SHOWCASE_GATEWAY_ID"
  fi
  cat >"$RUN_DIR/policy.yaml" <<EOT
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/bin]
network_middlewares:
  talon-governance:
    middleware: talon
    order: 10
    on_error: fail_closed
    endpoints:
      include: ["host.openshell.internal", "$provider_host"]
network_policies:
  model-provider:
    endpoints:
      - host: $provider_host
        port: $provider_port
        protocol: rest
        access: read-write
        enforcement: enforce
    binaries:
      - path: /usr/local/bin/support-agent
  # Talon's own Action Gateway through the same talon middleware; the
  # protected business service's port is deliberately NOT admitted.
  talon-action-gateway:
    endpoints:
      - host: host.openshell.internal
        port: $SHOWCASE_TALON_HTTP_PORT
        protocol: rest
        access: read-write
        enforcement: enforce
    binaries:
      - path: /usr/local/bin/support-agent
EOT
  local image sandbox
  image="$(agent_image)"; save_state SHOWCASE_AGENT_IMAGE "$image"
  sandbox="${SHOWCASE_SANDBOX_NAME:-sc-$(openssl rand -hex 4)}"
  if ! openshell_cli sandbox list 2>>"$LOGS/setup.log" | grep -q "$sandbox"; then
    openshell_cli sandbox create --name "$sandbox" --from "$image" --policy "$RUN_DIR/policy.yaml" --provider showcase-openai --no-tty --detach -- /bin/sleep 2147483647 >>"$LOGS/setup.log" 2>&1 || die "openshell sandbox create from $image (see $LOGS/setup.log)"
  fi
  save_state SHOWCASE_SANDBOX_NAME "$sandbox"
  local sid; sid="$(openshell_cli sandbox list --ids 2>>"$LOGS/setup.log" | head -n1)"
  [[ -n "$sid" ]] || die "could not read the sandbox id"
  save_state SHOWCASE_SANDBOX_ID "$sid"
  # Bind the REAL sandbox identity to the use case (agent reload, no restart).
  local bind_provider=()
  [[ "$PROVIDER_MODE" != mock ]] || bind_provider=(--provider-name openshell-mock --provider-base-url "http://host.openshell.internal:$SHOWCASE_MOCK_PORT" --provider-secret-name openshell-mock-provider-key)
  "$TALON" openshell prepare --config "$CONFIG" --agent "$AGENT" --tenant "$TENANT" \
    --listen "$HOST_IP:$SHOWCASE_TALON_GRPC_PORT" --tls-cert "$TLS_DIR/talon-cert.pem" --tls-key "$TLS_DIR/talon-key.pem" \
    --issuer "openshell-gateway:$SHOWCASE_GATEWAY_ID" --audience "$AUDIENCE" --jwks-file "$RUN_DIR/openshell-jwks.json" \
    --self-host "host.openshell.internal:$SHOWCASE_TALON_HTTP_PORT" --protected-base-url "http://127.0.0.1:$SHOWCASE_PROTECTED_PORT" \
    --max-capture-bytes 262144 --settlement-timeout 60s --sandbox-subject "spiffe://openshell/sandbox/$sid" \
    "${bind_provider[@]}" --summary "$RUN_DIR/prepare.json" >>"$LOGS/setup.log" 2>&1 || die "binding the sandbox identity (see $LOGS/setup.log)"
  [[ "$(jq -r '.restart_required' "$RUN_DIR/prepare.json")" == "false" ]] || die "binding the sandbox changed gateway.openshell — that must not happen after start"
  sleep 2  # agent reload cadence (standalone: 1s; shared Talon: its own interval)
  # Reachability proof from INSIDE the sandbox: Talon's host answers, the
  # protected service does not (OpenShell's network policy, not Talon).
  local probe
  probe="$(openshell_cli sandbox exec --name "$sandbox" --no-tty --no-login-shell --timeout 60 -- /usr/local/bin/support-agent probe "http://host.openshell.internal:$SHOWCASE_TALON_HTTP_PORT/health" "http://host.openshell.internal:$SHOWCASE_PROTECTED_PORT/tickets" 2>>"$LOGS/setup.log" || true)"
  printf '%s\n' "$probe" >>"$LOGS/setup.log"
  grep -q "$SHOWCASE_TALON_HTTP_PORT/health REACHABLE=yes" <<<"$probe" || die "the sandbox cannot reach Talon's Action Gateway through OpenShell: $probe"
  grep -q "$SHOWCASE_PROTECTED_PORT/tickets REACHABLE=no" <<<"$probe" || die "the sandbox CAN reach the protected service directly; the network policy is wrong: $probe"
  pass "sandbox $sandbox ($sid) from $image: bound to $AGENT; Talon reachable through OpenShell; protected service unreachable (OpenShell network policy)"
  echo "started: run 'status', then 'run' (two shells: 'approval-status' / 'approve' | 'reject')"
}

# ---------------------------------------------------------------- status
cmd_status() {
  local rc=0
  check() { # ok? label detail
    if [[ "$1" == 0 ]]; then printf '  [pass] %-28s %s\n' "$2" "$3"; else printf '  [FAIL] %-28s %s\n' "$2" "$3"; rc=1; fi
  }
  resolve_talon
  [[ -z "${TALON_SECRETS_KEY:-}" && -f "$RUN_DIR/talon.env" ]] && source "$RUN_DIR/talon.env"
  echo "OpenShell showcase status ($( [[ "$EMBEDDED" == 1 ]] && echo embedded || echo standalone ), provider mode $PROVIDER_MODE)"
  check 0 "talon" "$("$TALON" version 2>/dev/null | head -n1) at $TALON (openshell prepare, audit --runtime-ref present)"
  local url="${TALON_URL:-${SHOWCASE_TALON_URL:-}}"
  if [[ -n "$url" ]] && curl -fsS --max-time 3 "$url/health" >/dev/null 2>&1; then check 0 "talon http" "$url healthy"; else check 1 "talon http" "${url:-unset} not healthy"; fi
  if [[ -f "$CONFIG" ]]; then
    # talon doctor's openshell category (static checks; upstream probes are
    # skipped because host.openshell.internal resolves only inside containers).
    local doctor
    doctor="$(cd "$CONFIG_DIR" && TALON_DATA_DIR="$DATA_DIR" "$TALON" doctor --gateway-config "$(basename "$CONFIG")" --skip-upstream 2>&1 | grep -E 'openshell_' || true)"
    if [[ -z "$doctor" ]]; then check 1 "talon doctor" "no openshell checks (gateway.openshell missing in $CONFIG?)"
    else
      while IFS= read -r line; do
        case "$line" in
          *✗*|*"[fail]"*) check 1 "doctor" "$(sed 's/^ *//' <<<"$line")" ;;
          *) check 0 "doctor" "$(sed 's/^ *//' <<<"$line")" ;;
        esac
      done <<<"$doctor"
    fi
  else check 1 "config" "$CONFIG missing (run prepare)"; fi
  if [[ -n "${SHOWCASE_AGENT_FILE:-}" && -f "$SHOWCASE_AGENT_FILE" ]] && grep -q "spiffe://openshell/sandbox/${SHOWCASE_SANDBOX_ID:-__none__}" "$SHOWCASE_AGENT_FILE"; then
    check 0 "sandbox binding" "$AGENT ← spiffe://openshell/sandbox/${SHOWCASE_SANDBOX_ID}"
  else check 1 "sandbox binding" "no verified sandbox bound to $AGENT (run start)"; fi
  if [[ -x "$BIN/openshell" ]]; then
    check 0 "openshell" "cli $("$BIN/openshell" --version 2>/dev/null), gateway $("$BIN/openshell-gateway" --version 2>/dev/null) (pinned ${SHOWCASE_OPENSHELL_VERSION:-?}, docker driver)"
  else check 1 "openshell" "release not fetched (run start)"; fi
  if listening "http://127.0.0.1:${SHOWCASE_GW_HEALTH_PORT:-0}/healthz" && pid_alive gateway; then check 0 "openshell-gateway" "healthy, talon registered over TLS (CA $TLS_DIR/ca.pem)"; else check 1 "openshell-gateway" "not running"; fi
  if [[ -n "${SHOWCASE_SANDBOX_NAME:-}" ]] && openshell_cli sandbox list 2>/dev/null | grep -q "$SHOWCASE_SANDBOX_NAME"; then check 0 "sandbox" "$SHOWCASE_SANDBOX_NAME (${SHOWCASE_SANDBOX_ID:-?}) from ${SHOWCASE_AGENT_IMAGE:-?}"; else check 1 "sandbox" "not present"; fi
  if [[ "$PROVIDER_MODE" == mock ]]; then
    if listening "http://127.0.0.1:${SHOWCASE_MOCK_PORT:-0}/__state" && pid_alive mockprovider; then check 0 "mock provider" "calls so far: $(curl -fsS "http://127.0.0.1:$SHOWCASE_MOCK_PORT/__state" | jq -r .calls)"; else check 1 "mock provider" "not running"; fi
  else check 0 "provider" "real (api.openai.com through OpenShell's credential injection)"; fi
  if listening "http://127.0.0.1:${SHOWCASE_PROTECTED_PORT:-0}/__state" && pid_alive protectedservice; then
    check 0 "protected service" "tickets=$(curl -fsS "http://127.0.0.1:$SHOWCASE_PROTECTED_PORT/__state" | jq -r .tickets) refunds=$(curl -fsS "http://127.0.0.1:$SHOWCASE_PROTECTED_PORT/__state" | jq -r .refunds) customers=$(curl -fsS "http://127.0.0.1:$SHOWCASE_PROTECTED_PORT/__state" | jq -r .customers)"
  else check 1 "protected service" "not running"; fi
  if [[ -s "$RUN_DIR/reviewer.key" ]]; then check 0 "reviewer" "credential present (group support-leads, tenant $TENANT; never enters the sandbox)"; else check 1 "reviewer" "no credential (run prepare)"; fi
  if [[ "$rc" == 0 ]]; then pass "status: every mandatory control is in place"; else die "status: a mandatory control is missing"; fi
}

# ---------------------------------------------------------------- run
protected() { curl -fsS "http://127.0.0.1:$SHOWCASE_PROTECTED_PORT/__state" | jq -r ".$1"; }

cmd_run() {
  [[ -n "${SHOWCASE_SANDBOX_NAME:-}" ]] || die "run 'start' first"
  for c in jq curl; do need "$c" "required by run"; done
  if [[ "$EMBEDDED" == "1" ]]; then
    [[ -n "${TALON_SHOWCASE_SESSION:-}" && -n "${TALON_SHOWCASE_OPERATION_PREFIX:-}" ]] || die "embedded mode supplies TALON_SHOWCASE_SESSION and TALON_SHOWCASE_OPERATION_PREFIX"
  else
    if [[ -z "${TALON_SHOWCASE_SESSION:-}" ]]; then
      local nonce; nonce="$(openssl rand -hex 5)"
      TALON_SHOWCASE_SESSION="openshell-$nonce"; TALON_SHOWCASE_OPERATION_PREFIX="openshell-refund-$nonce"
      ( umask 077; printf 'export TALON_SHOWCASE_SESSION=%q\nexport TALON_SHOWCASE_OPERATION_PREFIX=%q\n' "$TALON_SHOWCASE_SESSION" "$TALON_SHOWCASE_OPERATION_PREFIX" >"$RUN_DIR/latest.env" )
    fi
  fi
  local session="$TALON_SHOWCASE_SESSION" prefix="$TALON_SHOWCASE_OPERATION_PREFIX"
  [[ "$session" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || die "invalid session id $session"
  local agent_log="$RUN_DIR/$session.agent.log" approval_file="$RUN_DIR/$session.approval" result="$RUN_DIR/$session.result.json"
  local tickets0 refunds0 customers0
  tickets0="$(protected tickets)"; refunds0="$(protected refunds)"; customers0="$(protected customers)"
  log "run: session $session, operation prefix $prefix, sandbox $SHOWCASE_SANDBOX_NAME ($SHOWCASE_SANDBOX_ID)"
  log "the agent runs INSIDE the sandbox; it holds no Talon, reviewer or provider credential"
  # The agent writes its continuation journal inside the sandbox (restart
  # recovery is proven by the stable operation ids against Talon itself).
  set +e
  openshell_cli sandbox exec --name "$SHOWCASE_SANDBOX_NAME" --no-tty --no-login-shell --timeout "$(( ${TALON_SHOWCASE_APPROVAL_WAIT_S:-600} + 120 ))" \
    --env "TALON_BASE=http://host.openshell.internal:$SHOWCASE_TALON_HTTP_PORT" \
    --env "PROVIDER_BASE=http://$( [[ "$PROVIDER_MODE" == mock ]] && printf 'host.openshell.internal:%s' "$SHOWCASE_MOCK_PORT" || printf 'api.openai.com' )" \
    --env "TALON_SESSION=$session" --env "OPERATION_ID=$prefix" --env "TICKET_ID=T-1842" \
    --env "APPROVAL_WAIT_S=${TALON_SHOWCASE_APPROVAL_WAIT_S:-600}" --env "AGENT_ADVERSARIAL_PROBE=1" --env "AGENT_STATE_DIR=/home/agent/.talon-agent" \
    --env "OPENAI_API_KEY=placeholder-replaced-by-openshell" \
    -- /usr/local/bin/support-agent 2>>"$LOGS/setup.log" | tee "$agent_log" | while IFS= read -r line; do
      printf 'agent> %s\n' "$line"
      case "$line" in
        APPROVAL_ID=*) ( umask 077; printf 'APPROVAL_ID=%s\nOPERATION_ID=%s\nSESSION=%s\n' "$(awk '{print $1}' <<<"${line#APPROVAL_ID=}")" "$(sed -n 's/.*OPERATION=\([^ ]*\).*/\1/p' <<<"$line")" "$session" >"$approval_file" )
          echo "---- reviewer: in another shell run '$0 approval-status' then '$0 approve' or '$0 reject' ----" ;;
      esac
    done
  local code="${PIPESTATUS[0]}"
  set -e
  local tickets1 refunds1 customers1
  tickets1="$(protected tickets)"; refunds1="$(protected refunds)"; customers1="$(protected customers)"
  local d_tickets=$((tickets1 - tickets0)) d_refunds=$((refunds1 - refunds0)) d_customers=$((customers1 - customers0))
  local refund_op; refund_op="$(sed -n 's/^OPERATION_ID=//p' "$approval_file" 2>/dev/null | head -n1)"
  [[ -n "$refund_op" ]] || refund_op="$(grep -oE 'OPERATION='"$prefix"'-create_refund_request-[0-9a-f]+' "$agent_log" | head -n1 | cut -d= -f2)"
  echo "protected service deltas: tickets=$d_tickets refunds=$d_refunds customers(deletions)=$d_customers"
  local status
  case "$code" in
    0) status="completed"
       [[ "$d_customers" == 0 ]] || die "a forbidden deletion reached the protected service ($d_customers)"
       [[ "$d_refunds" == 1 ]] || die "expected exactly one refund dispatch, observed $d_refunds"
       grep -q 'APPROVAL=approved' "$agent_log" || die "completed without a reviewer approval in the transcript"
       grep -q 'REPLAY=operation_already_succeeded' "$agent_log" || die "replay safety was not demonstrated"
       grep -q 'ADVERSARIAL=denied' "$agent_log" || die "the adversarial forbidden-action probe was not denied" ;;
    2) status="rejected"
       [[ "$d_refunds" == 0 && "$d_customers" == 0 ]] || die "a rejected run produced downstream mutations (refunds=$d_refunds customers=$d_customers)" ;;
    3) echo "RESULT: no reviewer decision within ${TALON_SHOWCASE_APPROVAL_WAIT_S:-600}s; the operation is still pending in Talon — rerun 'run' with the same session to resume (no receipt written)"; exit 3 ;;
    5) status="unresolved"; warn "a downstream outcome is unknown; reconcile with the operator (no retry was attempted)" ;;
    *) die "agent exited with $code (see $agent_log)" ;;
  esac
  [[ -n "$refund_op" ]] || die "no refund operation id in the transcript"
  ( umask 077; jq -n --arg s "$session" --arg r "$SHOWCASE_SANDBOX_ID" --arg op "$refund_op" --arg st "$status" --arg img "$SHOWCASE_AGENT_IMAGE" --arg ver "${SHOWCASE_OPENSHELL_VERSION:-}" --arg pm "$PROVIDER_MODE" \
      --argjson t "$d_tickets" --argjson rf "$d_refunds" --argjson c "$d_customers" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{session_id:$s, runtime_ref:$r, refund_operation_id:$op, status:$st, provider_mode:$pm, openshell_version:$ver, agent_image:$img, observed_downstream:{tickets:$t, refunds:$rf, customer_deletions:$c}, concluded_at:$at,
        note:"locator written by the showcase runner; proof is Talon'"'"'s signed evidence (talon audit list --runtime-ref <runtime_ref> --report; talon audit verify --operation <refund_operation_id>)"}' >"$result" )
  pass "run $status: receipt $result (session $session, sandbox $SHOWCASE_SANDBOX_ID, refund operation $refund_op)"
  echo "reconstruct: TALON_DATA_DIR=$DATA_DIR $TALON audit list --runtime-ref $SHOWCASE_SANDBOX_ID --limit 200 --report"
  echo "verify:      TALON_DATA_DIR=$DATA_DIR $TALON audit verify --operation $refund_op"
  [[ "$status" != unresolved ]] || exit 5
}

# ---------------------------------------------------------------- reviewer commands (Talon's reviewer API, outside the sandbox)
reviewer_target() {
  [[ -s "$RUN_DIR/reviewer.key" ]] || die "no reviewer credential (run prepare)"
  local url="${TALON_URL:-${SHOWCASE_TALON_URL:-}}"; [[ -n "$url" ]] || die "Talon URL unknown (run start)"
  local session="${TALON_SHOWCASE_SESSION:-}"
  if [[ -z "$session" && -f "$RUN_DIR/latest.env" ]]; then source "$RUN_DIR/latest.env"; session="$TALON_SHOWCASE_SESSION"; fi
  [[ -n "$session" ]] || die "no session: start a run first (TALON_SHOWCASE_SESSION)"
  local f="$RUN_DIR/$session.approval"
  [[ -s "$f" ]] || die "no pending approval recorded for session $session yet (the agent reports APPROVAL_ID when it reaches the refund)"
  APPROVAL_ID="$(sed -n 's/^APPROVAL_ID=//p' "$f")"; REFUND_OP="$(sed -n 's/^OPERATION_ID=//p' "$f")"; REVIEWER_URL="$url"
  REVIEWER_KEY="$(cat "$RUN_DIR/reviewer.key")"
}
cmd_approval_status() {
  reviewer_target
  resolve_talon
  [[ -z "${TALON_SECRETS_KEY:-}" && -f "$RUN_DIR/talon.env" ]] && source "$RUN_DIR/talon.env"
  # The host side holds no agent key, so the pending state is read from
  # Talon's own signed lifecycle (the decision goes through the reviewer API).
  echo "approval $APPROVAL_ID for operation $REFUND_OP (sandbox ${SHOWCASE_SANDBOX_ID:-?}):"
  local report
  report="$(talon_cli audit list --runtime-ref "${SHOWCASE_SANDBOX_ID:-}" --limit 500 --report 2>/dev/null | awk -v op="$REFUND_OP" '$1==op {p=1; print; next} /^  [^ ]/ {p=0} p')"
  if [[ -z "$report" ]]; then echo "  (no lifecycle records for $REFUND_OP yet)"; else printf '%s\n' "$report"; fi
  if grep -q 'approval_decided' <<<"$report"; then echo "  decided: $(grep -o 'approval=[a-z]*' <<<"$report" | tail -n1)"; else echo "  pending: waiting for a reviewer ('approve' or 'reject')"; fi
}
decide() { # approve|reject
  reviewer_target
  local reason="verified with the customer"; [[ "$1" == approve ]] || reason="not justified"
  local body; body="$(curl -fsS --max-time 5 -X POST -H "Authorization: Bearer $REVIEWER_KEY" -H 'content-type: application/json' --data "{\"decision\":\"$1\",\"reason\":\"$reason\"}" "$REVIEWER_URL/v1/approvals/$APPROVAL_ID/decisions")" || die "$1 failed (already decided, expired, or the credential is not in group support-leads?)"
  echo "$1: operation $REFUND_OP is now $(jq -r '.operation.operation_status' <<<"$body") — approval alone dispatches nothing; the agent's claim does"
}
cmd_approve() { decide approve; }
cmd_reject()  { decide reject; }

# ---------------------------------------------------------------- validate (CI lane)
cmd_validate() {
  [[ "$EMBEDDED" != "1" ]] || die "validate runs standalone (it owns a private run dir); unset TALON_SHOWCASE_EMBEDDED"
  local vdir; vdir="$(mktemp -d "${TMPDIR:-/tmp}/talon-openshell-showcase.XXXXXX")"
  log "validate: private run dir $vdir, OpenShell $OPENSHELL_VERSION"
  local self="${BASH_SOURCE[0]}"
  # The private run must not inherit the state this process loaded from
  # its own run dir (ports, ids, resolved binaries) or the caller's Talon keys.
  local unset_vars=()
  local v
  for v in $(compgen -v | grep -E '^(SHOWCASE_|TALON_BIN_RESOLVED$|TALON_SHOWCASE_(SESSION|OPERATION_PREFIX|CONFIG_DIR|TALON_DATA_DIR|TALON_URL)$|TALON_SIGNING_KEY$|TALON_ADMIN_KEY$)'); do unset_vars+=(-u "$v"); done
  local envv=(env "${unset_vars[@]}" TALON_SHOWCASE_RUN_DIR="$vdir" TALON_SHOWCASE_EMBEDDED=0 TALON_SHOWCASE_PROVIDER_MODE=mock TALON_SHOWCASE_APPROVAL_WAIT_S=120)
  "${envv[@]}" bash "$self" prepare || die "validate: prepare"
  "${envv[@]}" bash "$self" start || { "${envv[@]}" bash "$self" stop || true; die "validate: start"; }
  "${envv[@]}" bash "$self" status || { "${envv[@]}" bash "$self" stop || true; die "validate: status"; }
  # Approved journey: the reviewer approves from the host as soon as the
  # agent reports the approval id; then the agent claims and completes.
  local session
  session="openshell-validate-$(openssl rand -hex 3)"
  ( for _ in $(seq 1 240); do [[ -s "$vdir/$session.approval" ]] && { sleep 1; "${envv[@]}" env TALON_SHOWCASE_SESSION="$session" bash "$self" approve && exit 0; }; sleep 0.5; done; exit 1 ) &
  local approver=$!
  "${envv[@]}" env TALON_SHOWCASE_SESSION="$session" TALON_SHOWCASE_OPERATION_PREFIX="openshell-refund-$session" bash "$self" run || { kill $approver 2>/dev/null; "${envv[@]}" bash "$self" stop || true; die "validate: approved run"; }
  wait $approver || { "${envv[@]}" bash "$self" stop || true; die "validate: host-side approval did not happen"; }
  jq -e --arg s "$session" '.session_id == $s and .status == "completed" and .observed_downstream.refunds == 1 and .observed_downstream.customer_deletions == 0' "$vdir/$session.result.json" >/dev/null || die "validate: receipt"
  # Resume after a restart: the same session and prefix find the operation
  # already succeeded; no second refund.
  "${envv[@]}" env TALON_SHOWCASE_SESSION="$session" TALON_SHOWCASE_OPERATION_PREFIX="openshell-refund-$session" bash "$self" run || die "validate: resumed run"
  jq -e '.observed_downstream.refunds == 0' "$vdir/$session.result.json" >/dev/null || die "validate: the resumed run dispatched again"
  # Rejected journey: zero mutations.
  local session2
  session2="openshell-validate-$(openssl rand -hex 3)"
  ( for _ in $(seq 1 240); do [[ -s "$vdir/$session2.approval" ]] && { sleep 1; "${envv[@]}" env TALON_SHOWCASE_SESSION="$session2" bash "$self" reject && exit 0; }; sleep 0.5; done; exit 1 ) &
  local rejecter=$!
  set +e
  "${envv[@]}" env TALON_SHOWCASE_SESSION="$session2" TALON_SHOWCASE_OPERATION_PREFIX="openshell-refund-$session2" bash "$self" run; local rc=$?
  set -e
  wait $rejecter || die "validate: host-side rejection did not happen"
  [[ "$rc" == 0 ]] || die "validate: rejected run exited $rc"
  jq -e '.status == "rejected" and .observed_downstream.refunds == 0 and .observed_downstream.customer_deletions == 0' "$vdir/$session2.result.json" >/dev/null || die "validate: rejected receipt"
  # Evidence: the refund lifecycle verifies, the runtime report is complete.
  local talon op sid
  talon="$(sed -n 's/^export TALON_BIN_RESOLVED=//p' "$vdir/showcase.env" | tr -d "'\"")"
  op="$(jq -r .refund_operation_id "$vdir/$session.result.json")"
  sid="$(jq -r .runtime_ref "$vdir/$session.result.json")"
  ( [[ ! -f "$vdir/talon.env" ]] || source "$vdir/talon.env"; TALON_DATA_DIR="$vdir/talon-data" "$talon" audit verify --operation "$op" | grep -Fq 'Lifecycle: VALID' ) || die "validate: refund lifecycle does not verify"
  ( [[ ! -f "$vdir/talon.env" ]] || source "$vdir/talon.env"; TALON_DATA_DIR="$vdir/talon-data" "$talon" audit list --runtime-ref "$sid" --limit 500 --report >"$vdir/logs/runtime-report.txt" )
  grep -q 'More records exist' "$vdir/logs/runtime-report.txt" && die "validate: runtime report paginated"
  grep -q 'UNVERIFIED' "$vdir/logs/runtime-report.txt" && die "validate: unverified record in the runtime report"
  grep -q 'tools_removed=\[delete_customer\]' "$vdir/logs/runtime-report.txt" || die "validate: tool filtering not in evidence"
  grep -q 'reviewer=apr_' "$vdir/logs/runtime-report.txt" || die "validate: reviewer decision not in evidence"
  # Hygiene: no provider secret, reviewer credential or Talon key in logs.
  local leak
  for leak in "$(sed -n 's/^export SHOWCASE_PROVIDER_SECRET=//p' "$vdir/showcase.env" | tr -d "'\"")" "$(cat "$vdir/reviewer.key")" "PRIVATE KEY-----"; do
    [[ -n "$leak" ]] && grep -rqF -- "$leak" "$vdir/logs" "$vdir"/*.agent.log 2>/dev/null && die "validate: secret-shaped material in logs"
  done
  "${envv[@]}" bash "$self" stop || die "validate: stop"
  pass "validate: approved and rejected journeys, resume without a second refund, evidence VALID, runtime report complete, logs clean (OpenShell $OPENSHELL_VERSION, $vdir)"
  [[ "${TALON_SHOWCASE_KEEP:-0}" == 1 ]] || rm -rf "$vdir"
}

# ---------------------------------------------------------------- stop
cmd_stop() {
  if [[ -n "${SHOWCASE_SANDBOX_NAME:-}" && -x "$BIN/openshell" ]] && pid_alive gateway; then
    openshell_cli sandbox delete "$SHOWCASE_SANDBOX_NAME" >>"$LOGS/setup.log" 2>&1 || true
  fi
  stop_bg gateway; stop_bg mockprovider; stop_bg protectedservice
  if [[ "$EMBEDDED" == "1" ]]; then log "embedded mode: the shared Talon is left running (Full Demo's real-stop owns it)"; else stop_bg talon; fi
  rm -f "$RUN_DIR/showcase.env.tmp"
  for k in SHOWCASE_SANDBOX_NAME SHOWCASE_SANDBOX_ID; do [[ -f "$STATE" ]] && sed -i "/^export $k=/d" "$STATE" || true; done
  if [[ "${TALON_SHOWCASE_KEEP:-0}" == 1 ]]; then
    echo "kept: $LOGS and the run state (keys under $TLS_DIR/$JWT_DIR and $RUN_DIR/reviewer.key are private files, never printed)"
  fi
  pass "stop: showcase resources stopped (sandbox, gateway, mocks$( [[ "$EMBEDDED" == 1 ]] || echo ', talon' ))"
}

case "$COMMAND" in
  prepare) cmd_prepare ;;
  start) cmd_start ;;
  status) cmd_status ;;
  run) cmd_run ;;
  approval-status) cmd_approval_status ;;
  approve) cmd_approve ;;
  reject) cmd_reject ;;
  validate) cmd_validate ;;
  stop) cmd_stop ;;
esac

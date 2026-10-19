#!/usr/bin/env bash
# Real-OpenShell live smoke (#482, #457): Talon as supervisor middleware of a
# REAL, pinned OpenShell gateway and sandbox (v0.1.3 baseline, v0.1.4 pinned),
# with a deterministic mock provider and a protected action target.
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
#   Action Gateway through the SAME hop (#457/#482, sandbox holds no Talon secret):
#   G  allowed read action: the sandbox establishes and claims under its
#      verified identity; the protected service is called exactly once
#   H  forbidden action: DENY, zero dispatch, claim refused
#   I  consequential action requiring approval: 202 and zero dispatch; the
#      claim waits; a human reviewer approves from the host; approval alone
#      dispatches nothing; the sandbox's claim dispatches exactly once; exact
#      replay never duplicates
#   J  unbound sandbox: denied at the hop (workload_identity_unbound), Talon's
#      API never reached, record count unchanged
#   K  a sandbox-written assertion header is overwritten by the hop (the
#      request still authenticates as the verified sandbox, never as the
#      forged claims); a forged assertion presented directly to Talon is refused
#   L  direct egress from the sandbox to the protected service is blocked by
#      OpenShell network policy (Talon authorization is not what prevents it)
#   M  the reviewer route is unreachable through the hop, whatever credential
#      the sandbox holds
#   N  the checked-in reference agent (examples/openshell/sandbox-agent.sh)
#      runs the whole scenario inside the real sandbox with a host-side human
#      approval: exactly one effect, replay-safe, lifecycle VALID
#   Response side (HTTP_RESPONSE / PRE_RETURN): every allowed model response is
#   inspected before the sandbox receives it; evidence carries the provider's
#   ACTUAL usage priced from the table in a settlement record joined to its
#   decision (which booked no cost), never estimate plus actual.
#   plus: signed Talon evidence with delegated_expected provenance verifies
#   offline, action lifecycle records carry the verified sandbox identity and
#   join the model records through the session spine, `audit verify
#   --operation` is VALID, and no secret appears in Talon's state or logs.
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
#   TALON_OPENSHELL_WORKLOAD_IMAGE
#                               digest-pinned (@sha256:) curl-capable workload
#                               image replacing the default fixture; the
#                               in-sandbox precondition still has to pass
#   OPENSHELL_VERSION           released OpenShell tag to exercise (default
#                               v0.1.3, the validated baseline; v0.1.4 is pinned
#                               as well — its middleware proto differs from
#                               v0.1.3 by a comment only — and is exercised by
#                               the live workflow's experimental matrix entry)
#   TALON_OPENSHELL_PREFLIGHT_ONLY=1
#                               stop before starting the gateway: verifies the
#                               pinned artifacts, builds talon, generates the
#                               gateway JWT bundle and Talon's TLS identity,
#                               starts talon with the middleware listener and
#                               runs `openshell-gateway config preflight` on the
#                               generated registration (no Docker needed)
set -euo pipefail
PREFLIGHT_ONLY="${TALON_OPENSHELL_PREFLIGHT_ONLY:-0}"
# TALON_OPENSHELL_SELFTEST_FAIL=1 makes the harness exit non-zero immediately:
# the workflow's own plumbing check (a failing harness must be a red job).
if [[ "${TALON_OPENSHELL_SELFTEST_FAIL:-0}" == "1" ]]; then echo "FAIL self-test: deliberate harness failure requested" >&2; exit 1; fi

OPENSHELL_VERSION="${OPENSHELL_VERSION:-v0.1.3}"
# sha256 from each release's openshell-checksums-sha256.txt and
# openshell-gateway-checksums-sha256.txt. Only pinned versions can run.
declare -A CLI_SHA GW_SHA
case "$OPENSHELL_VERSION" in
  v0.1.3) # released 2026-10-09; validated baseline
    CLI_SHA=([x86_64]="ed08ea7874c47f22d6e5dcc4b27d9ef1ef5d2060f83035b35ff725d5160830a3" [aarch64]="07687dacefc52bc73b01943f5b58f7a5082c1ceaa228461b9a2a78023b8057c0")
    GW_SHA=([x86_64]="da8dce943fe01cce90243b2bf2587c71a243e4d641a4b616528829b681ced198" [aarch64]="801214322227f64f2d3faa6989daaa5e6cd9ef1ab768b5860496deeb1158c27b")
    ;;
  v0.1.4) # released 2026-10-13; proto contract identical to v0.1.3 (comment-only diff), validated by the experimental matrix entry
    CLI_SHA=([x86_64]="2b65178e62e1ece1d90d482555e9f1f98ff0296e058409b33418104b6333df07" [aarch64]="1cd6e63597e1947c44a753bf5352f949e8d8d02e344af92ab899b7c111112d95")
    GW_SHA=([x86_64]="43f43554bcaabff2a8147444410d1ad0b7f51bdae7589c2d249982bc8b260b91" [aarch64]="d0f8a2045e613f612a542abe860e497906169c2483093a9bd52e41737df397f0")
    ;;
  *) echo "MISSING pin: OPENSHELL_VERSION=$OPENSHELL_VERSION has no pinned checksums in this harness" >&2; exit 2 ;;
esac
OPENSHELL_SEMVER="${OPENSHELL_VERSION#v}"
RELEASE_BASE="https://github.com/NVIDIA/OpenShell/releases/download/${OPENSHELL_VERSION}"

# Workload fixture. The sandbox image is a TEST FIXTURE, never OpenShell's
# mutable default (nvcr.io/nvidia/base/ubuntu:24.04 has no curl, which made the
# first real run die with "curl: not found" inside CASE A). It is pinned by
# multi-arch index digest, contains exactly the client the lane drives
# (/usr/bin/curl, busybox /bin/sh and /bin/sleep), and is verified inside the
# REAL sandbox before CASE A. Talon has no dependency on this image; production
# users run their own agent images. The three places that name the client
# binary (provider profile, network policy, request) all use $CURL_BIN.
# curlimages/curl 8.22.0, index digest from Docker Hub (linux amd64/arm64/arm/386/ppc64le).
WORKLOAD_IMAGE_REPO="docker.io/curlimages/curl"
WORKLOAD_IMAGE_TAG="8.22.0"
WORKLOAD_IMAGE_DIGEST="sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777"
WORKLOAD_IMAGE="${TALON_OPENSHELL_WORKLOAD_IMAGE:-$WORKLOAD_IMAGE_REPO:$WORKLOAD_IMAGE_TAG@$WORKLOAD_IMAGE_DIGEST}"
[[ "$WORKLOAD_IMAGE" == *@sha256:* ]] || { echo "FAIL live workload image must be digest pinned (got $WORKLOAD_IMAGE)" >&2; exit 1; }
WORKLOAD_IMAGE_DIGEST="${WORKLOAD_IMAGE##*@}"
CURL_BIN="${TALON_OPENSHELL_CURL_BIN:-/usr/bin/curl}"
SH_BIN="/bin/sh"
SLEEP_BIN="/bin/sleep"

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
# The release TARBALLS are cached; every run re-verifies their sha256 against
# the pins above and extracts the binaries fresh into the run's work dir, so
# a cache hit never bypasses verification and the binary used always comes
# from a tarball that matched the official checksum manifest on this run.
CACHE="${TALON_OPENSHELL_CACHE:-$HOME/.cache/talon-openshell}/$OPENSHELL_VERSION"
mkdir -p "$CACHE"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/talon-openshell-live.XXXXXX")"
LOGS="$WORK/logs"; mkdir -p "$LOGS"
BIN="$WORK/bin"; mkdir -p "$BIN"
fetch_pinned() { # name url sha binary
  local name="$1" url="$2" sha="$3" binary="$4"
  local tgz="$CACHE/$name.tgz"
  if [[ -f "$tgz" ]] && ! echo "$sha  $tgz" | sha256sum -c - >/dev/null 2>&1; then
    log "cached $name tarball does not match the pinned checksum; discarding it"
    rm -f "$tgz"
  fi
  if [[ ! -f "$tgz" ]]; then
    log "downloading $name ($OPENSHELL_VERSION)"
    curl -fsSL --retry 3 -o "$tgz.part" "$url" && mv "$tgz.part" "$tgz"
  fi
  echo "$sha  $tgz" | sha256sum -c - >/dev/null || { rm -f "$tgz"; die "checksum mismatch for $name (expected $sha)"; }
  tar -xzf "$tgz" -C "$BIN" "$binary" || die "$name archive did not contain $binary"
  [[ -x "$BIN/$binary" ]] || die "$binary is not executable after extraction"
}
fetch_pinned "openshell-cli" "$RELEASE_BASE/openshell-${ARCH}-unknown-linux-musl.tar.gz" "${CLI_SHA[$ARCH]}" "openshell"
fetch_pinned "openshell-gateway" "$RELEASE_BASE/openshell-gateway-${ARCH}-unknown-linux-gnu.tar.gz" "${GW_SHA[$ARCH]}" "openshell-gateway"
CLI_BIN="$BIN/openshell"; GW_BIN="$BIN/openshell-gateway"
[[ "$("$CLI_BIN" --version)" == *"$OPENSHELL_SEMVER"* ]] || die "unexpected CLI version: $("$CLI_BIN" --version) (want $OPENSHELL_SEMVER)"
[[ "$("$GW_BIN" --version)" == *"$OPENSHELL_SEMVER"* ]] || die "unexpected gateway version: $("$GW_BIN" --version) (want $OPENSHELL_SEMVER)"
log "verified release artifacts: cli sha256 ${CLI_SHA[$ARCH]}, gateway sha256 ${GW_SHA[$ARCH]} ($ARCH)"

# ---------------------------------------------------------------- workspace
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
TALON_HTTP_PORT="$(free_port)"; TALON_GRPC_PORT="$(free_port)"; MOCK_PORT="$(free_port)"; PROTECTED_PORT="$(free_port)"; GW_PORT="$(free_port)"; GW_HEALTH_PORT="$(free_port)"
GW_ENDPOINT="http://127.0.0.1:$GW_PORT"
CLI=(env -u OPENSHELL_SANDBOX_POLICY "$CLI_BIN" --gateway-endpoint "$GW_ENDPOINT")

TALON_PID=""; GW_PID=""; MOCK_PID=""; PROTECTED_PID=""; SANDBOXES=()
dump_logs() {
  for f in talon-serve gateway mockprovider protectedservice setup; do
    printf '\n--- %s log ---\n' "$f" >&2
    [[ -f "$LOGS/$f.log" ]] && tail -n 120 "$LOGS/$f.log" >&2 || printf '(missing)\n' >&2
  done
}
cleanup() {
  local status=$?
  trap - EXIT
  for sb in "${SANDBOXES[@]:-}"; do [[ -n "$sb" ]] && "${CLI[@]}" sandbox delete "$sb" >>"$LOGS/setup.log" 2>&1 || true; done
  for pid in "$GW_PID" "$TALON_PID" "$MOCK_PID" "$PROTECTED_PID"; do [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }; done
  # Secret-bearing material (tls/, jwt/, talon-home/, provider-state.json)
  # stays in $WORK and is never part of the collected logs; CI uploads $LOGS only.
  if [[ "$status" -eq 0 && "${TALON_OPENSHELL_KEEP:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "work dir retained: $WORK (logs: $LOGS)" >&2; fi
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
go build -o "$WORK/protectedservice" ./tests/openshell-live/protectedservice >>"$LOGS/setup.log" 2>&1 || die "go build protectedservice"
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
# Talon's middleware TLS identity, in OpenShell's real trust topology: an
# operator CA (tls_ca_cert_path on the registration; rustls/webpki requires
# a real CA trust anchor, a self-signed leaf is "unknown certificate") signs
# Talon's server certificate, whose SANs are exactly what the gateway and
# every supervisor dial (the host address and host.openshell.internal) and
# whose EKU is serverAuth. Keys are ephemeral; nothing under tls/ is uploaded.
TLS_DIR="$WORK/tls"; mkdir -p "$TLS_DIR"
cat >"$TLS_DIR/ca.cnf" <<'EOT'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = talon-openshell-live test CA
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
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -config "$TLS_DIR/ca.cnf" \
  -keyout "$TLS_DIR/ca-key.pem" -out "$TLS_DIR/ca.pem" >>"$LOGS/setup.log" 2>&1 || die "openssl CA"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -config "$TLS_DIR/server.cnf" \
  -keyout "$TLS_DIR/talon-key.pem" -out "$TLS_DIR/talon.csr" >>"$LOGS/setup.log" 2>&1 || die "openssl server CSR"
openssl x509 -req -in "$TLS_DIR/talon.csr" -CA "$TLS_DIR/ca.pem" -CAkey "$TLS_DIR/ca-key.pem" -CAcreateserial -days 2 \
  -extfile "$TLS_DIR/server.cnf" -extensions v3_server -out "$TLS_DIR/talon-cert.pem" >>"$LOGS/setup.log" 2>&1 || die "openssl sign server cert"
openssl verify -CAfile "$TLS_DIR/ca.pem" "$TLS_DIR/talon-cert.pem" >>"$LOGS/setup.log" 2>&1 || die "server certificate does not chain to the test CA"
# A second, unrelated CA for the negative proof (wrong trust anchor → TLS fails).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -config "$TLS_DIR/ca.cnf" \
  -keyout "$TLS_DIR/other-ca-key.pem" -out "$TLS_DIR/other-ca.pem" >>"$LOGS/setup.log" 2>&1 || die "openssl other CA"
log "tls: CA $(openssl x509 -in "$TLS_DIR/ca.pem" -noout -fingerprint -sha256 | cut -d= -f2), server SAN IP:$HOST_IP DNS:host.openshell.internal"

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
# The protected action target. It listens on every interface so CASE L can
# prove that OpenShell's network policy — not Talon — is what keeps the
# sandbox from reaching it directly; Talon dispatches to it over loopback.
"$WORK/protectedservice" -listen "$MOCK_BIND:$PROTECTED_PORT" -state-file "$WORK/protected-state.json" >"$LOGS/protectedservice.log" 2>&1 &
PROTECTED_PID=$!
wait_http "http://127.0.0.1:$PROTECTED_PORT/__state" 10 || die "protected service did not start"
protected_state() { curl -fsS "http://127.0.0.1:$PROTECTED_PORT/__state"; }
protected_count() { protected_state | jq -r ".$1"; }

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
    # Sandboxes reach Talon's OWN Action Gateway on the host at this port;
    # the provider shares the hostname on another port, so the entry carries
    # Talon's port (a destination is either Talon or a provider).
    self_destination:
      hosts: ["host.openshell.internal:$TALON_HTTP_PORT"]
      assertion_ttl: "60s"
    # Response side: Talon inspects the provider's response at PRE_RETURN,
    # settles actual usage/cost and applies the response PII policy.
    response_governance:
      enabled: true
      settlement_timeout: "60s"
EOT
# Trusted action catalog of the use case (the sandbox cannot change it): a
# read, a consequential refund that needs a human reviewer, and a forbidden
# action. Destinations are Talon-side loopback; the sandbox has no route to
# them except through Talon.
python3 - "$AGENT_FILE" "$PROTECTED_PORT" <<'PY' || die "catalog edit"
import sys
p, port = sys.argv[1:]
s = open(p).read()
assert "\ncapabilities:\n" in s and "\npolicies:\n" in s, "scaffold shape"
s = s.replace("\ncapabilities:\n", "\ncapabilities:\n  forbidden_tools: [delete_customer]\n", 1)
s = s.replace("\npolicies:\n", """
actions:
  definitions:
    lookup_ticket:
      description: Read one support ticket
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id]
        properties:
          ticket_id: {type: string}
      destination: {type: http, url: "http://127.0.0.1:%s/tickets", method: POST, success: {status_codes: [200]}}
    create_refund_request:
      description: Create a refund request for a support ticket
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: number}
          currency: {type: string, enum: [EUR, USD]}
      review:
        fields: [ticket_id, amount, currency]
      destination: {type: http, url: "http://127.0.0.1:%s/refunds", method: POST, success: {status_codes: [201]}}
    delete_customer:
      input_schema:
        type: object
        additionalProperties: false
        properties:
          customer_id: {type: string}
      destination: {type: http, url: "http://127.0.0.1:%s/customers"}

policies:
  approvals:
    expires_after: 30m
    rules:
      refund-request:
        actions: [create_refund_request]
        approver_groups: [support-leads]
""" % (port, port, port), 1)
open(p, "w").write(s)
PY
( cd "$TALON_HOME" && "$TALON" validate >>"$LOGS/setup.log" 2>&1 ) || die "talon validate rejected the agent catalog"
( cd "$TALON_HOME" && "$TALON" secrets set openai-api-key "$TALON_VAULT_DECOY" >>"$LOGS/setup.log" 2>&1 && "$TALON" secrets set "$AGENT-talon-key" "talon-gw-live-$(openssl rand -hex 6)" >>"$LOGS/setup.log" 2>&1 ) || die "talon secrets set"
# One human reviewer credential (host-side only; the sandbox never holds it,
# and CASE M proves it could not use it through the hop anyway).
LEAD_KEY="$( (cd "$TALON_HOME" && "$TALON" approver add --name lead-1 --tenant default --groups support-leads 2>>"$LOGS/setup.log") | grep -oE 'talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+' | head -n1)"
[[ -n "$LEAD_KEY" ]] || die "approver add printed no credential"

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
tls_ca_cert_path = "$TLS_DIR/ca.pem"
audience = "$AUDIENCE"
max_payload_bytes = 1048576
timeout = "10s"
EOT
"$GW_BIN" config preflight --path "$GW_CFG" >>"$LOGS/setup.log" 2>&1 || die "openshell-gateway config preflight rejected $GW_CFG"
pass "openshell-gateway config preflight accepted the talon registration"
# Talon's manifest is what the real gateway sees at startup: fetch it the way
# the gateway does (TLS to the registered endpoint, pinned operator CA, normal
# SAN verification). The wrong CA must fail — no InsecureSkipVerify anywhere.
go build -o "$WORK/describe" ./tests/openshell-live/describe >>"$LOGS/setup.log" 2>&1 || die "go build describe"
if "$WORK/describe" -endpoint "https://$HOST_IP:$TALON_GRPC_PORT" -ca "$TLS_DIR/other-ca.pem" >>"$LOGS/setup.log" 2>&1; then
  die "Describe succeeded with an unrelated CA; TLS verification is not effective"
fi
pass "tls: Describe with the wrong CA is refused"
"$WORK/describe" -endpoint "https://$HOST_IP:$TALON_GRPC_PORT" -ca "$TLS_DIR/ca.pem" -expect-response >>"$LOGS/setup.log" 2>&1 || die "Describe over TLS with the registered CA failed (see setup log: bindings must be HTTP_REQUEST/PRE_CREDENTIALS + HTTP_RESPONSE/PRE_RETURN)"
pass "tls: Describe with the registered CA and the dialed SAN negotiated protocol 1.0 and returned the HTTP_REQUEST/PRE_CREDENTIALS + HTTP_RESPONSE/PRE_RETURN manifest"
if [[ "$PREFLIGHT_ONLY" == "1" ]]; then
  echo "PREFLIGHT ONLY: artifacts verified, talon started with the middleware listener, TLS trust proven both ways, gateway registration accepted; the gateway/sandbox stages need Docker"
  exit 0
fi
env -u OPENSHELL_DRIVERS -u OPENSHELL_COMPUTE_DRIVER "$GW_BIN" --compute-driver docker --config "$GW_CFG" --name "$GATEWAY_ID" \
  --bind-address 127.0.0.1 --port "$GW_PORT" --health-port "$GW_HEALTH_PORT" --metrics-port 0 --disable-tls \
  --db-url "sqlite://$WORK/gateway.db" --log-level "${TALON_OPENSHELL_LOG_LEVEL:-info}" >"$LOGS/gateway.log" 2>&1 &
GW_PID=$!
gateway_startup_hint() { # diagnostics only: classify the likely stage from the gateway and talon logs
  local gw="$LOGS/gateway.log" tl="$LOGS/talon-serve.log"
  if grep -qiE "tls|certificate|handshake" "$gw" "$tl" 2>/dev/null; then echo "transport/TLS (certificate chain, SAN or CA mismatch)"
  elif grep -qiE "protocol metadata|protocol version|capabilit" "$gw" 2>/dev/null; then echo "extension protocol negotiation"
  elif grep -qiE "manifest|expected_audience|binding" "$gw" 2>/dev/null; then echo "manifest validation"
  elif grep -qiE "could not connect|connection refused|unreachable" "$gw" 2>/dev/null; then echo "transport (endpoint unreachable)"
  else echo "unclassified (see gateway log)"; fi
}
for ((i=0; i<240; i++)); do
  if ! kill -0 "$GW_PID" 2>/dev/null; then
    die "openshell-gateway exited during startup; likely stage: $(gateway_startup_hint)"
  fi
  curl -fsS --max-time 1 "http://127.0.0.1:$GW_HEALTH_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS --max-time 1 "http://127.0.0.1:$GW_HEALTH_PORT/healthz" >/dev/null 2>&1 || die "openshell-gateway not healthy; likely stage: $(gateway_startup_hint)"
pass "gateway $OPENSHELL_VERSION started with talon registered (Describe + protocol negotiation succeeded)"

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
binaries: [$CURL_BIN]
EOT
"${CLI[@]}" profile import -f "$WORK/profile.yaml" --global >>"$LOGS/setup.log" 2>&1 || die "profile import"
"${CLI[@]}" provider create --name mock-openai --type talon-live-openai --global-profile --credential "OPENAI_API_KEY=$PROVIDER_SECRET" >>"$LOGS/setup.log" 2>&1 || die "provider create"
# filesystem_policy is a FIXTURE need, not a governance statement: OpenShell's
# proxy-mode baseline grants read/execute under /usr, /lib, /etc, /app,
# /var/log and /proc only. The Alpine-based fixture keeps busybox (sh, sleep)
# under a real /bin directory, which Landlock would otherwise deny at exec
# ("failed to spawn sandbox entrypoint process '/bin/sleep': Permission
# denied", OpenShell Live run 38270547122). include_workdir stays true, the
# default an omitted block would have.
cat >"$WORK/policy.yaml" <<EOT
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
      - path: $CURL_BIN
  # Talon's own Action Gateway, reached through the same talon middleware
  # (selected by host). The protected service's port is deliberately NOT
  # listed: CASE L proves OpenShell blocks the direct path.
  talon-action-gateway:
    endpoints:
      - host: host.openshell.internal
        port: $TALON_HTTP_PORT
        protocol: rest
        access: read-write
        enforcement: enforce
    binaries:
      - path: $CURL_BIN
EOT
create_sandbox() { # name — ALWAYS from the pinned fixture; never OpenShell's default image.
  # busybox sleep has no "infinity"; the largest 32-bit second count is ~68 years.
  "${CLI[@]}" sandbox create --name "$1" --from "$WORKLOAD_IMAGE" --policy "$WORK/policy.yaml" --provider mock-openai --no-tty --detach -- "$SLEEP_BIN" 2147483647 >>"$LOGS/setup.log" 2>&1 || die "sandbox create $1 from $WORKLOAD_IMAGE"
  SANDBOXES+=("$1")
}
create_sandbox "$SANDBOX_A"
SANDBOX_A_ID="$("${CLI[@]}" sandbox list --ids 2>>"$LOGS/setup.log" | head -n 1)"
[[ -n "$SANDBOX_A_ID" ]] || die "could not read the sandbox id"
log "sandbox $SANDBOX_A id=$SANDBOX_A_ID from $WORKLOAD_IMAGE"

# ---------------------------------------------------------------- workload fixture precondition
# Prove the fixture before any governance case, inside the REAL sandbox: the
# client binary exists at exactly the path the provider profile and the
# network policy name, the shell and sleep exist, and the image the driver
# resolved carries the pinned digest. A mismatch here is a fixture failure,
# not a Talon or OpenShell governance failure, and must not surface later as
# an empty HTTP code.
sandbox_sh() { # sandbox script
  "${CLI[@]}" sandbox exec --name "$1" --no-tty --no-login-shell --timeout 60 -- "$SH_BIN" -c "$2" 2>>"$LOGS/setup.log"
}
FIXTURE="$(sandbox_sh "$SANDBOX_A" 'printf "curl=%s\nsh=%s\nsleep=%s\nuser=%s\n" "$(command -v curl || echo missing)" "$(command -v sh || echo missing)" "$(command -v sleep || echo missing)" "$(id -u 2>/dev/null || echo unknown)"; curl --version 2>/dev/null | head -n1' || true)"
printf '%s\n' "$FIXTURE" >>"$LOGS/setup.log"
DETECTED_CURL="$(sed -n 's/^curl=//p' <<<"$FIXTURE" | head -n1)"
DETECTED_SH="$(sed -n 's/^sh=//p' <<<"$FIXTURE" | head -n1)"
DETECTED_SLEEP="$(sed -n 's/^sleep=//p' <<<"$FIXTURE" | head -n1)"
CURL_VERSION_LINE="$(grep -m1 '^curl ' <<<"$FIXTURE" || true)"
[[ "$DETECTED_CURL" == "$CURL_BIN" ]] || die "workload fixture: expected curl at $CURL_BIN, image $WORKLOAD_IMAGE reported '${DETECTED_CURL:-missing}' (sandbox output: $FIXTURE)"
[[ "$DETECTED_SH" == "$SH_BIN" ]] || die "workload fixture: expected sh at $SH_BIN, image reported '${DETECTED_SH:-missing}'"
[[ "$DETECTED_SLEEP" == "$SLEEP_BIN" ]] || die "workload fixture: expected sleep at $SLEEP_BIN, image reported '${DETECTED_SLEEP:-missing}'"
[[ -n "$CURL_VERSION_LINE" ]] || die "workload fixture: curl --version produced no output in the sandbox"
RESOLVED_DIGESTS="$(docker image inspect --format '{{join .RepoDigests " "}}' "$WORKLOAD_IMAGE_REPO@$WORKLOAD_IMAGE_DIGEST" 2>>"$LOGS/setup.log" || true)"
grep -qF "$WORKLOAD_IMAGE_DIGEST" <<<"$RESOLVED_DIGESTS" || die "workload fixture: docker resolved digests '$RESOLVED_DIGESTS' do not include the pinned $WORKLOAD_IMAGE_DIGEST"
pass "workload fixture: $WORKLOAD_IMAGE present in the real sandbox with curl=$DETECTED_CURL sh=$DETECTED_SH sleep=$DETECTED_SLEEP ($CURL_VERSION_LINE); docker resolved digest matches the pin"
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

sandbox_request() { # sandbox body -> prints "<http_code>\n<response body>"; stdout only, no file writes in the sandbox
  local sb="$1" body="$2"
  "${CLI[@]}" sandbox exec --name "$sb" --no-tty --no-login-shell --timeout 60 --env "TALON_BODY=$body" -- \
    "$SH_BIN" -c 'out=$('"$CURL_BIN"' -sS --max-time 40 -w "\n__CODE__%{http_code}" -X POST "http://host.openshell.internal:'"$MOCK_PORT"'/v1/chat/completions" -H "Authorization: Bearer $OPENAI_API_KEY" -H "content-type: application/json" -H "X-Talon-Session-ID: sess-live-'"$RUN_ID"'" --data "$TALON_BODY"); echo "${out##*__CODE__}"; printf "%s\n" "${out%__CODE__*}"' 2>>"$LOGS/setup.log"
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

# ---------------------------------------------------------------- action gateway through the hop
SESSION="sess-live-$RUN_ID"
# sandbox_action sandbox method path body [extra curl args…] -> "<http_code>\n<response body>"
# The sandbox dials Talon's HTTP API on the host through OpenShell; it holds
# no Talon credential — the hop supplies the workload assertion.
sandbox_action() {
  local sb="$1" method="$2" path="$3" body="$4"; shift 4
  "${CLI[@]}" sandbox exec --name "$sb" --no-tty --no-login-shell --timeout 60 --env "TALON_BODY=$body" --env "TALON_PATH=$path" --env "TALON_METHOD=$method" --env "TALON_SESSION=$SESSION" "$@" -- \
    "$SH_BIN" -c 'out=$('"$CURL_BIN"' -sS --max-time 40 -w "\n__CODE__%{http_code}" -X "$TALON_METHOD" "http://host.openshell.internal:'"$TALON_HTTP_PORT"'$TALON_PATH" -H "content-type: application/json" -H "X-Talon-Session-ID: $TALON_SESSION" ${TALON_EXTRA_HEADER:+-H "$TALON_EXTRA_HEADER"} ${TALON_BODY:+--data "$TALON_BODY"}); echo "${out##*__CODE__}"; printf "%s\n" "${out%__CODE__*}"' 2>>"$LOGS/setup.log"
}
body_of() { tail -n +2 <<<"$1"; }
json_field() { jq -r "$2 // empty" <<<"$(body_of "$1")" 2>/dev/null; }
records_total() { ( cd "$TALON_HOME" && "$TALON" audit export --format signed-json 2>>"$LOGS/setup.log" ) | jq '.records | length'; }

# ---------------------------------------------------------------- CASE G — allowed read action, executed once
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations '{"operation_id":"op-read-live","action":"lookup_ticket","arguments":{"ticket_id":"T-1842"}}')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "201" ]] || die "CASE G expected 201 (operation created under the verified sandbox identity), got $CODE: $OUT"
[[ "$(json_field "$OUT" .operation.verdict)" == "ALLOW" ]] || die "CASE G verdict: $OUT"
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations/op-read-live/attempts '')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "200" && "$(json_field "$OUT" .attempt.status)" == "succeeded" ]] || die "CASE G claim: $CODE $OUT"
[[ "$(protected_count tickets)" == "1" ]] || die "CASE G protected tickets = $(protected_count tickets), want 1"
pass "CASE G allowed read action: sandbox authenticated through the hop with no Talon secret; protected service called exactly once"

# ---------------------------------------------------------------- CASE H — forbidden action
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations '{"operation_id":"op-del-live","action":"delete_customer","arguments":{"customer_id":"c-9"}}')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "403" && "$(json_field "$OUT" .operation.verdict)" == "DENY" ]] || die "CASE H expected 403 DENY, got $CODE: $OUT"
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations/op-del-live/attempts '')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "403" && "$(json_field "$OUT" .error.code)" == "policy_denied" ]] || die "CASE H claim on denied: $CODE $OUT"
[[ "$(protected_count customers)" == "0" ]] || die "CASE H a forbidden action reached the protected service"
pass "CASE H forbidden action: DENY evidenced, zero dispatch, claim refused"

# ---------------------------------------------------------------- CASE I — approval-required action, approved, executed once, replay-safe
REFUND='{"operation_id":"op-refund-live","action":"create_refund_request","arguments":{"ticket_id":"T-1842","amount":50.00,"currency":"EUR"}}'
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations "$REFUND")"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "202" && "$(json_field "$OUT" .operation.operation_status)" == "awaiting_approval" ]] || die "CASE I expected 202 awaiting_approval, got $CODE: $OUT"
APPROVAL_ID="$(json_field "$OUT" .operation.approval.id)"; [[ -n "$APPROVAL_ID" ]] || die "CASE I no approval id: $OUT"
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations/op-refund-live/attempts '')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "409" && "$(json_field "$OUT" .error.code)" == "approval_pending" ]] || die "CASE I claim before approval: $CODE $OUT"
OUT="$(sandbox_action "$SANDBOX_A" GET "/v1/approvals/$APPROVAL_ID" '')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "200" && "$(json_field "$OUT" .approval.status)" == "pending" ]] || die "CASE I approval read via hop: $CODE $OUT"
[[ "$(protected_count refunds)" == "0" ]] || die "CASE I refund dispatched before approval"
# The human reviewer decides from the HOST with the approver credential.
DEC="$(curl -sS -o "$WORK/decision.json" -w '%{http_code}' -X POST "http://127.0.0.1:$TALON_HTTP_PORT/v1/approvals/$APPROVAL_ID/decisions" -H "Authorization: Bearer $LEAD_KEY" -H 'content-type: application/json' --data '{"decision":"approve","reason":"verified with customer"}')"
[[ "$DEC" == "200" && "$(jq -r '.operation.operation_status' "$WORK/decision.json")" == "authorized" ]] || die "CASE I reviewer approve: $DEC $(cat "$WORK/decision.json")"
[[ "$(protected_count refunds)" == "0" ]] || die "CASE I the reviewer decision itself dispatched"
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations/op-refund-live/attempts '')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "200" && "$(json_field "$OUT" .attempt.status)" == "succeeded" ]] || die "CASE I approved claim: $CODE $OUT"
[[ "$(protected_count refunds)" == "1" ]] || die "CASE I protected refunds = $(protected_count refunds), want 1"
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations "$REFUND")"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "200" && "$(json_field "$OUT" .created)" == "false" ]] || die "CASE I exact replay: $CODE $OUT"
OUT="$(sandbox_action "$SANDBOX_A" POST /v1/action-operations/op-refund-live/attempts '')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "409" && "$(json_field "$OUT" .error.code)" == "operation_already_succeeded" ]] || die "CASE I second claim: $CODE $OUT"
[[ "$(protected_count refunds)" == "1" ]] || die "CASE I replay duplicated the effect"
grep -q '"idempotency_key": "talon-op_' <<<"$(protected_state)" || die "CASE I protected service saw no Talon idempotency key"
pass "CASE I approval-required action: zero dispatch until a human approved; approval alone dispatched nothing; sandbox claim executed exactly once; replay did not duplicate"

# ---------------------------------------------------------------- CASE J — unbound sandbox, action path
RECORDS_BEFORE="$(records_total)"
OUT="$(sandbox_action "$SANDBOX_B" POST /v1/action-operations '{"operation_id":"op-b-live","action":"lookup_ticket","arguments":{"ticket_id":"T-1"}}')"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "403" ]] || die "CASE J expected 403, got $CODE: $OUT"
grep -q '"workload_identity_unbound"' <<<"$OUT" || die "CASE J reason_code is not workload_identity_unbound: $OUT"
[[ "$(records_total)" == "$RECORDS_BEFORE" ]] || die "CASE J an unbound sandbox produced a Talon record"
[[ "$(protected_count tickets)" == "1" ]] || die "CASE J protected service reached for an unbound sandbox"
pass "CASE J unbound sandbox on the action path: denied at the hop, Talon's API never reached"

# ---------------------------------------------------------------- CASE K — sandbox-written assertion is overwritten; forged assertion direct to Talon refused
OUT="$(TALON_EXTRA_HEADER='X-Talon-Workload-Assertion: v1.eyJhZ2VudCI6Im90aGVyLWFnZW50IiwidGVuYW50IjoiYWNtZSJ9.Zm9yZ2Vk' sandbox_action "$SANDBOX_A" GET /v1/action-operations/op-refund-live '' --env "TALON_EXTRA_HEADER=X-Talon-Workload-Assertion: v1.eyJhZ2VudCI6Im90aGVyLWFnZW50IiwidGVuYW50IjoiYWNtZSJ9.Zm9yZ2Vk")"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "200" && "$(json_field "$OUT" .operation.operation_status)" == "succeeded" ]] || die "CASE K the hop did not overwrite the sandbox-written assertion (expected the verified sandbox's own operation): $CODE $OUT"
DIRECT="$(curl -sS -o "$WORK/forged.json" -w '%{http_code}' "http://127.0.0.1:$TALON_HTTP_PORT/v1/action-operations/op-refund-live" -H 'X-Talon-Workload-Assertion: v1.eyJhZ2VudCI6InNhbmRib3hlZC1zdXBwb3J0In0.Zm9yZ2Vk')"
[[ "$DIRECT" == "401" && "$(jq -r '.error.code' "$WORK/forged.json")" == "workload_identity_invalid" ]] || die "CASE K forged assertion direct to Talon: $DIRECT $(cat "$WORK/forged.json")"
pass "CASE K assertion header: sandbox-written value overwritten at the hop; forged assertion refused at Talon's ingress"

# ---------------------------------------------------------------- CASE L — direct egress to the protected service blocked by OpenShell
OUT="$("${CLI[@]}" sandbox exec --name "$SANDBOX_A" --no-tty --no-login-shell --timeout 60 -- "$SH_BIN" -c 'out=$('"$CURL_BIN"' -sS --max-time 20 -w "\n__CODE__%{http_code}" -X POST "http://host.openshell.internal:'"$PROTECTED_PORT"'/refunds" -H "content-type: application/json" --data "{}" 2>&1); echo "${out##*__CODE__}"; printf "%s\n" "${out%__CODE__*}"' 2>>"$LOGS/setup.log" || true)"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" != "201" && "$CODE" != "200" ]] || die "CASE L the sandbox reached the protected service directly: $OUT"
[[ "$(protected_count refunds)" == "1" ]] || die "CASE L protected refunds changed on a direct sandbox call"
pass "CASE L direct egress to the protected service blocked by OpenShell network policy (code ${CODE:-none}); count unchanged"

# ---------------------------------------------------------------- CASE M — reviewer route unreachable through the hop
OUT="$(sandbox_action "$SANDBOX_A" POST "/v1/approvals/$APPROVAL_ID/decisions" '{"decision":"approve"}' --env "TALON_EXTRA_HEADER=Authorization: Bearer $LEAD_KEY")"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" == "403" ]] || die "CASE M expected 403 from the hop, got $CODE: $OUT"
grep -q '"self_destination_path_not_governed"' <<<"$OUT" || die "CASE M reason_code is not self_destination_path_not_governed: $OUT"
pass "CASE M reviewer route: unreachable through the hop even with a reviewer credential"

# ---------------------------------------------------------------- CASE N — reference sandbox agent, end to end
# The checked-in reference agent (examples/openshell/sandbox-agent.sh) runs
# INSIDE the real sandbox with sh+curl+sed only: model call, governed read,
# consequential refund → waits for a human → resumes → exactly one effect →
# replay-safe. The host plays the reviewer while the agent waits.
AGENT_SCRIPT="$(cat "$ROOT/examples/openshell/sandbox-agent.sh")"
AGENT_OUT="$WORK/agent-out.txt"; : >"$AGENT_OUT"
REFUNDS_BEFORE="$(protected_count refunds)"
"${CLI[@]}" sandbox exec --name "$SANDBOX_A" --no-tty --no-login-shell --timeout 300 \
  --env "TALON_BASE=http://host.openshell.internal:$TALON_HTTP_PORT" --env "PROVIDER_BASE=http://host.openshell.internal:$MOCK_PORT" \
  --env "TALON_SESSION=$SESSION" --env "OPERATION_ID=refund-agent-live" --env "APPROVAL_WAIT_S=120" \
  -- "$SH_BIN" -c "$AGENT_SCRIPT" >"$AGENT_OUT" 2>>"$LOGS/setup.log" &
AGENT_PID=$!
AGENT_APPROVAL=""
for ((i=0; i<120; i++)); do
  AGENT_APPROVAL="$(sed -n 's/^APPROVAL_ID=//p' "$AGENT_OUT" | head -n1)"
  [[ -n "$AGENT_APPROVAL" ]] && break
  kill -0 "$AGENT_PID" 2>/dev/null || break
  sleep 1
done
[[ -n "$AGENT_APPROVAL" ]] || { wait "$AGENT_PID" || true; die "CASE N the reference agent did not reach the approval step: $(cat "$AGENT_OUT")"; }
[[ "$(protected_count refunds)" == "$REFUNDS_BEFORE" ]] || die "CASE N refund dispatched before the human decided"
DEC="$(curl -sS -o "$WORK/decision-n.json" -w '%{http_code}' -X POST "http://127.0.0.1:$TALON_HTTP_PORT/v1/approvals/$AGENT_APPROVAL/decisions" -H "Authorization: Bearer $LEAD_KEY" -H 'content-type: application/json' --data '{"decision":"approve","reason":"reference agent run"}')"
[[ "$DEC" == "200" ]] || die "CASE N reviewer approve: $DEC $(cat "$WORK/decision-n.json")"
wait "$AGENT_PID" || die "CASE N the reference agent exited non-zero: $(cat "$AGENT_OUT")"
grep -q '^MODEL=ok$' "$AGENT_OUT" || die "CASE N model step: $(cat "$AGENT_OUT")"
grep -q '^READ=succeeded' "$AGENT_OUT" || die "CASE N read step: $(cat "$AGENT_OUT")"
grep -q '^APPROVAL=approved$' "$AGENT_OUT" || die "CASE N approval step: $(cat "$AGENT_OUT")"
grep -q '^ATTEMPT=succeeded$' "$AGENT_OUT" || die "CASE N claim step: $(cat "$AGENT_OUT")"
grep -q '^REPLAY=operation_already_succeeded$' "$AGENT_OUT" || die "CASE N replay step: $(cat "$AGENT_OUT")"
grep -q '^RESULT=succeeded$' "$AGENT_OUT" || die "CASE N result: $(cat "$AGENT_OUT")"
[[ "$(protected_count refunds)" == "$((REFUNDS_BEFORE + 1))" ]] || die "CASE N protected refunds = $(protected_count refunds), want $((REFUNDS_BEFORE + 1))"
( cd "$TALON_HOME" && "$TALON" audit verify --operation refund-agent-live ) >>"$LOGS/setup.log" 2>&1 || die "CASE N audit verify --operation refund-agent-live"
pass "CASE N reference sandbox agent: model → governed read → refund awaiting a human → approved from the host → exactly one effect → replay-safe; lifecycle VALID"

# ---------------------------------------------------------------- evidence and secret hygiene
EXPORT="$WORK/export.json"
( cd "$TALON_HOME" && "$TALON" audit export --format signed-json ) >"$EXPORT" 2>>"$LOGS/setup.log" || die "talon audit export"
# signed-json is an envelope: {"export_metadata":…, "records":[<evidence>…]}.
DELEGATED="$(jq '[.records[] | select(.enforcement.provenance=="delegated_expected" and .enforcement.mechanism=="delegate" and .enforcement.boundary=="external_runtime" and .enforcement.decision_authority=="talon" and .enforcement.decision_returned_via=="openshell_middleware")] | length' "$EXPORT")"
[[ "${DELEGATED:-0}" -ge 3 ]] || die "expected >=3 delegated_expected records, found ${DELEGATED:-0}"
VERIFIED="$(jq '[.records[] | select(.workload_identity.status=="verified" and .workload_identity.runtime=="openshell" and .upstream_auth_mode=="external_runtime")] | length' "$EXPORT")"
[[ "${VERIFIED:-0}" -ge 3 ]] || die "expected >=3 verified openshell identity records with external_runtime auth mode, found ${VERIFIED:-0}"
# The verified identity must be the REAL gateway's token for the REAL sandbox:
# issuer "openshell-gateway:<gateway_id>" (the gateway_jwt registration) and
# subject spiffe://openshell/sandbox/<id as reported by the released CLI>.
REAL_ID="$(jq --arg iss "openshell-gateway:$GATEWAY_ID" --arg sub "spiffe://openshell/sandbox/$SANDBOX_A_ID" '[.records[] | select(.workload_identity.status=="verified" and .workload_identity.issuer==$iss and .workload_identity.subject==$sub)] | length' "$EXPORT")"
[[ "${REAL_ID:-0}" -ge 3 ]] || die "expected >=3 records verified for issuer openshell-gateway:$GATEWAY_ID and subject spiffe://openshell/sandbox/$SANDBOX_A_ID, found ${REAL_ID:-0}"
jq -e '[.records[] | select(.enforcement.provenance=="talon_enforced" and .workload_identity.runtime=="openshell")] | length == 0' "$EXPORT" >/dev/null || die "a delegated decision was labelled talon_enforced"
ALLOW_ID="$(jq -r '[.records[] | select(.enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true)][0].id // empty' "$EXPORT")"
[[ -n "$ALLOW_ID" ]] || die "no allowed delegated record id found"
( cd "$TALON_HOME" && "$TALON" audit verify "$ALLOW_ID" ) >>"$LOGS/setup.log" 2>&1 || die "talon audit verify $ALLOW_ID"
if grep -rqF "$PROVIDER_SECRET" "$TALON_HOME" "$LOGS/talon-serve.log" "$EXPORT" 2>/dev/null; then die "provider secret found in Talon state, evidence or logs"; fi
grep -qF "$TALON_VAULT_DECOY" <<<"$(provider_state)" && die "Talon's vault value reached the provider"
pass "evidence: $DELEGATED delegated_expected records, identity verified for the real gateway and sandbox ($SANDBOX_A_ID), offline verification OK, provider secret absent from Talon"
# Response settlements: every allowed model decision booked no cost
# (awaiting_settlement) and has exactly one gateway_response record under
# the same correlation id carrying the mock provider's real usage (12/3)
# priced from the table; no estimate is counted next to an actual.
DECISIONS_ALLOWED="$(jq '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true)] | length' "$EXPORT")"
AWAITING="$(jq '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true and .execution.pricing_basis=="awaiting_settlement" and .execution.cost==0)] | length' "$EXPORT")"
[[ "$AWAITING" == "$DECISIONS_ALLOWED" && "${AWAITING:-0}" -ge 3 ]] || die "allowed decisions=$DECISIONS_ALLOWED but awaiting_settlement records=$AWAITING (every allowed delegated decision must defer its cost to the settlement)"
SETTLED="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .execution.tokens.input==12 and .execution.tokens.output==3 and .execution.cost>0 and .execution.pricing_basis!="awaiting_settlement" and .execution.pricing_basis!="estimate_no_usage" and .execution.pricing_basis!="estimate_unsettled" and (.gateway_annotations|index("response_observed")!=null))] | length' "$EXPORT")"
[[ "$SETTLED" == "$DECISIONS_ALLOWED" ]] || die "settled responses with the provider's actual usage=$SETTLED, want $DECISIONS_ALLOWED"
JOINED="$(jq '[.records[] | select(.invocation_type=="gateway" and .policy_decision.allowed==true and .enforcement.provenance=="delegated_expected") | .correlation_id] as $c | [.records[] | select(.invocation_type=="gateway_response" and (.correlation_id as $x | $c | index($x)) != null)] | length' "$EXPORT")"
[[ "$JOINED" == "$DECISIONS_ALLOWED" ]] || die "settlements joined to their decision by correlation id=$JOINED, want $DECISIONS_ALLOWED"
jq -e '[.records[] | select(.invocation_type=="gateway_response" and (.gateway_annotations|index("decision_unmatched")!=null))] | length == 0' "$EXPORT" >/dev/null || die "a settlement lost its request half"
pass "evidence: $SETTLED response settlements carry the provider's actual usage (12/3) priced from the table under their decision's correlation id; decisions booked 0 while awaiting settlement"
# Action lifecycle records: the REAL sandbox identity verified through the
# hop, Talon-enforced execution with the runtime reference, the session spine
# shared with the model records, lifecycle verification, and no credential.
ACTION_IDENTIFIED="$(jq --arg sub "spiffe://openshell/sandbox/$SANDBOX_A_ID" --arg iss "openshell-gateway:$GATEWAY_ID" '[.records[] | select(.invocation_type=="action_lifecycle" and .workload_identity.status=="verified" and .workload_identity.runtime=="openshell" and .workload_identity.auth_method=="workload_hop_assertion" and .workload_identity.subject==$sub and .workload_identity.issuer==$iss and .enforcement.provenance=="talon_enforced" and .enforcement.runtime.reference==$"'"$SANDBOX_A_ID"'" and .action_lifecycle.identity_source=="workload_asserted")] | length' "$EXPORT")"
[[ "${ACTION_IDENTIFIED:-0}" -ge 8 ]] || die "expected >=8 action lifecycle records carrying the verified sandbox identity, found ${ACTION_IDENTIFIED:-0}"
SESSION_MODEL="$(jq --arg s "$SESSION" '[.records[] | select(.session_id==$s and .invocation_type=="gateway")] | length' "$EXPORT")"
SESSION_ACTIONS="$(jq --arg s "$SESSION" '[.records[] | select(.session_id==$s and .invocation_type=="action_lifecycle")] | length' "$EXPORT")"
[[ "${SESSION_MODEL:-0}" -ge 3 && "${SESSION_ACTIONS:-0}" -ge 8 ]] || die "session join: model=$SESSION_MODEL actions=$SESSION_ACTIONS records on session $SESSION (want >=3 and >=8)"
jq -e '[.records[] | select(.invocation_type=="action_lifecycle" and .workload_identity.runtime=="openshell" and .action_lifecycle.identity_source=="caller_provided")] | length == 0' "$EXPORT" >/dev/null || die "a hop-established operation was labelled caller_provided"
( cd "$TALON_HOME" && "$TALON" audit verify --operation op-refund-live ) >>"$LOGS/setup.log" 2>&1 || die "talon audit verify --operation op-refund-live"
( cd "$TALON_HOME" && "$TALON" audit verify --operation op-del-live ) >>"$LOGS/setup.log" 2>&1 || die "talon audit verify --operation op-del-live"
if grep -qF "$LEAD_KEY" "$EXPORT" "$LOGS/talon-serve.log" 2>/dev/null; then die "reviewer credential found in evidence or logs"; fi
if grep -qE '"X-Talon-Workload-Assertion"|v1\.eyJ[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{40,}' "$EXPORT" "$LOGS/talon-serve.log" 2>/dev/null; then die "workload assertion material found in evidence or logs"; fi
pass "evidence: $ACTION_IDENTIFIED action records carry the verified sandbox identity (talon_enforced, runtime ref $SANDBOX_A_ID); session $SESSION joins $SESSION_MODEL model and $SESSION_ACTIONS action records; lifecycle verification VALID; no reviewer credential or assertion material in Talon's export or logs"

# ---------------------------------------------------------------- log hygiene
# Only $LOGS is ever collected by CI. Prove it carries no secret material:
# provider key, Talon keys, the gateway's or Talon's private keys, or any
# bearer token value.
hygiene_check() {
  local leak=0 needle
  for needle in "$PROVIDER_SECRET" "$TALON_SECRETS_KEY" "$TALON_SIGNING_KEY" "$TALON_ADMIN_KEY" "$LEAD_KEY" "PRIVATE KEY-----" "Bearer ey"; do
    if grep -rqF -- "$needle" "$LOGS" 2>/dev/null; then echo "HYGIENE secret-shaped material found in logs: $(printf '%s' "$needle" | cut -c1-12)…" >&2; leak=1; fi
  done
  return $leak
}
hygiene_check || die "log hygiene check failed"
pass "log hygiene: collected logs carry no provider secret, Talon key, private key or bearer token"

# ---------------------------------------------------------------- record environment
cat <<EOT
ALL PASS openshell live smoke
  openshell cli:      $("$CLI_BIN" --version)   sha256 ${CLI_SHA[$ARCH]}
  openshell gateway:  $("$GW_BIN" --version)   sha256 ${GW_SHA[$ARCH]}
  talon commit:       $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo untracked)
  driver:             docker $(docker version --format '{{.Server.Version}}') on $(uname -r) ($ARCH)
  workload image:     $WORKLOAD_IMAGE
  resolved digests:   $RESOLVED_DIGESTS
  sandbox binaries:   curl=$DETECTED_CURL sh=$DETECTED_SH sleep=$DETECTED_SLEEP ($CURL_VERSION_LINE)
  openshell images:   $(docker ps -a --format '{{.Image}}' | grep -i openshell | sort -u | tr '\n' ' ')
  host address:       $HOST_IP (talon middleware https://$HOST_IP:$TALON_GRPC_PORT, talon http :$TALON_HTTP_PORT, mock provider :$MOCK_PORT, protected service :$PROTECTED_PORT)
  action cases:       G allow=1 dispatch, H deny=0, I approval→1 dispatch (replay 0), J unbound, K assertion overwrite/forgery, L direct egress blocked, M reviewer route closed, N reference agent end to end
  ocsf (gateway):     $LOGS/gateway-ocsf.jsonl ($(wc -l <"$LOGS/gateway-ocsf.jsonl" 2>/dev/null || echo 0) lines)
EOT

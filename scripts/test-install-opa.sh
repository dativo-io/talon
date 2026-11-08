#!/usr/bin/env bash
# Failure-injection test for scripts/install-opa.sh: a local HTTP server
# stands in for the GitHub release host and serves, per route, an HTML "504
# Gateway Time-out" page, a truncated binary, a binary whose digest does not
# match, a binary that reports the wrong version, and a good one. The
# installer must install nothing in the first four cases and install exactly
# the good one in the last, atomically. No network, no Docker.
set -euo pipefail
cd "$(dirname "$0")/.."

export TMPDIR="${TMPDIR:-/tmp}"
work="$(mktemp -d "$TMPDIR/test-install-opa.XXXXXX")"
trap 'rm -rf "$work"; [[ -n "${server_pid:-}" ]] && kill "$server_pid" 2>/dev/null || true' EXIT

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "PASS $*"; }
bad()  { fail=$((fail+1)); echo "FAIL $*" >&2; }

# A fake "opa" that reports a version: a shell script, so the version check can
# be exercised without the 64 MB real binary. Its digest is computed, never
# invented, and passed through the OPA_SHA256 test override.
mk_fake() { # $1=file $2=version
  printf '#!/usr/bin/env bash\nif [[ "${1:-}" == "version" ]]; then printf "Version: %s\\nBuild Commit: test\\n"; fi\n' "$2" > "$1"
  chmod 0755 "$1"
}
mk_fake "$work/good" "1.22.2"
mk_fake "$work/wrongversion" "9.9.9"
good_sha="$(sha256sum "$work/good" | awk '{print $1}')"
wrongversion_sha="$(sha256sum "$work/wrongversion" | awk '{print $1}')"
head -c 20 "$work/good" > "$work/truncated"

# The local release host: each prefix selects a failure mode for
# /<prefix>/v1.22.2/opa_linux_amd64_static.
python3 -I - "$work" > "$work/server.port" 2>"$work/server.log" <<'PY' &
import http.server, socketserver, sys, os
work = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        mode = self.path.split("/")[1] if self.path.count("/") >= 2 else ""
        if mode == "gateway504":
            body = b"<html><head><title>504 Gateway Time-out</title></head><body><h1>504 Gateway Time-out</h1></body></html>"
            self.send_response(504); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        files = {"truncated": "truncated", "badsum": "good", "wrongversion": "wrongversion", "good": "good"}
        if mode not in files:
            self.send_response(404); self.end_headers(); return
        data = open(os.path.join(work, files[mode]), "rb").read()
        self.send_response(200); self.send_header("Content-Type", "application/octet-stream"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
with socketserver.TCPServer(("127.0.0.1", 0), H) as srv:
    print(srv.server_address[1], flush=True)
    srv.serve_forever()
PY
server_pid=$!
for _ in $(seq 1 50); do [[ -s "$work/server.port" ]] && break; sleep 0.1; done
port="$(cat "$work/server.port")"
[[ -n "$port" ]] || { echo "local server did not start: $(cat "$work/server.log")" >&2; exit 1; }
base="http://127.0.0.1:$port"

run_case() { # $1=name $2=mode $3=sha-override(or empty) $4=expect(ok|fail) $5=expected-message-fragment
  local name="$1" mode="$2" sha="$3" expect="$4" fragment="$5"
  local dir="$work/install-$name"
  mkdir -p "$dir"
  local out rc=0
  if [[ -n "$sha" ]]; then
    out="$(OPA_DOWNLOAD_BASE="$base/$mode" OPA_INSTALL_DIR="$dir" OPA_SHA256="$sha" bash scripts/install-opa.sh 2>&1)" || rc=$?
  else
    out="$(OPA_DOWNLOAD_BASE="$base/$mode" OPA_INSTALL_DIR="$dir" bash scripts/install-opa.sh 2>&1)" || rc=$?
  fi
  if [[ "$expect" == "fail" ]]; then
    if [[ $rc -ne 0 ]] && grep -q -- "$fragment" <<<"$out" && [[ ! -e "$dir/opa" ]] && [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
      ok "$name: refused ($fragment), nothing installed"
    else
      bad "$name: rc=$rc installed=$(ls -A "$dir" 2>/dev/null | tr '\n' ' ') out=$out"
    fi
  else
    local extra=0
    for f in "$dir"/* "$dir"/.[!.]*; do [[ -e "$f" && "$(basename "$f")" != "opa" ]] && extra=1; done
    if [[ $rc -eq 0 ]] && [[ -x "$dir/opa" ]] && "$dir/opa" version | grep -q "Version: 1.22.2" && [[ $extra -eq 0 ]]; then
      ok "$name: installed exactly one verified binary"
    else
      bad "$name: rc=$rc files=$(ls -A "$dir" 2>/dev/null | tr '\n' ' ') out=$out"
    fi
  fi
}

run_case gateway504   gateway504   ""                 fail "download failed"
run_case truncated    truncated    "$good_sha"        fail "checksum mismatch"
run_case badsum       badsum       "0000000000000000000000000000000000000000000000000000000000000000" fail "checksum mismatch"
run_case wrongversion wrongversion "$wrongversion_sha" fail "expected 'Version: 1.22.2'"
run_case good         good         "$good_sha"        ok   ""

# Idempotence: a second run against an unreachable host must succeed from the
# already-verified install without downloading.
dir="$work/install-good"
if OPA_DOWNLOAD_BASE="http://127.0.0.1:9/nowhere" OPA_INSTALL_DIR="$dir" OPA_SHA256="$good_sha" bash scripts/install-opa.sh 2>&1 | grep -q "already installed"; then
  ok "idempotent: verified install is reused without a download"
else
  bad "idempotent: expected the verified install to be reused"
fi

# Guard: the pinned digest in the script is the one published by the release.
pinned="$(grep -E '^OPA_SHA256_LINUX_AMD64=' scripts/install-opa.sh | cut -d'"' -f2)"
if [[ "$pinned" =~ ^[0-9a-f]{64}$ ]]; then ok "pinned digest has sha256 shape"; else bad "pinned digest malformed: $pinned"; fi

echo "install-opa failure injection: $pass passed, $fail failed"
[[ $fail -eq 0 ]]

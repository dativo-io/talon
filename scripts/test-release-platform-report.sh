#!/usr/bin/env bash
# Offline test of scripts/release-platform-report.sh (#359): the platform
# assets report must state, for each darwin archive, present-and-verified or
# the exact reason it is absent — a macOS runner that was never acquired is
# a different statement from a build that FAILED — and must refuse (exit 1)
# a release whose required linux/amd64 archive is missing or wrong, or whose
# darwin job succeeded but left no archive.
#
#   R1  linux + both darwin archives present, jobs succeeded          → exit 0, "present" x3
#   R2  darwin/amd64 cancelled while queued (no runner, no step ran)   → exit 0, "macOS runner not acquired", ::warning
#   R3  darwin/amd64 failed at "Build and package"                    → exit 0, "build FAILED at step", ::error (never "not acquired")
#   R4  darwin/amd64 cancelled after it started                        → exit 0, "cancelled after it started"
#   R5  no job data                                                     → exit 0, "no job data (reason unknown)"
#   R6  linux archive missing                                           → exit 1
#   R7  linux archive present but checksums.txt disagrees               → exit 1
#   R8  darwin job succeeded but the archive is absent                  → exit 1, ::error
#   R9  --out writes the same markdown; relative --assets-dir works
#   R10 annotations (::warning::/::error::) go to the console (stderr) only:
#       never into the markdown on stdout or in --out, which the release
#       workflow appends to the release notes
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="$ROOT/scripts/release-platform-report.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/talon-platform-report-test.XXXXXX")"
trap 'rm -rf "${WORK:?}"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }
V="0.0.0-report"; TAG="v$V"

make_assets() { # dir [darwin archs...]
  local d="$1"; shift; rm -rf "${d:?}"; mkdir -p "$d"
  printf 'linux binary %s\n' "$RANDOM" >"$d/talon_${V}_linux_amd64.tar.gz"
  (cd "$d" && sha256sum "talon_${V}_linux_amd64.tar.gz" >checksums.txt)
  for arch in "$@"; do
    printf 'darwin %s binary\n' "$arch" >"$d/talon_${V}_darwin_${arch}.tar.gz"
    (cd "$d" && sha256sum "talon_${V}_darwin_${arch}.tar.gz" >"talon_${V}_darwin_${arch}.tar.gz.sha256")
  done
}
job() { # arch conclusion runner steps-json
  printf '{"name": "Darwin binaries (%s)", "run_attempt": 1, "conclusion": %s, "runner_name": %s, "steps": %s}' "$1" "$2" "$3" "$4"
}
jobs_json() { printf '{"jobs": [%s]}' "$(IFS=,; echo "$*")" >"$WORK/jobs.json"; echo "$WORK/jobs.json"; }
STEPS_OK='[{"name":"Set up job","conclusion":"success"},{"name":"Build and package (darwin/amd64)","conclusion":"success"},{"name":"Upload to the draft","conclusion":"success"}]'
STEPS_FAIL='[{"name":"Set up job","conclusion":"success"},{"name":"Build and package (darwin/amd64)","conclusion":"failure"},{"name":"Upload to the draft","conclusion":"skipped"}]'
STEPS_QUEUED='[{"name":"Set up job","conclusion":null},{"name":"Build and package (darwin/amd64)","conclusion":null}]'
STEPS_CANCELLED='[{"name":"Set up job","conclusion":"success"},{"name":"Build and package (darwin/amd64)","conclusion":"cancelled"}]'
# OUT holds the markdown (stdout); ERR holds the console annotations (stderr).
run() { OUT="$WORK/out.md"; ERR="$WORK/out.err"; set +e; bash "$REPORT" "$@" >"$OUT" 2>"$ERR"; RC=$?; set -e; }
no_annotations_in_markdown() { if grep -q '^::' "$OUT"; then echo "--- markdown:" >&2; cat "$OUT" >&2; fail "$1: workflow annotations leaked into the markdown report"; fi; }

# R1
make_assets "$WORK/a1" arm64 amd64
J="$(jobs_json "$(job arm64 '"success"' '"mac-1"' "$STEPS_OK")" "$(job amd64 '"success"' '"mac-2"' "$STEPS_OK")")"
run --tag "$TAG" --assets-dir "$WORK/a1" --jobs-json "$J" --annotate
[[ "$RC" == 0 ]] || { cat "$OUT"; fail "R1 must exit 0"; }
grep -q '| linux/amd64 | .* | present, required, sha256' "$OUT" || fail "R1 linux row"
[[ "$(grep -c 'present, best effort, `.sha256` verified (job succeeded)' "$OUT")" == 2 ]] || { cat "$OUT"; fail "R1 darwin rows"; }
grep -q '^::' "$ERR" && fail "R1 must not annotate"
no_annotations_in_markdown R1
pass "R1 all archives present and verified"

# R2
make_assets "$WORK/a2" arm64
J="$(jobs_json "$(job arm64 '"success"' '"mac-1"' "$STEPS_OK")" "$(job amd64 '"cancelled"' 'null' "$STEPS_QUEUED")")"
run --tag "$TAG" --assets-dir "$WORK/a2" --jobs-json "$J" --annotate
[[ "$RC" == 0 ]] || { cat "$OUT"; fail "R2 must exit 0 (linux present)"; }
grep -q '| darwin/amd64 | .* | absent — macOS runner not acquired (job cancelled while queued, no step ran); macOS installs from source' "$OUT" || { cat "$OUT"; fail "R2 not-acquired row"; }
grep -q '^::warning::darwin/amd64 archive absent: macOS runner not acquired' "$ERR" || fail "R2 warning annotation on the console"
no_annotations_in_markdown R2
grep -q 'FAILED' "$OUT" && fail "R2 must not call a queued cancellation a failure"
pass "R2 a macOS runner that was never acquired is reported as such, with a warning, and does not block"

# R3
J="$(jobs_json "$(job arm64 '"success"' '"mac-1"' "$STEPS_OK")" "$(job amd64 '"failure"' '"mac-2"' "$STEPS_FAIL")")"
run --tag "$TAG" --assets-dir "$WORK/a2" --jobs-json "$J" --annotate
[[ "$RC" == 0 ]] || { cat "$OUT"; fail "R3 must exit 0 (darwin is best effort; the workflow documents the decision)"; }
grep -q '| darwin/amd64 | .* | absent — build FAILED at step "Build and package (darwin/amd64)" (a real macOS build or upload failure, not a runner-availability issue; fix forward) |' "$OUT" || { cat "$OUT"; fail "R3 failed-build row"; }
grep -q '^::error::darwin/amd64 archive absent: build FAILED' "$ERR" || fail "R3 error annotation on the console"
no_annotations_in_markdown R3
grep -q 'not acquired' "$OUT" && fail "R3 a failed build must never be described as an unavailable runner"
pass "R3 a failed macOS build is reported as a build failure with an error annotation, never as an unavailable runner"

# R4
J="$(jobs_json "$(job arm64 '"success"' '"mac-1"' "$STEPS_OK")" "$(job amd64 '"cancelled"' '"mac-2"' "$STEPS_CANCELLED")")"
run --tag "$TAG" --assets-dir "$WORK/a2" --jobs-json "$J"
if [[ "$RC" != 0 ]] || ! grep -q 'absent — job cancelled after it started (at step "Build and package (darwin/amd64)")' "$OUT"; then cat "$OUT"; fail "R4 cancelled-after-start row"; fi
pass "R4 a cancellation after the job started names the step"

# R5
run --tag "$TAG" --assets-dir "$WORK/a2"
if [[ "$RC" != 0 ]] || ! grep -q 'absent — no job data (reason unknown)' "$OUT"; then cat "$OUT"; fail "R5 no job data"; fi
pass "R5 without job data the absence is stated with an unknown reason"

# R6
make_assets "$WORK/a6" arm64 amd64; rm -f "$WORK/a6/talon_${V}_linux_amd64.tar.gz"
run --tag "$TAG" --assets-dir "$WORK/a6"
if [[ "$RC" != 1 ]] || ! grep -q 'ABSENT — the required archive is missing' "$OUT"; then cat "$OUT"; fail "R6 missing linux archive must exit 1"; fi
pass "R6 a missing linux/amd64 archive fails the report"

# R7
make_assets "$WORK/a7" arm64 amd64; printf 'x' >>"$WORK/a7/talon_${V}_linux_amd64.tar.gz"
run --tag "$TAG" --assets-dir "$WORK/a7"
if [[ "$RC" != 1 ]] || ! grep -q 'present but checksums.txt disagrees' "$OUT"; then cat "$OUT"; fail "R7 checksum disagreement must exit 1"; fi
pass "R7 a linux archive that disagrees with checksums.txt fails the report"

# R8
J="$(jobs_json "$(job arm64 '"success"' '"mac-1"' "$STEPS_OK")" "$(job amd64 '"success"' '"mac-2"' "$STEPS_OK")")"
run --tag "$TAG" --assets-dir "$WORK/a2" --jobs-json "$J" --annotate
if [[ "$RC" != 1 ]] || ! grep -q 'ABSENT although the darwin job succeeded' "$OUT" || ! grep -q '^::error::darwin/amd64: job succeeded but' "$ERR"; then cat "$OUT" "$ERR"; fail "R8 succeeded-but-absent must exit 1 with an error"; fi
no_annotations_in_markdown R8
pass "R8 a darwin job that succeeded without leaving an archive fails the report"

# R9
mkdir -p "$WORK/r9"; cp -r "$WORK/a1" "$WORK/r9/assets"
set +e; (cd "$WORK/r9" && bash "$REPORT" --tag "$TAG" --assets-dir assets --out report.md) >"$WORK/r9.out" 2>"$WORK/r9.err"; RC=$?; set -e
[[ "$RC" == 0 && -s "$WORK/r9/report.md" ]] || { cat "$WORK/r9.out"; fail "R9 relative paths and --out"; }
cmp -s "$WORK/r9/report.md" "$WORK/r9.out" || fail "R9 --out must equal stdout"
if ! grep -q '^## Platform assets' "$WORK/r9/report.md" || ! grep -q 'Supported installer path: \*\*linux/amd64\*\*' "$WORK/r9/report.md"; then fail "R9 report header"; fi
pass "R9 --out writes the report; relative --assets-dir resolves against the caller's directory"

# R10: the --out file (what the workflow appends to the release notes) never carries annotations
J="$(jobs_json "$(job arm64 '"success"' '"mac-1"' "$STEPS_OK")" "$(job amd64 '"failure"' '"mac-2"' "$STEPS_FAIL")")"
run --tag "$TAG" --assets-dir "$WORK/a2" --jobs-json "$J" --annotate --out "$WORK/r10.md"
[[ "$RC" == 0 && -s "$WORK/r10.md" ]] || { cat "$OUT" "$ERR"; fail "R10 report with --annotate --out"; }
if grep -q '^::' "$WORK/r10.md"; then cat "$WORK/r10.md"; fail "R10 --out file (release notes) carries workflow annotations"; fi
cmp -s "$WORK/r10.md" "$OUT" || fail "R10 --out must equal the markdown on stdout"
grep -q '^::error::darwin/amd64 archive absent: build FAILED' "$ERR" || fail "R10 the annotation must still reach the console"
pass "R10 annotations stay on the console; the markdown report and --out file are clean"
echo "ALL PASS test-release-platform-report"

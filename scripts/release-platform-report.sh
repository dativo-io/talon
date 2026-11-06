#!/usr/bin/env bash
# Platform assets report for a release (#359): which platform archives this
# release carries, and — for the ones it does not — exactly why, so a
# missing darwin archive is never mistaken for a build that was never tried
# and a failed macOS build is never mistaken for an unavailable runner.
#
#   scripts/release-platform-report.sh --tag vX.Y.Z --assets-dir DIR
#       [--jobs-json FILE | --run-id ID [--repo OWNER/NAME]] [--out FILE] [--annotate]
#
# The supported installer path is linux/amd64: its archive is REQUIRED (the
# script exits 1 without it, or when its checksums.txt entry does not match)
# and the release workflow verifies it before publication. The darwin
# archives (arm64, amd64) are best effort: present when the macOS job built
# and uploaded them, absent otherwise. The reason for an absence is read
# from the run's jobs (GitHub Actions jobs API JSON, `--jobs-json` or
# `--run-id` via `gh api`):
#   - the job succeeded but the archive is absent     → inconsistency, exit 1
#   - the job failed                                   → "build FAILED at step …" (not a runner issue; fix forward)
#   - the job was cancelled before any step ran        → "macOS runner not acquired"
#   - the job was cancelled after it started           → "cancelled at step …"
#   - skipped / no job data                            → stated as such
# --annotate emits GitHub Actions annotations on STDERR (warning for an
# unavailable runner, error for a failed build; neither changes the exit
# status, the publication decision belongs to the workflow and is documented
# there). The markdown goes to stdout and to --out only; the workflow appends
# it to the release notes before publishing, so the release page states the
# platform truth for this version without workflow command lines in it.
set -euo pipefail
TAG=""; ASSETS_DIR=""; JOBS_JSON=""; JOBS_TMP=""; RUN_ID=""; REPO="${GITHUB_REPOSITORY:-dativo-io/talon}"; OUT=""; ANNOTATE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --assets-dir) ASSETS_DIR="$2"; shift 2 ;;
    --jobs-json) JOBS_JSON="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --annotate) ANNOTATE=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "release-platform-report: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$TAG" && -d "$ASSETS_DIR" ]] || { echo "release-platform-report: --tag and an existing --assets-dir are required" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "release-platform-report: jq is required" >&2; exit 2; }
ASSETS_DIR="$(cd "$ASSETS_DIR" && pwd -P)"
VERSION="${TAG#v}"
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

if [[ -z "$JOBS_JSON" && -n "$RUN_ID" ]]; then
  JOBS_JSON="$(mktemp "${TMPDIR:-/tmp}/release-jobs.XXXXXX.json")"; JOBS_TMP="$JOBS_JSON"
  gh api "repos/$REPO/actions/runs/$RUN_ID/jobs?per_page=100" >"$JOBS_JSON" || { echo "release-platform-report: cannot read the jobs of run $RUN_ID (needs actions: read)" >&2; exit 2; }
fi
if [[ -n "$JOBS_JSON" ]] && ! jq -e '.jobs | type == "array"' "$JOBS_JSON" >/dev/null 2>&1; then
  echo "release-platform-report: $JOBS_JSON is not a jobs listing" >&2; exit 2
fi

RC=0
REPORT="$(mktemp "${TMPDIR:-/tmp}/release-platform-report.XXXXXX")"
trap 'rm -f "${REPORT:?}" ${JOBS_TMP:+"$JOBS_TMP"}' EXIT
# Annotations go to the console (stderr) only: the markdown on stdout and in
# --out is appended to the release notes and must never carry `::` commands.
annotate() { if [[ "$ANNOTATE" == 1 ]]; then echo "::$1::$2" >&2; fi; }
job_state() { # arch -> one line describing the darwin job's outcome
  local arch="$1" job conclusion runner first_failed started_steps
  [[ -n "$JOBS_JSON" ]] || { echo "no job data (reason unknown)"; return; }
  job="$(jq -c --arg n "Darwin binaries ($arch)" '[.jobs[] | select(.name == $n)] | sort_by(.run_attempt // 0) | last // empty' "$JOBS_JSON")"
  [[ -n "$job" ]] || { echo "no darwin/$arch job in this run"; return; }
  conclusion="$(jq -r '.conclusion // "none"' <<<"$job")"
  runner="$(jq -r '.runner_name // ""' <<<"$job")"
  started_steps="$(jq -r '[.steps[]? | select(.conclusion != null and .conclusion != "skipped")] | length' <<<"$job")"
  first_failed="$(jq -r '[.steps[]? | select(.conclusion == "failure" or .conclusion == "cancelled")][0].name // ""' <<<"$job")"
  case "$conclusion" in
    success) echo "job succeeded" ;;
    failure) echo "build FAILED at step \"${first_failed:-unknown}\" (a real macOS build or upload failure, not a runner-availability issue; fix forward)" ;;
    cancelled)
      if [[ -z "$runner" && "$started_steps" == 0 ]]; then echo "macOS runner not acquired (job cancelled while queued, no step ran)"
      else echo "job cancelled after it started (at step \"${first_failed:-unknown}\")"; fi ;;
    skipped) echo "job skipped" ;;
    *) echo "job conclusion: $conclusion" ;;
  esac
}

{
  echo "## Platform assets"
  echo
  echo "Supported installer path: **linux/amd64** — the published archive is verified (checksum, executable version and commit, OpenShell showcase manifest) before this release is published, and \`scripts/install.sh\` installs it. The darwin archives are **best effort**: present when the macOS job built them, absent otherwise, as stated below for this release. macOS and arm64 Linux otherwise install from source (\`make install\` / \`go install\`)."
  echo
  echo "| Platform | Archive | State |"
  echo "|---|---|---|"
  linux="talon_${VERSION}_linux_amd64.tar.gz"
  if [[ -s "$ASSETS_DIR/$linux" ]]; then
    actual="$(sha256 "$ASSETS_DIR/$linux")"
    expected="$(awk -v n="$linux" '$2 == n {print $1}' "$ASSETS_DIR/checksums.txt" 2>/dev/null | head -n1 || true)"
    if [[ "$expected" == "$actual" ]]; then echo "| linux/amd64 | \`$linux\` | present, required, sha256 \`$actual\` matches checksums.txt |"
    else echo "| linux/amd64 | \`$linux\` | **present but checksums.txt disagrees** (\`${expected:-no entry}\` vs \`$actual\`) |"; RC=1; fi
  else
    echo "| linux/amd64 | \`$linux\` | **ABSENT — the required archive is missing; this release cannot be published** |"; RC=1
  fi
  for arch in arm64 amd64; do
    archive="talon_${VERSION}_darwin_${arch}.tar.gz"
    state="$(job_state "$arch")"
    if [[ -s "$ASSETS_DIR/$archive" ]]; then
      if [[ -s "$ASSETS_DIR/$archive.sha256" && "$(awk '{print $1}' "$ASSETS_DIR/$archive.sha256" | head -n1)" == "$(sha256 "$ASSETS_DIR/$archive")" ]]; then
        echo "| darwin/$arch | \`$archive\` | present, best effort, \`.sha256\` verified ($state) |"
      else
        echo "| darwin/$arch | \`$archive\` | **present but its .sha256 is missing or disagrees** ($state) |"; RC=1
      fi
    else
      case "$state" in
        "job succeeded") echo "| darwin/$arch | \`$archive\` | **ABSENT although the darwin job succeeded** — upload inconsistency, investigate before publishing |"; RC=1
                         annotate error "darwin/$arch: job succeeded but $archive is not on the release" ;;
        "build FAILED"*) echo "| darwin/$arch | \`$archive\` | absent — $state |"
                         annotate error "darwin/$arch archive absent: $state" ;;
        "macOS runner not acquired"*) echo "| darwin/$arch | \`$archive\` | absent — $state; macOS installs from source for this version |"
                         annotate warning "darwin/$arch archive absent: $state" ;;
        *) echo "| darwin/$arch | \`$archive\` | absent — $state |"
                         annotate warning "darwin/$arch archive absent: $state" ;;
      esac
    fi
  done
  echo
  echo "Not shipped as archives (install from source): linux/arm64, windows. Verify this release yourself: \`scripts/verify-release.sh --tag $TAG\`."
} >"$REPORT"
cat "$REPORT"
[[ -z "$OUT" ]] || cp "$REPORT" "$OUT"
exit "$RC"

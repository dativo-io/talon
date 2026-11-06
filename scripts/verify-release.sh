#!/usr/bin/env bash
# Verify a published Talon release from the artifacts a customer downloads
# (#359, #507): no checkout, no Go toolchain, no GitHub login — curl, tar,
# jq and sha256sum (or shasum) are all it needs. The same script is the
# release workflow's publication gate (assets already downloaded from the
# draft, --assets-dir) and its post-publication re-check of the public bytes.
#
#   scripts/verify-release.sh [--tag vX.Y.Z|latest] [--assets-dir DIR] [--work-dir DIR]
#                             [--install DIR] [--all-archives] [--skip-images]
#                             [--skip-commit] [--no-exec] [--summary-json FILE]
#
# Paths may be relative; they are resolved against the caller's working
# directory once, up front, and the script never changes directory.
#
# What it proves for linux/amd64, the gated installer path:
#   1. checksums.txt names the linux archive and its sha256 matches; every
#      *.sha256 asset present matches its file (the darwin archives when
#      --all-archives downloads them, or whatever --assets-dir holds).
#   2. The archive's `talon` is executable, `talon version` reports exactly
#      `Talon <version>` and the commit it was built from is the commit the
#      release tag points at.
#   3. The showcase manifest (`talon-openshell-showcase_<v>_linux_amd64.manifest.json`)
#      names this release, lists the released talon by the sha256 of the
#      executable (`artifacts.talon`), pins the agent image by this version,
#      is byte-identical to the manifest inside the bundle, and every helper
#      binary in the bundle matches its manifest digest.
#   4. (unless --skip-images) `ghcr.io/dativo-io/talon:<v>` and the
#      manifest's agent image are pullable WITHOUT credentials and the
#      registry reports a sha256 digest for each; the digests are printed.
#   5. (--install DIR) scripts/install.sh (next to this script, or
#      TALON_INSTALL_SH) installs this exact version into DIR and the
#      installed binary is byte-identical to the one verified above.
#
# Exit 0 only when every check passed. A failure names the asset and the
# reason: a FAIL is the honest state of a release (v1.15.0–v1.15.3 fail
# check 3: their manifests have no talon entry), never something to work
# around by editing the manifest. Nothing fails open: metadata that cannot
# be parsed, a tag whose commit cannot be resolved, a registry answer
# without a digest and a host that cannot execute the linux/amd64 binary
# (unless --no-exec is passed knowingly) are all failures.
#
# Environment (tests point them at a local server):
#   TALON_RELEASE_REPO           owner/name (default dativo-io/talon)
#   TALON_RELEASE_API_BASE       default https://api.github.com
#   TALON_RELEASE_DOWNLOAD_BASE  default https://github.com/<repo>/releases/download
#   TALON_REGISTRY_BASE          default https://ghcr.io (the anonymous token flow)
set -euo pipefail

REPO="${TALON_RELEASE_REPO:-dativo-io/talon}"
API_BASE="${TALON_RELEASE_API_BASE:-https://api.github.com}"
DOWNLOAD_BASE="${TALON_RELEASE_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"
REGISTRY_BASE="${TALON_REGISTRY_BASE:-https://ghcr.io}"
TAG="${TALON_RELEASE_TAG:-latest}"
ASSETS_DIR=""; WORK_DIR=""; INSTALL_DIR=""; ALL_ARCHIVES=0; SKIP_IMAGES=0; SKIP_COMMIT=0; NO_EXEC=0; SUMMARY_JSON=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --assets-dir) ASSETS_DIR="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    --install) INSTALL_DIR="$2"; shift 2 ;;
    --all-archives) ALL_ARCHIVES=1; shift ;;
    --skip-images) SKIP_IMAGES=1; shift ;;
    --skip-commit) SKIP_COMMIT=1; shift ;;
    --no-exec) NO_EXEC=1; shift ;;
    --summary-json) SUMMARY_JSON="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "verify-release: unknown argument $1" >&2; exit 2 ;;
  esac
done
for tool in curl jq tar; do command -v "$tool" >/dev/null 2>&1 || { echo "verify-release: $tool is required" >&2; exit 2; }; done
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
# Every path argument is made absolute here, once, against the caller's
# working directory; the script itself never changes directory, so a
# relative --work-dir, --assets-dir, --install or --summary-json means what
# the caller sees.
abs_dir() { mkdir -p "$1" && (cd "$1" && pwd -P); }
abs_file() { local d; d="$(abs_dir "$(dirname "$1")")" && printf '%s/%s' "$d" "$(basename "$1")"; }
if [[ -n "$ASSETS_DIR" ]]; then [[ -d "$ASSETS_DIR" ]] || { echo "verify-release: --assets-dir $ASSETS_DIR is not a directory" >&2; exit 2; }; ASSETS_DIR="$(cd "$ASSETS_DIR" && pwd -P)"; fi
[[ -z "$WORK_DIR" ]] || WORK_DIR="$(abs_dir "$WORK_DIR")"
[[ -z "$INSTALL_DIR" ]] || INSTALL_DIR="$(abs_dir "$INSTALL_DIR")"
[[ -z "$SUMMARY_JSON" ]] || SUMMARY_JSON="$(abs_file "$SUMMARY_JSON")"
[[ -z "${TALON_INSTALL_SH:-}" ]] || TALON_INSTALL_SH="$(abs_file "$TALON_INSTALL_SH")"

FAILURES=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*" >&2; FAILURES=$((FAILURES + 1)); }
info() { echo "INFO $*"; }
# GH_TOKEN / GITHUB_TOKEN, when present, authenticate the metadata reads only
# (anonymous api.github.com calls are rate-limited per IP; CI runners share
# IPs). Asset downloads and registry pulls are always anonymous.
API_AUTH=()
if [[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then API_AUTH=(-H "Authorization: Bearer ${GH_TOKEN:-${GITHUB_TOKEN:-}}"); fi
api() { curl -fsSL --retry 3 --retry-delay 2 -H 'Accept: application/vnd.github+json' "${API_AUTH[@]}" "$API_BASE/repos/$REPO/$1"; }

# ---------------------------------------------------------------- tag, version, release metadata
RELEASE_JSON=""; METADATA_INVALID=0
if [[ "$TAG" == "latest" ]]; then
  RELEASE_JSON="$(api releases/latest)" || { echo "verify-release: cannot resolve releases/latest" >&2; exit 2; }
  jq -e '.tag_name | type == "string"' <<<"$RELEASE_JSON" >/dev/null 2>&1 || { echo "verify-release: releases/latest did not return release metadata" >&2; exit 2; }
  TAG="$(jq -r .tag_name <<<"$RELEASE_JSON")"
else
  # A draft is invisible to anonymous metadata calls; --assets-dir mode may
  # legitimately run without it (the release workflow, before publication).
  RELEASE_JSON="$(api "releases/tags/$TAG" 2>/dev/null || true)"
  if [[ -n "$RELEASE_JSON" ]] && ! jq -e --arg t "$TAG" '.tag_name == $t and (.draft | type == "boolean")' <<<"$RELEASE_JSON" >/dev/null 2>&1; then
    METADATA_INVALID=1; RELEASE_JSON=""
  fi
fi
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "verify-release: tag must look like vX.Y.Z (got '$TAG')" >&2; exit 2; }
VERSION="${TAG#v}"
LINUX_ARCHIVE="talon_${VERSION}_linux_amd64.tar.gz"
BUNDLE_NAME="talon-openshell-showcase_${VERSION}_linux_amd64"
BUNDLE_ARCHIVE="$BUNDLE_NAME.tar.gz"
MANIFEST_NAME="$BUNDLE_NAME.manifest.json"
EXPECTED_AGENT_IMAGE="ghcr.io/dativo-io/talon-openshell-agent:${VERSION}"
TALON_IMAGE="ghcr.io/dativo-io/talon:${VERSION}"
echo "verify-release: $TAG (version $VERSION) from ${ASSETS_DIR:-$DOWNLOAD_BASE/$TAG}"
if [[ -n "$RELEASE_JSON" ]]; then
  info "release metadata: draft=$(jq -r .draft <<<"$RELEASE_JSON") prerelease=$(jq -r .prerelease <<<"$RELEASE_JSON") immutable=$(jq -r '.immutable // "unknown"' <<<"$RELEASE_JSON") published_at=$(jq -r '.published_at // "-"' <<<"$RELEASE_JSON")"
  if [[ "$(jq -r .draft <<<"$RELEASE_JSON")" != "false" ]]; then
    # The release workflow verifies the draft's assets (--assets-dir) before
    # publishing it; that is the one place a draft is expected.
    if [[ -n "$ASSETS_DIR" ]]; then info "release $TAG is a draft (pre-publication verification)"; else fail "release $TAG is still a draft: customers cannot download it"; fi
  fi
elif [[ "$METADATA_INVALID" == 1 ]]; then
  fail "release metadata for $TAG is not a release object for that tag (unparseable or for another tag)"
else
  info "release metadata: unavailable (draft release, or no API access); asset checks continue"
fi

# ---------------------------------------------------------------- the release commit
TAG_COMMIT=""
if [[ "$SKIP_COMMIT" == 0 ]]; then
  ref="$(api "git/ref/tags/$TAG" 2>/dev/null || true)"
  if [[ -n "$ref" ]] && jq -e '.object.sha | type == "string"' <<<"$ref" >/dev/null 2>&1; then
    obj_type="$(jq -r '.object.type // empty' <<<"$ref")"; obj_sha="$(jq -r '.object.sha // empty' <<<"$ref")"
    if [[ "$obj_type" == "tag" && "$obj_sha" =~ ^[0-9a-f]{40}$ ]]; then
      TAG_COMMIT="$(api "git/tags/$obj_sha" 2>/dev/null | jq -r '.object.sha // empty' 2>/dev/null || true)"
    elif [[ "$obj_type" == "commit" ]]; then
      TAG_COMMIT="$obj_sha"
    fi
  fi
  # An unresolved commit is a failure, never a silently skipped check.
  if [[ "$TAG_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    info "tag $TAG points at commit $TAG_COMMIT"
  else
    TAG_COMMIT=""
    fail "cannot resolve the commit of tag $TAG (git/ref/tags returned no commit sha); use --skip-commit only for an offline check"
  fi
fi

# ---------------------------------------------------------------- assets
if [[ -z "$WORK_DIR" ]]; then
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/talon-verify-release.XXXXXX")"
  trap 'rm -rf "${WORK_DIR:?}"' EXIT
fi
mkdir -p "$WORK_DIR"
if [[ -z "$ASSETS_DIR" ]]; then
  ASSETS_DIR="$WORK_DIR/assets"; mkdir -p "$ASSETS_DIR"
  fetch() { # name required(1/0)
    local name="${1:?asset name}" required="$2"
    if curl -fsSL --retry 3 --retry-delay 2 -o "${ASSETS_DIR:?}/$name" "$DOWNLOAD_BASE/$TAG/$name"; then return 0; fi
    rm -f "${ASSETS_DIR:?}/${name:?}"
    if [[ "$required" == 1 ]]; then fail "asset $name is not downloadable from $DOWNLOAD_BASE/$TAG"; else info "asset $name is not published"; fi
    return 1
  }
  fetch checksums.txt 1 || true
  fetch "$LINUX_ARCHIVE" 1 || true
  fetch "$BUNDLE_ARCHIVE" 1 || true
  fetch "$BUNDLE_ARCHIVE.sha256" 1 || true
  fetch "$MANIFEST_NAME" 1 || true
  if [[ "$ALL_ARCHIVES" == 1 ]]; then
    for arch in arm64 amd64; do
      if fetch "talon_${VERSION}_darwin_${arch}.tar.gz" 0; then fetch "talon_${VERSION}_darwin_${arch}.tar.gz.sha256" 1 || true; fi
    done
  fi
fi
A="$ASSETS_DIR"
for required in checksums.txt "$LINUX_ARCHIVE" "$BUNDLE_ARCHIVE" "$BUNDLE_ARCHIVE.sha256" "$MANIFEST_NAME"; do
  [[ -s "$A/$required" ]] || fail "required asset missing or empty: $required"
done
for arch in arm64 amd64; do
  if [[ -s "$A/talon_${VERSION}_darwin_${arch}.tar.gz" ]]; then info "darwin/$arch archive present"; else info "darwin/$arch archive not present here (not required for the linux/amd64 installer path)"; fi
done
# Nothing below can run without the linux archive and the manifest.
[[ -s "$A/$LINUX_ARCHIVE" && -s "$A/$MANIFEST_NAME" && -s "$A/checksums.txt" && -s "$A/$BUNDLE_ARCHIVE" ]] || { echo "FAIL verify-release: $TAG ($FAILURES failures; required assets missing)" >&2; exit 1; }

# 1. checksums ------------------------------------------------------------
LINUX_ARCHIVE_SHA="$(sha256 "$A/$LINUX_ARCHIVE")"
expected="$(awk -v n="$LINUX_ARCHIVE" '$2 == n {print $1}' "$A/checksums.txt" | head -n1)"
if [[ -z "$expected" ]]; then fail "checksums.txt has no entry for $LINUX_ARCHIVE"
elif [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then fail "checksums.txt entry for $LINUX_ARCHIVE is not a sha256 ('$expected')"
elif [[ "$expected" != "$LINUX_ARCHIVE_SHA" ]]; then fail "$LINUX_ARCHIVE sha256 $LINUX_ARCHIVE_SHA differs from checksums.txt ($expected)"
else pass "checksums.txt: $LINUX_ARCHIVE sha256 $LINUX_ARCHIVE_SHA"; fi
for f in "$A"/*.sha256; do
  [[ -e "$f" ]] || continue
  name="$(basename "$f")"; target="${name%.sha256}"
  if [[ ! -s "$A/$target" ]]; then info "$name: $target not present here, not checked"; continue; fi
  want="$(awk '{print $1}' "$f" | head -n1)"; got="$(sha256 "$A/$target")"
  if [[ ! "$want" =~ ^[0-9a-f]{64}$ ]]; then fail "$name does not contain a sha256 ('$want')"
  elif [[ "$want" == "$got" ]]; then pass "$name matches $target"; else fail "$name ($want) does not match $target ($got)"; fi
done

# 2. the executable --------------------------------------------------------
mkdir -p "$WORK_DIR/talon"
TALON_SHA=""; TALON_COMMIT=""; EXEC_CHECKED=0
if ! tar -C "$WORK_DIR/talon" -xzf "$A/$LINUX_ARCHIVE" talon 2>/dev/null || [[ ! -x "$WORK_DIR/talon/talon" ]]; then
  fail "$LINUX_ARCHIVE does not contain an executable talon at its root"
else
  TALON_SHA="$(sha256 "$WORK_DIR/talon/talon")"
  if [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]]; then
    EXEC_CHECKED=1
    version_out="$("$WORK_DIR/talon/talon" version 2>&1 || true)"
    if [[ "$(head -n1 <<<"$version_out")" == "Talon $VERSION" ]]; then pass "talon version reports 'Talon $VERSION'"; else fail "talon version reports '$(head -n1 <<<"$version_out")', expected 'Talon $VERSION'"; fi
    TALON_COMMIT="$(sed -n 's/^Commit: *//p' <<<"$version_out" | head -n1)"
    if [[ -n "$TAG_COMMIT" ]]; then
      if [[ -n "$TALON_COMMIT" && "$TAG_COMMIT" == "$TALON_COMMIT"* ]]; then pass "talon was built from the tag's commit ($TALON_COMMIT)"; else fail "talon reports commit '$TALON_COMMIT'; tag $TAG points at $TAG_COMMIT"; fi
    fi
  elif [[ "$NO_EXEC" == 1 ]]; then
    info "not linux/amd64 here (--no-exec): the archive's talon is hashed but not executed; version and commit are NOT verified"
  else
    fail "this host ($(uname -s)/$(uname -m)) cannot execute the linux/amd64 talon, so its version and commit cannot be verified; pass --no-exec to verify digests only (the verdict then does not cover them)"
  fi
fi

# 3. the showcase manifest and bundle -------------------------------------
MANIFEST="$A/$MANIFEST_NAME"
MANIFEST_TALON_SHA=""; AGENT_IMAGE=""
if ! jq -e . "$MANIFEST" >/dev/null 2>&1; then
  fail "$MANIFEST_NAME is not valid JSON"
else
  mv="$(jq -r '.talon_version // empty' "$MANIFEST")"
  if [[ "$mv" == "$VERSION" ]]; then pass "manifest talon_version $mv"; else fail "manifest talon_version '$mv', expected $VERSION"; fi
  mb="$(jq -r '.bundle // empty' "$MANIFEST")"
  if [[ "$mb" == "$BUNDLE_NAME" ]]; then pass "manifest bundle $mb"; else fail "manifest bundle '$mb', expected $BUNDLE_NAME"; fi
  MANIFEST_TALON_SHA="$(jq -r '.artifacts.talon.sha256 // empty' "$MANIFEST")"
  if [[ -z "$MANIFEST_TALON_SHA" ]]; then
    fail "manifest has no artifacts.talon entry: the showcase customer path refuses this release's own binary (the v1.15.0–v1.15.3 defect, #507)"
  elif [[ -z "$TALON_SHA" ]]; then
    fail "manifest artifacts.talon.sha256 cannot be checked (no executable extracted)"
  elif [[ "$MANIFEST_TALON_SHA" != "$TALON_SHA" ]]; then
    fail "manifest artifacts.talon.sha256 $MANIFEST_TALON_SHA is not the digest of the released executable ($TALON_SHA)"
  else
    pass "manifest artifacts.talon.sha256 is the digest of the released executable ($TALON_SHA)"
  fi
  mp="$(jq -r '.artifacts.talon.path // empty' "$MANIFEST")"
  [[ -z "$MANIFEST_TALON_SHA" || "$mp" == "$LINUX_ARCHIVE" ]] || fail "manifest artifacts.talon.path '$mp', expected $LINUX_ARCHIVE"
  AGENT_IMAGE="$(jq -r '.agent_image // empty' "$MANIFEST")"
  if [[ "$AGENT_IMAGE" == "$EXPECTED_AGENT_IMAGE" ]]; then pass "manifest agent_image $AGENT_IMAGE"; else fail "manifest agent_image '$AGENT_IMAGE', expected $EXPECTED_AGENT_IMAGE"; fi
  mkdir -p "$WORK_DIR/bundle"
  if ! tar -C "$WORK_DIR/bundle" -xzf "$A/$BUNDLE_ARCHIVE" 2>/dev/null || [[ ! -d "$WORK_DIR/bundle/$BUNDLE_NAME" ]]; then
    fail "$BUNDLE_ARCHIVE does not extract to $BUNDLE_NAME/"
  else
    BUNDLE="$WORK_DIR/bundle/$BUNDLE_NAME"
    if cmp -s "$BUNDLE/showcase-manifest.json" "$MANIFEST"; then pass "bundled showcase-manifest.json is byte-identical to $MANIFEST_NAME"; else fail "the manifest inside $BUNDLE_ARCHIVE differs from $MANIFEST_NAME"; fi
    for h in mockprovider protectedservice describe support-agent; do
      want="$(jq -r --arg n "$h" '.artifacts[$n].sha256 // empty' "$MANIFEST")"
      if [[ -z "$want" ]]; then fail "manifest has no entry for helper $h"
      elif [[ ! -f "$BUNDLE/bin/$h" ]]; then fail "bundle lacks bin/$h"
      elif [[ "$want" != "$(sha256 "$BUNDLE/bin/$h")" ]]; then fail "bundle bin/$h does not match its manifest digest"
      else pass "bundle bin/$h matches the manifest"; fi
    done
    if [[ -x "$BUNDLE/demo.sh" && -f "$BUNDLE/lib/openshell-release.sh" && -f "$BUNDLE/test-contract.sh" ]]; then pass "bundle layout: demo.sh, lib/openshell-release.sh, test-contract.sh"; else fail "bundle layout incomplete: $(find "$BUNDLE" -maxdepth 2 | head -20 | tr '\n' ' ')"; fi
  fi
fi

# 4. the images, without credentials ---------------------------------------
TALON_IMAGE_DIGEST=""; AGENT_IMAGE_DIGEST=""
image_digest() { # ref -> prints a sha256:<64 hex> digest (exit 0), or the reason (exit 1)
  local ref="$1" rest repo tag token code headers digest
  rest="${ref#*/}"; repo="${rest%%:*}"; tag="${rest##*:}"
  token="$(curl -fsS "$REGISTRY_BASE/token?scope=repository:$repo:pull" 2>/dev/null | jq -r '.token // empty' 2>/dev/null || true)"
  [[ -n "$token" ]] || { echo "no anonymous pull token for $repo (private package, or absent)"; return 1; }
  headers="$(curl -sS -o /dev/null -D - -w '%{http_code}' -H "Authorization: Bearer $token" \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json' \
    "$REGISTRY_BASE/v2/$repo/manifests/$tag")" || { echo "manifest request failed"; return 1; }
  code="$(tail -n1 <<<"$headers")"
  [[ "$code" == 200 ]] || { echo "anonymous manifest fetch returned HTTP $code (tag missing, or package private)"; return 1; }
  digest="$(sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *//p' <<<"$headers" | tr -d '\r' | head -n1)"
  # A 200 without a digest is not proof of anything pinnable: a customer
  # cannot record or pull by digest what the registry does not state.
  [[ "$digest" =~ ^sha256:[0-9a-fA-F]{64}$ ]] || { echo "HTTP 200 but no valid Docker-Content-Digest header (got '${digest:-none}')"; return 1; }
  echo "$digest"
}
# check_image runs in the main shell on purpose: pass/fail must update the
# verdict counter, which a $(...) capture would silently discard.
IMG_RESULT=""
check_image() { # ref -> IMG_RESULT = digest on PASS, empty on FAIL
  local ref="$1" out
  if out="$(image_digest "$ref")"; then pass "$ref pullable without credentials, digest $out"; IMG_RESULT="$out"
  else fail "$ref: $out"; IMG_RESULT=""; fi
}
if [[ "$SKIP_IMAGES" == 1 ]]; then
  info "image checks skipped (--skip-images)"
else
  check_image "$TALON_IMAGE"; TALON_IMAGE_DIGEST="$IMG_RESULT"
  if [[ -n "$AGENT_IMAGE" ]]; then check_image "$AGENT_IMAGE"; AGENT_IMAGE_DIGEST="$IMG_RESULT"; fi
fi

# 5. the installer -----------------------------------------------------------
INSTALLED_SHA=""
if [[ -n "$INSTALL_DIR" ]]; then
  INSTALL_SH="${TALON_INSTALL_SH:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh}"
  if [[ ! -f "$INSTALL_SH" ]]; then
    fail "installer not found at $INSTALL_SH (set TALON_INSTALL_SH)"
  else
    mkdir -p "$INSTALL_DIR"
    if TALON_VERSION="$TAG" INSTALL_DIR="$INSTALL_DIR" TALON_INSTALL_ALLOW_SOURCE=0 \
       TALON_INSTALL_API_BASE="$API_BASE" TALON_INSTALL_DOWNLOAD_BASE="$DOWNLOAD_BASE" TALON_RELEASE_REPO="$REPO" \
       sh "$INSTALL_SH" >"$WORK_DIR/install.log" 2>&1; then
      INSTALLED_SHA="$(sha256 "$INSTALL_DIR/talon")"
      if [[ -n "$TALON_SHA" && "$INSTALLED_SHA" == "$TALON_SHA" ]]; then pass "install.sh installed the verified executable into $INSTALL_DIR (sha256 $INSTALLED_SHA)"; else fail "install.sh installed a binary with sha256 $INSTALLED_SHA, verified executable is $TALON_SHA"; fi
    else
      fail "install.sh failed for $TAG: $(tail -n 5 "$WORK_DIR/install.log" | tr '\n' ' ')"
    fi
  fi
fi

# ---------------------------------------------------------------- summary
echo "verify-release summary for $TAG"
echo "  commit (tag)                      ${TAG_COMMIT:-unresolved}"
echo "  commit (talon version)            ${TALON_COMMIT:-unresolved}"
echo "  $LINUX_ARCHIVE  sha256 $LINUX_ARCHIVE_SHA"
echo "  talon (executable)                sha256 ${TALON_SHA:-n/a}"
echo "  executable checked (version/commit)  $([[ "$EXEC_CHECKED" == 1 ]] && echo yes || echo no)"
echo "  $BUNDLE_ARCHIVE  sha256 $(sha256 "$A/$BUNDLE_ARCHIVE")"
echo "  $MANIFEST_NAME  sha256 $(sha256 "$MANIFEST") artifacts.talon.sha256=${MANIFEST_TALON_SHA:-absent}"
echo "  $TALON_IMAGE  digest ${TALON_IMAGE_DIGEST:-not checked}"
echo "  ${AGENT_IMAGE:-agent image}  digest ${AGENT_IMAGE_DIGEST:-not checked}"
if [[ -n "$SUMMARY_JSON" ]]; then
  jq -n --arg tag "$TAG" --arg version "$VERSION" --arg tag_commit "$TAG_COMMIT" --arg talon_commit "$TALON_COMMIT" \
    --arg archive "$LINUX_ARCHIVE" --arg archive_sha "$LINUX_ARCHIVE_SHA" --arg talon_sha "$TALON_SHA" \
    --arg bundle "$BUNDLE_ARCHIVE" --arg bundle_sha "$(sha256 "$A/$BUNDLE_ARCHIVE")" --arg manifest_sha "$(sha256 "$MANIFEST")" \
    --arg manifest_talon_sha "$MANIFEST_TALON_SHA" --arg talon_image "$TALON_IMAGE" --arg talon_image_digest "$TALON_IMAGE_DIGEST" \
    --arg agent_image "$AGENT_IMAGE" --arg agent_image_digest "$AGENT_IMAGE_DIGEST" --arg installed_sha "$INSTALLED_SHA" \
    --argjson failures "$FAILURES" --argjson exec_checked "$EXEC_CHECKED" \
    '{tag:$tag, version:$version, tag_commit:$tag_commit, talon_commit:$talon_commit, executable_checked:($exec_checked == 1),
      linux_amd64_archive:{name:$archive, sha256:$archive_sha}, talon_executable_sha256:$talon_sha,
      showcase_bundle:{name:$bundle, sha256:$bundle_sha}, showcase_manifest:{sha256:$manifest_sha, artifacts_talon_sha256:$manifest_talon_sha},
      images:{talon:{ref:$talon_image, digest:$talon_image_digest}, agent:{ref:$agent_image, digest:$agent_image_digest}},
      installed_sha256:$installed_sha, failures:$failures, verdict:(if $failures == 0 then "PASS" else "FAIL" end)}' >"$SUMMARY_JSON"
  echo "  summary json                      $SUMMARY_JSON"
fi
if [[ "$FAILURES" == 0 ]]; then echo "PASS verify-release: $TAG"; else echo "FAIL verify-release: $TAG ($FAILURES failures)" >&2; exit 1; fi

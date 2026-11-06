#!/usr/bin/env bash
# Offline failure-injection test of the published-artifact path (#359): the
# release verifier (scripts/verify-release.sh) and the installer
# (scripts/install.sh) are run against a FAKE release served from 127.0.0.1
# — release metadata, tag ref, download URLs and an anonymous registry — built
# from this checkout exactly the way the release workflow builds a real one
# (archive, checksums.txt, showcase bundle + manifest in release mode). Then
# the assets are tampered with one at a time and every tamper must be caught:
#
#   P1  intact release: verifier PASS, installer (run under `sh`) installs the
#       byte-identical executable, version pin honoured
#   P2  the archive's digest published only as <archive>.sha256 (checksum
#       parity, the darwin shape): the installer still verifies it
#   N1  altered binary inside the archive, checksums.txt unchanged
#   N2  altered binary WITH regenerated checksums.txt: the installer alone
#       cannot tell (it trusts the release's own checksum file) — the showcase
#       manifest's artifacts.talon.sha256 is what catches it
#   N3  one hex digit of artifacts.talon.sha256 modified
#   N4  manifest without artifacts.talon (the v1.15.0–v1.15.3 shape)
#   N5  tag/version mismatch: the archive's talon reports another version
#   N6  tag points at another commit than the one talon reports
#   N7  the manifest's agent image is not pullable anonymously
#   N8  installer: no archive for the platform → exit 1, no source build,
#       no `go` invoked
#   N9  a draft release is refused by the installer and flagged by the verifier
#   N10 installer: an unpublished version pin fails before any download
#   (the installer's own checksum mismatch and version refusal are N1 and N5)
#
# No network beyond 127.0.0.1, no Docker. Needs Go (to build the test talon
# and the bundle helpers), python3 (the fake server), curl, jq, tar.
#
#   make test-release-verify      or      scripts/test-verify-release.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# TALON_TEST_INSTALL_SH points the test at another installer (RED check: the
# pre-#359 installer fails P1 under sh, P2, N8 and N9).
INSTALL_SH="${TALON_TEST_INSTALL_SH:-$ROOT/scripts/install.sh}"
for tool in go python3 curl jq tar sha256sum; do command -v "$tool" >/dev/null 2>&1 || { echo "test-verify-release: $tool is required" >&2; exit 2; }; done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/talon-verify-release-test.XXXXXX")"
SERVER_PID=""
cleanup() { if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi; rm -rf "${WORK:?}"; }
trap cleanup EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }
# expect_fail <output-file> <rc> <pattern> <what>: a non-zero rc AND the named reason
expect_fail() { if [[ "$2" == 0 ]] || ! grep -q -- "$3" "$1"; then echo "--- output:" >&2; cat "$1" >&2; fail "$4"; fi; }

VERSION="0.0.0-verify"; TAG="v$VERSION"
COMMIT_FULL="0123456789abcdef0123456789abcdef01234567"; COMMIT_SHORT="0123456"
LINUX_ARCHIVE="talon_${VERSION}_linux_amd64.tar.gz"
BUNDLE_NAME="talon-openshell-showcase_${VERSION}_linux_amd64"

# ---------------------------------------------------------------- build the fake release like the workflow does
echo "building the test talon ($TAG, commit $COMMIT_SHORT)..."
(cd "$ROOT" && CGO_ENABLED=1 go build -trimpath -ldflags "-s -w \
  -X github.com/dativo-io/talon/internal/cmd.Version=${VERSION} \
  -X github.com/dativo-io/talon/internal/cmd.Commit=${COMMIT_SHORT} \
  -X github.com/dativo-io/talon/internal/cmd.BuildDate=2026-01-01T00:00:00Z" -o "$WORK/talon" ./cmd/talon)
[[ "$("$WORK/talon" version | head -n1)" == "Talon $VERSION" ]] || fail "test talon reports $("$WORK/talon" version | head -n1)"
TALON_SHA="$(sha256sum "$WORK/talon" | cut -d' ' -f1)"

build_release() { # out-dir talon-binary  -> archive, checksums.txt, bundle, .sha256, manifest (as goreleaser + the workflow produce them)
  local out="$1" bin="$2" stage
  mkdir -p "$out"; stage="$(mktemp -d "$WORK/stage.XXXXXX")"
  cp "$bin" "$stage/talon"; cp "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/CHANGELOG.md" "$stage/"
  tar -C "$stage" -czf "$out/$LINUX_ARCHIVE" talon LICENSE README.md CHANGELOG.md
  (cd "$out" && sha256sum "$LINUX_ARCHIVE" >checksums.txt)
  TALON_SHOWCASE_BUNDLE_RELEASE=1 bash "$ROOT/scripts/build-showcase-bundle.sh" "$VERSION" "$out" \
    "ghcr.io/dativo-io/talon-openshell-agent:${VERSION}" "$bin" "$LINUX_ARCHIVE" >"$out/build.log" 2>&1 || { cat "$out/build.log"; fail "bundle build"; }
}
echo "building the fake release assets (archive, checksums, showcase bundle + manifest)..."
build_release "$WORK/release" "$WORK/talon"
[[ "$(jq -r .artifacts.talon.sha256 "$WORK/release/$BUNDLE_NAME.manifest.json")" == "$TALON_SHA" ]] || fail "release-mode bundle must list the talon digest"

# ---------------------------------------------------------------- the fake GitHub + registry on 127.0.0.1
WWW="$WORK/www"
release_json() { # tag draft asset... -> JSON the installer/verifier read (only the fields they use)
  local tag="$1" draft="$2"; shift 2
  local assets="" a
  for a in "$@"; do assets="$assets{\"name\": \"$a\"},"; done
  printf '{"tag_name": "%s", "draft": %s, "prerelease": false, "immutable": false, "published_at": "2026-01-01T00:00:00Z", "assets": [%s]}' "$tag" "$draft" "${assets%,}"
}
publish() { # release-dir tag [draft] -> serve these assets as the release <tag>
  local dir="$1" tag="$2" draft="${3:-false}" names=()
  rm -rf "${WWW:?}"; mkdir -p "$WWW/repos/dativo-io/talon/releases/tags" "$WWW/repos/dativo-io/talon/git/ref/tags" "$WWW/dl/$tag" \
    "$WWW/v2/dativo-io/talon/manifests" "$WWW/v2/dativo-io/talon-openshell-agent/manifests"
  for f in "$dir"/*; do [[ "$(basename "$f")" == build.log ]] && continue; cp "$f" "$WWW/dl/$tag/"; names+=("$(basename "$f")"); done
  release_json "$tag" "$draft" "${names[@]}" >"$WWW/repos/dativo-io/talon/releases/tags/$tag"
  cp "$WWW/repos/dativo-io/talon/releases/tags/$tag" "$WWW/repos/dativo-io/talon/releases/latest"
  printf '{"ref": "refs/tags/%s", "object": {"type": "commit", "sha": "%s"}}' "$tag" "${TAG_COMMIT_OVERRIDE:-$COMMIT_FULL}" >"$WWW/repos/dativo-io/talon/git/ref/tags/$tag"
  echo '{"token": "anonymous"}' >"$WWW/token"
  echo '{"schemaVersion": 2}' >"$WWW/v2/dativo-io/talon/manifests/${tag#v}"
  echo '{"schemaVersion": 2}' >"$WWW/v2/dativo-io/talon-openshell-agent/manifests/${tag#v}"
}
publish "$WORK/release" "$TAG"
python3 -u -m http.server --bind 127.0.0.1 --directory "$WWW" 0 >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
PORT=""
for _ in $(seq 1 50); do PORT="$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$WORK/server.log" | head -n1)"; [[ -n "$PORT" ]] && break; sleep 0.1; done
[[ -n "$PORT" ]] || { cat "$WORK/server.log"; fail "fake server did not start"; }
BASE="http://127.0.0.1:$PORT"
export TALON_RELEASE_API_BASE="$BASE" TALON_RELEASE_DOWNLOAD_BASE="$BASE/dl" TALON_REGISTRY_BASE="$BASE" TALON_RELEASE_REPO="dativo-io/talon"
export TALON_INSTALL_API_BASE="$BASE" TALON_INSTALL_DOWNLOAD_BASE="$BASE/dl" TALON_INSTALL_SH="$INSTALL_SH"
verify() { # tag extra-args... -> rc, output in $OUT
  OUT="$WORK/verify.out"; set +e
  bash "$ROOT/scripts/verify-release.sh" --tag "$1" --work-dir "$WORK/vw-$RANDOM" "${@:2}" >"$OUT" 2>&1; RC=$?; set -e
}
install_sh() { # install-dir env... -> rc, output in $OUT
  OUT="$WORK/install.out"; set +e
  env "${@:2}" INSTALL_DIR="$1" TALON_INSTALL_ALLOW_SOURCE=0 PATH="/usr/bin:/bin" sh "$INSTALL_SH" >"$OUT" 2>&1; RC=$?; set -e
}

# ---------------------------------------------------------------- P1 intact release
sh -n "$INSTALL_SH" || fail "install.sh must parse under /bin/sh (the documented 'curl | sh')"
verify "$TAG" --install "$WORK/install-p1" --summary-json "$WORK/p1.json"
[[ "$RC" == 0 ]] || { cat "$OUT"; fail "P1 intact release must verify"; }
grep -q "^PASS verify-release: $TAG" "$OUT" || fail "P1 verdict line"
[[ "$(sha256sum "$WORK/install-p1/talon" | cut -d' ' -f1)" == "$TALON_SHA" ]] || fail "P1 installed executable differs from the built one"
[[ "$(jq -r .verdict "$WORK/p1.json")" == PASS && "$(jq -r .talon_executable_sha256 "$WORK/p1.json")" == "$TALON_SHA" && "$(jq -r .installed_sha256 "$WORK/p1.json")" == "$TALON_SHA" ]] || fail "P1 summary json: $(cat "$WORK/p1.json")"
grep -q "talon was built from the tag's commit ($COMMIT_SHORT)" "$OUT" || fail "P1 commit agreement not reported"
pass "P1 intact release verifies end to end; install.sh (sh) installs the byte-identical executable; summary json written"
install_sh "$WORK/install-pin" TALON_VERSION="$TAG"
[[ "$RC" == 0 && "$(sha256sum "$WORK/install-pin/talon" | cut -d' ' -f1)" == "$TALON_SHA" ]] || { cat "$OUT"; fail "P1 pinned install"; }
grep -q "Version: $TAG" "$OUT" || fail "P1 pinned version not reported"
install_sh "$WORK/install-latest"
[[ "$RC" == 0 ]] || { cat "$OUT"; fail "P1 latest install"; }
pass "P1 install.sh honours TALON_VERSION and resolves latest"

# ---------------------------------------------------------------- P2 digest published only as <archive>.sha256
rm -rf "$WORK/p2"; cp -r "$WORK/release" "$WORK/p2"; rm -f "$WORK/p2/build.log"
(cd "$WORK/p2" && mv checksums.txt "$LINUX_ARCHIVE.sha256" && : >checksums.txt)
publish "$WORK/p2" "$TAG"
install_sh "$WORK/install-p2" TALON_VERSION="$TAG"
[[ "$RC" == 0 && "$(sha256sum "$WORK/install-p2/talon" | cut -d' ' -f1)" == "$TALON_SHA" ]] || { cat "$OUT"; fail "P2 installer must verify against <archive>.sha256 when checksums.txt lacks the entry"; }
pass "P2 checksum parity: install.sh verifies against the per-archive .sha256 asset"
publish "$WORK/release" "$TAG"

# ---------------------------------------------------------------- N1 altered binary, checksums unchanged
tamper_dir() { rm -rf "${WORK:?}/${1:?}"; cp -r "$WORK/release" "$WORK/$1"; rm -f "$WORK/$1/build.log"; }
tamper_dir n1
cp "$WORK/talon" "$WORK/talon-altered"; printf '\n' >>"$WORK/talon-altered"; chmod +x "$WORK/talon-altered"
mkdir -p "$WORK/n1-stage"; cp "$WORK/talon-altered" "$WORK/n1-stage/talon"; cp "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/CHANGELOG.md" "$WORK/n1-stage/"
tar -C "$WORK/n1-stage" -czf "$WORK/n1/$LINUX_ARCHIVE" talon LICENSE README.md CHANGELOG.md
publish "$WORK/n1" "$TAG"
verify "$TAG" --skip-images
expect_fail "$OUT" "$RC" "differs from checksums.txt" "N1 altered archive must fail the checksum"
install_sh "$WORK/install-n1" TALON_VERSION="$TAG"
expect_fail "$OUT" "$RC" "checksum mismatch" "N1 installer must refuse the altered archive"
[[ ! -e "$WORK/install-n1/talon" ]] || fail "N1 installer left a binary behind"
pass "N1 altered binary with the original checksums.txt: verifier and installer fail closed, nothing installed"

# ---------------------------------------------------------------- N2 altered binary with regenerated checksums
tamper_dir n2
cp "$WORK/n1/$LINUX_ARCHIVE" "$WORK/n2/$LINUX_ARCHIVE"
(cd "$WORK/n2" && sha256sum "$LINUX_ARCHIVE" >checksums.txt)
publish "$WORK/n2" "$TAG"
install_sh "$WORK/install-n2" TALON_VERSION="$TAG"
[[ "$RC" == 0 ]] || { cat "$OUT"; fail "N2 precondition: the installer alone accepts a consistent archive+checksums pair"; }
verify "$TAG" --skip-images
expect_fail "$OUT" "$RC" "is not the digest of the released executable" "N2 altered binary with consistent checksums must be caught by the manifest"
pass "N2 altered binary with regenerated checksums.txt: the installer cannot tell, the manifest digest catches it"

# ---------------------------------------------------------------- N3 modified manifest digest
tamper_dir n3
m="$WORK/n3/$BUNDLE_NAME.manifest.json"
flipped="$(jq -r .artifacts.talon.sha256 "$m" | awk '{c=substr($0,1,1); r=(c=="0")?"1":"0"; print r substr($0,2)}')"
jq --arg s "$flipped" '.artifacts.talon.sha256 = $s' "$m" >"$m.tmp" && mv "$m.tmp" "$m"
publish "$WORK/n3" "$TAG"
verify "$TAG" --skip-images
expect_fail "$OUT" "$RC" "is not the digest of the released executable" "N3 modified manifest digest must fail"
grep -q "differs from $BUNDLE_NAME.manifest.json" "$OUT" || fail "N3 the bundled manifest must be reported as differing from the published one"
pass "N3 one modified hex digit in artifacts.talon.sha256 fails, and the bundle/manifest disagreement is reported"

# ---------------------------------------------------------------- N4 manifest without the talon entry (v1.15.0–v1.15.3)
tamper_dir n4
m="$WORK/n4/$BUNDLE_NAME.manifest.json"
jq 'del(.artifacts.talon)' "$m" >"$m.tmp" && mv "$m.tmp" "$m"
publish "$WORK/n4" "$TAG"
verify "$TAG" --skip-images
expect_fail "$OUT" "$RC" "has no artifacts.talon entry" "N4 manifest without talon entry must fail"
pass "N4 a manifest without artifacts.talon (the pre-v1.15.4 shape) fails"

# ---------------------------------------------------------------- N5 the archive's talon reports another version than the tag
tamper_dir n5
OTHER="v0.0.0-other"
for f in "$WORK/n5"/*; do b="$(basename "$f")"; case "$b" in *"$VERSION"*) mv "$f" "$WORK/n5/${b//$VERSION/0.0.0-other}" ;; esac; done
(cd "$WORK/n5" && sed -i "s/$VERSION/0.0.0-other/" checksums.txt "talon-openshell-showcase_0.0.0-other_linux_amd64.tar.gz.sha256")
publish "$WORK/n5" "$OTHER"
verify "$OTHER" --skip-images
expect_fail "$OUT" "$RC" "talon version reports 'Talon $VERSION', expected 'Talon 0.0.0-other'" "N5 version mismatch must fail"
install_sh "$WORK/install-n5" TALON_VERSION="$OTHER"
expect_fail "$OUT" "$RC" "expected 'Talon 0.0.0-other'" "N5 installer must refuse a binary of another version"
[[ ! -e "$WORK/install-n5/talon" ]] || fail "N5 installer left a binary behind"
pass "N5 an executable that does not report the tag's version is refused by verifier and installer"

# ---------------------------------------------------------------- N6 tag points at another commit
TAG_COMMIT_OVERRIDE="fedcba9876543210fedcba9876543210fedcba98" publish "$WORK/release" "$TAG"
verify "$TAG" --skip-images
expect_fail "$OUT" "$RC" "talon reports commit '$COMMIT_SHORT'; tag $TAG points at fedcba98" "N6 commit disagreement must fail"
pass "N6 an executable built from another commit than the tag's is refused"
publish "$WORK/release" "$TAG"

# ---------------------------------------------------------------- N7 agent image not pullable anonymously
rm -f "$WWW/v2/dativo-io/talon-openshell-agent/manifests/$VERSION"
verify "$TAG"
expect_fail "$OUT" "$RC" "talon-openshell-agent:$VERSION is not pullable without credentials" "N7 private/missing agent image must fail"
grep -q "ghcr.io/dativo-io/talon:$VERSION pullable without credentials" "$OUT" || fail "N7 the talon image check must still pass"
pass "N7 an agent image that is not pullable anonymously fails the release"
publish "$WORK/release" "$TAG"

# ---------------------------------------------------------------- N8 installer: no archive for the platform → no source build
jq 'del(.assets[] | select(.name | startswith("talon_")))' "$WWW/repos/dativo-io/talon/releases/tags/$TAG" >"$WORK/noasset.json"
cp "$WORK/noasset.json" "$WWW/repos/dativo-io/talon/releases/tags/$TAG"
mkdir -p "$WORK/fakego"; printf '#!/bin/sh\necho "go must not be invoked" >&2; exit 99\n' >"$WORK/fakego/go"; chmod +x "$WORK/fakego/go"
OUT="$WORK/install.out"; set +e
env INSTALL_DIR="$WORK/install-n8" TALON_VERSION="$TAG" PATH="$WORK/fakego:/usr/bin:/bin" sh "$INSTALL_SH" >"$OUT" 2>&1; RC=$?; set -e
expect_fail "$OUT" "$RC" "does not build from source by default" "N8 installer must refuse to build from source"
grep -q "go must not be invoked" "$OUT" && fail "N8 installer invoked go"
[[ ! -e "$WORK/install-n8/talon" ]] || fail "N8 installer left a binary behind"
pass "N8 no archive for the platform: install.sh exits 1 without a source build"
publish "$WORK/release" "$TAG"

# ---------------------------------------------------------------- N9 installer: draft release
publish "$WORK/release" "$TAG" true
install_sh "$WORK/install-n9" TALON_VERSION="$TAG"
expect_fail "$OUT" "$RC" "is a draft release" "N9 installer must refuse a draft"
verify "$TAG" --skip-images
expect_fail "$OUT" "$RC" "is still a draft" "N9 verifier must flag a draft"
pass "N9 a draft release is refused by the installer and flagged by the verifier"
publish "$WORK/release" "$TAG"

# ---------------------------------------------------------------- N10 unknown version
install_sh "$WORK/install-n10" TALON_VERSION=v9.9.9
expect_fail "$OUT" "$RC" "no such published release" "N10 unknown version must fail"
pass "N10 an unpublished version pin fails before anything is downloaded"

echo "ALL PASS test-verify-release: published-artifact verifier and installer fail closed on every injected defect"

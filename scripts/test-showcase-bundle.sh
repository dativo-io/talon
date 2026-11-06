#!/usr/bin/env bash
# Offline test of the showcase bundle builder and of the CUSTOMER path it
# feeds (#507): build a bundle from this checkout around a built talon, then
# run the bundle's own runner from OUTSIDE the checkout — no Go, no source —
# with the published-manifest gate on. The regression this pins: every
# manifest published before v1.16.0 had no `artifacts.talon` entry, so the
# documented customer path refused the release's own binary 100% of the time.
#
#   TALON_SHOWCASE_TALON_BIN=bin/talon scripts/test-showcase-bundle.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TALON="${TALON_SHOWCASE_TALON_BIN:?set TALON_SHOWCASE_TALON_BIN to a built talon}"
TALON="$(cd "$(dirname "$TALON")" && pwd)/$(basename "$TALON")"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/talon-showcase-bundle-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }
refused() { # rc output pattern message
  if [[ "$1" == 0 ]] || ! grep -q -- "$3" <<<"$2"; then fail "$4: $2"; fi
}
VERSION="$("$TALON" version | head -n1 | sed 's/^Talon //')"
[[ -n "$VERSION" ]] || fail "cannot read the version of $TALON"
TALON_SHA="$(sha256sum "$TALON" | cut -d' ' -f1)"

# 1. Release mode refuses to build a manifest without the released binary.
set +e; out="$(TALON_SHOWCASE_BUNDLE_RELEASE=1 bash "$ROOT/scripts/build-showcase-bundle.sh" "$VERSION" "$WORK/norelease" 2>&1)"; rc=$?; set -e
refused "$rc" "$out" 'release mode requires the released talon binary' "release mode without a talon binary must refuse"
pass "release mode: a manifest without artifacts.talon cannot be built"

# 2. A binary that does not report the release version is refused (the
#    manifest must hash the executable this release ships, nothing else).
set +e; out="$(bash "$ROOT/scripts/build-showcase-bundle.sh" "0.0.0-other" "$WORK/wrongver" ghcr.io/dativo-io/talon-openshell-agent:test "$TALON" 2>&1)"; rc=$?; set -e
refused "$rc" "$out" "expected 'Talon 0.0.0-other'" "a binary of another version must be refused"
pass "version check: only the binary reporting the release version is hashed"

# 3. The bundle around the real binary carries its digest and is self-consistent.
TALON_SHOWCASE_BUNDLE_RELEASE=1 bash "$ROOT/scripts/build-showcase-bundle.sh" "$VERSION" "$WORK/dist" ghcr.io/dativo-io/talon-openshell-agent:test "$TALON" "talon_${VERSION}_linux_amd64.tar.gz" >"$WORK/build.out" 2>&1 || { cat "$WORK/build.out"; fail "bundle build"; }
NAME="talon-openshell-showcase_${VERSION}_linux_amd64"
[[ -s "$WORK/dist/$NAME.tar.gz" && -s "$WORK/dist/$NAME.tar.gz.sha256" && -s "$WORK/dist/$NAME.manifest.json" ]] || fail "bundle outputs missing: $(ls "$WORK/dist")"
(cd "$WORK/dist" && sha256sum -c "$NAME.tar.gz.sha256" >/dev/null) || fail "bundle .sha256 does not match the tarball"
jq -e --arg s "$TALON_SHA" --arg a "talon_${VERSION}_linux_amd64.tar.gz" --arg v "$VERSION" \
  '.talon_version == $v and .artifacts.talon.sha256 == $s and .artifacts.talon.path == $a and (.artifacts | keys | sort) == ["describe","mockprovider","protectedservice","support-agent","talon"]' \
  "$WORK/dist/$NAME.manifest.json" >/dev/null || fail "manifest content: $(cat "$WORK/dist/$NAME.manifest.json")"
mkdir -p "$WORK/extract" && tar -C "$WORK/extract" -xzf "$WORK/dist/$NAME.tar.gz"
BUNDLE="$WORK/extract/$NAME"
cmp -s "$BUNDLE/showcase-manifest.json" "$WORK/dist/$NAME.manifest.json" || fail "the manifest inside the tarball differs from the published one"
for b in mockprovider protectedservice describe support-agent; do
  want="$(jq -r --arg n "$b" '.artifacts[$n].sha256' "$BUNDLE/showcase-manifest.json")"
  [[ "$want" == "$(sha256sum "$BUNDLE/bin/$b" | cut -d' ' -f1)" ]] || fail "helper $b digest differs from the manifest"
done
[[ -x "$BUNDLE/demo.sh" && -f "$BUNDLE/lib/openshell-release.sh" && -f "$BUNDLE/test-contract.sh" ]] || fail "bundle layout: $(find "$BUNDLE" -maxdepth 2 | head -20)"
pass "bundle: artifacts.talon carries the released binary's sha256; helpers and tarball digests agree"

# 4. The customer path, from the extracted bundle, outside the checkout, with
#    the published-manifest gate on: prepare passes with the release binary,
#    refuses a manifest without the talon entry (the pre-v1.16.0 shape) and
#    refuses a tampered binary. No Go toolchain is involved past this point.
grep -q 'module github.com/dativo-io/talon' "$BUNDLE/../../../go.mod" 2>/dev/null && fail "the extracted bundle must not sit inside a checkout"
customer_prepare() { # run-dir manifest talon-bin -> output (rc in $?)
  TALON_SHOWCASE_RUN_DIR="$1" TALON_SHOWCASE_RELEASE_MANIFEST="$2" TALON_SHOWCASE_BUNDLE_DIR="$BUNDLE" \
    TALON_SHOWCASE_TALON_BIN="$3" TALON_SHOWCASE_HOST=10.9.8.7 PATH="/usr/bin:/bin" \
    bash "$BUNDLE/demo.sh" prepare 2>&1
}
set +e; out="$(customer_prepare "$WORK/run-ok" "$BUNDLE/showcase-manifest.json" "$TALON")"; rc=$?; set -e
if [[ "$rc" != 0 ]] || ! grep -q '^PASS prepare' <<<"$out"; then fail "customer path prepare with the release manifest: $out"; fi
jq -e '.agent_created == true' "$WORK/run-ok/prepare.json" >/dev/null || fail "customer prepare summary: $(cat "$WORK/run-ok/prepare.json")"
pass "customer path: prepare passes the manifest gate with the released talon"

jq 'del(.artifacts.talon)' "$BUNDLE/showcase-manifest.json" >"$WORK/manifest-pre-v1.16.0.json"
set +e; out="$(customer_prepare "$WORK/run-missing" "$WORK/manifest-pre-v1.16.0.json" "$TALON")"; rc=$?; set -e
refused "$rc" "$out" 'has no entry for talon' "a manifest without artifacts.talon must refuse the binary (the v1.15.0–v1.15.3 defect)"
pass "customer path: a manifest without artifacts.talon is refused (regression #507)"

cp "$TALON" "$WORK/talon-tampered" && printf '\n' >>"$WORK/talon-tampered" && chmod +x "$WORK/talon-tampered"
set +e; out="$(customer_prepare "$WORK/run-tampered" "$BUNDLE/showcase-manifest.json" "$WORK/talon-tampered")"; rc=$?; set -e
refused "$rc" "$out" 'does not match the release manifest' "a tampered talon must be refused"
pass "customer path: a binary whose digest differs from the manifest is refused"
echo "ALL PASS showcase bundle and customer path"
